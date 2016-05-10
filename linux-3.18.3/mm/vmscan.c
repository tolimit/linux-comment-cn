/*
 *  linux/mm/vmscan.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, Stephen Tweedie.
 *  kswapd added: 7.1.96  sct
 *  Removed kswapd_ctl limits, and swap out as many pages as needed
 *  to bring the system back to freepages.high: 2.4.97, Rik van Riel.
 *  Zone aware kswapd started 02/00, Kanoj Sarcar (kanoj@sgi.com).
 *  Multiqueue VM started 5.8.00, Rik van Riel.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/vmpressure.h>
#include <linux/vmstat.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	/* for try_to_release_page(),
					buffer_heads_over_limit */
#include <linux/mm_inline.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/compaction.h>
#include <linux/notifier.h>
#include <linux/rwsem.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/memcontrol.h>
#include <linux/delayacct.h>
#include <linux/sysctl.h>
#include <linux/oom.h>
#include <linux/prefetch.h>
#include <linux/printk.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>

#include <linux/swapops.h>
#include <linux/balloon_compaction.h>

#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/vmscan.h>

/* 扫描控制结构，用于内存回收和内存压缩 */
struct scan_control {
	/* How many pages shrink_list() should reclaim */
	/* 需要回收的页框数量 */
	unsigned long nr_to_reclaim;

	/* This context's GFP mask */
	/* 申请内存时使用的分配标志 */
	gfp_t gfp_mask;

	/* Allocation order */
	/* 申请内存时使用的order值，因为只有申请内存，然后内存不足时才会进行扫描 */
	int order;

	/*
	 * Nodemask of nodes allowed by the caller. If NULL, all nodes
	 * are scanned.
	 */
	/* 执行扫描的node结点掩码 */
	nodemask_t	*nodemask;

	/*
	 * The memory cgroup that hit its limit and as a result is the
	 * primary target of this reclaim invocation.
	 */
	/* 目标memcg，如果是针对zone的，则此为NULL */
	struct mem_cgroup *target_mem_cgroup;

	/* Scan (total_size >> priority) pages at once */
	/* 扫描优先级，代表一次扫描(total_size >> priority)个页框 
	 * 优先级越低，一次扫描的页框数量就越多
	 * 优先级越高，一次扫描的数量就越少
	 * 默认优先级为12
	 */
	int priority;

	/* 是否能够进行回写操作(与分配标志的__GFP_IO和__GFP_FS有关) */
	unsigned int may_writepage:1;

	/* Can mapped pages be reclaimed? */
	/* 能否进行unmap操作，就是将所有映射了此页的页表项清空 */
	unsigned int may_unmap:1;

	/* Can pages be swapped as part of reclaim? */
	/* 是否能够进行swap交换，如果不能，则不扫描匿名页lru链表 */
	unsigned int may_swap:1;

	unsigned int hibernation_mode:1;

	/* One of the zones is ready for compaction */
	/* 扫描结束后会标记，用于内存回收判断是否需要进行内存压缩 */
	unsigned int compaction_ready:1;

	/* Incremented by the number of inactive pages that were scanned */
	/* 已经扫描的页框数量 */
	unsigned long nr_scanned;

	/* Number of pages freed so far during a call to shrink_zones() */
	/* 已经回收的页框数量 */
	unsigned long nr_reclaimed;
};

#define lru_to_page(_head) (list_entry((_head)->prev, struct page, lru))

#ifdef ARCH_HAS_PREFETCH
#define prefetch_prev_lru_page(_page, _base, _field)			\
	do {								\
		if ((_page)->lru.prev != _base) {			\
			struct page *prev;				\
									\
			prev = lru_to_page(&(_page->lru));		\
			prefetch(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetch_prev_lru_page(_page, _base, _field) do { } while (0)
#endif

#ifdef ARCH_HAS_PREFETCHW
#define prefetchw_prev_lru_page(_page, _base, _field)			\
	do {								\
		if ((_page)->lru.prev != _base) {			\
			struct page *prev;				\
									\
			prev = lru_to_page(&(_page->lru));		\
			prefetchw(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetchw_prev_lru_page(_page, _base, _field) do { } while (0)
#endif

/*
 * From 0 .. 100.  Higher means more swappy.
 */
int vm_swappiness = 60;
/*
 * The total number of pages which are beyond the high watermark within all
 * zones.
 */
unsigned long vm_total_pages;

static LIST_HEAD(shrinker_list);
static DECLARE_RWSEM(shrinker_rwsem);

#ifdef CONFIG_MEMCG
static bool global_reclaim(struct scan_control *sc)
{
	return !sc->target_mem_cgroup;
}
#else
static bool global_reclaim(struct scan_control *sc)
{
	return true;
}
#endif

/* 计算zone能够回收的内存页框总数，也就是没有锁在内存中的匿名页和文件页之和 */
static unsigned long zone_reclaimable_pages(struct zone *zone)
{
	int nr;

	nr = zone_page_state(zone, NR_ACTIVE_FILE) +
	     zone_page_state(zone, NR_INACTIVE_FILE);

	/* 开启了swap的情况 */
	if (get_nr_swap_pages() > 0)
		nr += zone_page_state(zone, NR_ACTIVE_ANON) +
		      zone_page_state(zone, NR_INACTIVE_ANON);

	return nr;
}

/* 判断zone是否能够进行内存回收，判断的标准是 扫描的页数 < (所有可回收页框的数量 * 6) 
 * 也就是已经对此zone的所有可回收页框扫描过6遍了，则此zone不能进行内存回收
 */
bool zone_reclaimable(struct zone *zone)
{
	return zone_page_state(zone, NR_PAGES_SCANNED) <
		zone_reclaimable_pages(zone) * 6;
}

static unsigned long get_lru_size(struct lruvec *lruvec, enum lru_list lru)
{
	if (!mem_cgroup_disabled())
		return mem_cgroup_get_lru_size(lruvec, lru);

	return zone_page_state(lruvec_zone(lruvec), NR_LRU_BASE + lru);
}

/*
 * Add a shrinker callback to be called from the vm.
 */
int register_shrinker(struct shrinker *shrinker)
{
	size_t size = sizeof(*shrinker->nr_deferred);

	/*
	 * If we only have one possible node in the system anyway, save
	 * ourselves the trouble and disable NUMA aware behavior. This way we
	 * will save memory and some small loop time later.
	 */
	if (nr_node_ids == 1)
		shrinker->flags &= ~SHRINKER_NUMA_AWARE;

	if (shrinker->flags & SHRINKER_NUMA_AWARE)
		size *= nr_node_ids;

	shrinker->nr_deferred = kzalloc(size, GFP_KERNEL);
	if (!shrinker->nr_deferred)
		return -ENOMEM;

	down_write(&shrinker_rwsem);
	list_add_tail(&shrinker->list, &shrinker_list);
	up_write(&shrinker_rwsem);
	return 0;
}
EXPORT_SYMBOL(register_shrinker);

/*
 * Remove one
 */
void unregister_shrinker(struct shrinker *shrinker)
{
	down_write(&shrinker_rwsem);
	list_del(&shrinker->list);
	up_write(&shrinker_rwsem);
	kfree(shrinker->nr_deferred);
}
EXPORT_SYMBOL(unregister_shrinker);

#define SHRINK_BATCH 128

static unsigned long
shrink_slab_node(struct shrink_control *shrinkctl, struct shrinker *shrinker,
		 unsigned long nr_pages_scanned, unsigned long lru_pages)
{
	unsigned long freed = 0;
	unsigned long long delta;
	long total_scan;
	long freeable;
	long nr;
	long new_nr;
	int nid = shrinkctl->nid;
	long batch_size = shrinker->batch ? shrinker->batch
					  : SHRINK_BATCH;

	freeable = shrinker->count_objects(shrinker, shrinkctl);
	if (freeable == 0)
		return 0;

	/*
	 * copy the current shrinker scan count into a local variable
	 * and zero it so that other concurrent shrinker invocations
	 * don't also do this scanning work.
	 */
	nr = atomic_long_xchg(&shrinker->nr_deferred[nid], 0);

	total_scan = nr;
	delta = (4 * nr_pages_scanned) / shrinker->seeks;
	delta *= freeable;
	do_div(delta, lru_pages + 1);
	total_scan += delta;
	if (total_scan < 0) {
		printk(KERN_ERR
		"shrink_slab: %pF negative objects to delete nr=%ld\n",
		       shrinker->scan_objects, total_scan);
		total_scan = freeable;
	}

	/*
	 * We need to avoid excessive windup on filesystem shrinkers
	 * due to large numbers of GFP_NOFS allocations causing the
	 * shrinkers to return -1 all the time. This results in a large
	 * nr being built up so when a shrink that can do some work
	 * comes along it empties the entire cache due to nr >>>
	 * freeable. This is bad for sustaining a working set in
	 * memory.
	 *
	 * Hence only allow the shrinker to scan the entire cache when
	 * a large delta change is calculated directly.
	 */
	if (delta < freeable / 4)
		total_scan = min(total_scan, freeable / 2);

	/*
	 * Avoid risking looping forever due to too large nr value:
	 * never try to free more than twice the estimate number of
	 * freeable entries.
	 */
	if (total_scan > freeable * 2)
		total_scan = freeable * 2;

	trace_mm_shrink_slab_start(shrinker, shrinkctl, nr,
				nr_pages_scanned, lru_pages,
				freeable, delta, total_scan);

	/*
	 * Normally, we should not scan less than batch_size objects in one
	 * pass to avoid too frequent shrinker calls, but if the slab has less
	 * than batch_size objects in total and we are really tight on memory,
	 * we will try to reclaim all available objects, otherwise we can end
	 * up failing allocations although there are plenty of reclaimable
	 * objects spread over several slabs with usage less than the
	 * batch_size.
	 *
	 * We detect the "tight on memory" situations by looking at the total
	 * number of objects we want to scan (total_scan). If it is greater
	 * than the total number of objects on slab (freeable), we must be
	 * scanning at high prio and therefore should try to reclaim as much as
	 * possible.
	 */
	while (total_scan >= batch_size ||
	       total_scan >= freeable) {
		unsigned long ret;
		unsigned long nr_to_scan = min(batch_size, total_scan);

		shrinkctl->nr_to_scan = nr_to_scan;
		ret = shrinker->scan_objects(shrinker, shrinkctl);
		if (ret == SHRINK_STOP)
			break;
		freed += ret;

		count_vm_events(SLABS_SCANNED, nr_to_scan);
		total_scan -= nr_to_scan;

		cond_resched();
	}

	/*
	 * move the unused scan count back into the shrinker in a
	 * manner that handles concurrent updates. If we exhausted the
	 * scan, there is no need to do an update.
	 */
	if (total_scan > 0)
		new_nr = atomic_long_add_return(total_scan,
						&shrinker->nr_deferred[nid]);
	else
		new_nr = atomic_long_read(&shrinker->nr_deferred[nid]);

	trace_mm_shrink_slab_end(shrinker, nid, freed, nr, new_nr, total_scan);
	return freed;
}

/*
 * Call the shrink functions to age shrinkable caches
 *
 * Here we assume it costs one seek to replace a lru page and that it also
 * takes a seek to recreate a cache object.  With this in mind we age equal
 * percentages of the lru and ageable caches.  This should balance the seeks
 * generated by these structures.
 *
 * If the vm encountered mapped pages on the LRU it increase the pressure on
 * slab to avoid swapping.
 *
 * We do weird things to avoid (scanned*seeks*entries) overflowing 32 bits.
 *
 * `lru_pages' represents the number of on-LRU pages in all the zones which
 * are eligible for the caller's allocation attempt.  It is used for balancing
 * slab reclaim versus page reclaim.
 *
 * Returns the number of slab objects which we shrunk.
 */
unsigned long shrink_slab(struct shrink_control *shrinkctl,
			  unsigned long nr_pages_scanned,
			  unsigned long lru_pages)
{
	struct shrinker *shrinker;
	unsigned long freed = 0;

	if (nr_pages_scanned == 0)
		nr_pages_scanned = SWAP_CLUSTER_MAX;

	if (!down_read_trylock(&shrinker_rwsem)) {
		/*
		 * If we would return 0, our callers would understand that we
		 * have nothing else to shrink and give up trying. By returning
		 * 1 we keep it going and assume we'll be able to shrink next
		 * time.
		 */
		freed = 1;
		goto out;
	}

	/* 遍历shrinker_list链表，获取每一个struct shrinker结构 
	 * 创建一些slab时，因为有些slab是可以直接回收的，比如说vfs使用的struct dentry和struct inode，创建这个struct dentry的slab时，会调用register_shrinker()函数注册一个struct shrinker
	 * 这个struct shrinker链入到shrinker_list中，表示当这些slab即使对象在使用时也可以进行回收，把使用的对象释放掉
	 */
	list_for_each_entry(shrinker, &shrinker_list, list) {
		if (!(shrinker->flags & SHRINKER_NUMA_AWARE)) {
			shrinkctl->nid = 0;
			freed += shrink_slab_node(shrinkctl, shrinker,
					nr_pages_scanned, lru_pages);
			continue;
		}

		for_each_node_mask(shrinkctl->nid, shrinkctl->nodes_to_scan) {
			if (node_online(shrinkctl->nid))
				freed += shrink_slab_node(shrinkctl, shrinker,
						nr_pages_scanned, lru_pages);

		}
	}
	up_read(&shrinker_rwsem);
out:
	cond_resched();
	return freed;
}

static inline int is_page_cache_freeable(struct page *page)
{
	/*
	 * A freeable page cache page is referenced only by the caller
	 * that isolated the page, the page cache radix tree and
	 * optional buffer heads at page->private.
	 */
	return page_count(page) - page_has_private(page) == 2;
}

static int may_write_to_queue(struct backing_dev_info *bdi,
			      struct scan_control *sc)
{
	if (current->flags & PF_SWAPWRITE)
		return 1;
	if (!bdi_write_congested(bdi))
		return 1;
	if (bdi == current->backing_dev_info)
		return 1;
	return 0;
}

/*
 * We detected a synchronous write error writing a page out.  Probably
 * -ENOSPC.  We need to propagate that into the address_space for a subsequent
 * fsync(), msync() or close().
 *
 * The tricky part is that after writepage we cannot touch the mapping: nothing
 * prevents it from being freed up.  But we have a ref on the page and once
 * that page is locked, the mapping is pinned.
 *
 * We're allowed to run sleeping lock_page() here because we know the caller has
 * __GFP_FS.
 */
static void handle_write_error(struct address_space *mapping,
				struct page *page, int error)
{
	lock_page(page);
	if (page_mapping(page) == mapping)
		mapping_set_error(mapping, error);
	unlock_page(page);
}

/* possible outcome of pageout() */
typedef enum {
	/* failed to write page out, page is locked */
	PAGE_KEEP,
	/* move page to the active list, page is locked */
	PAGE_ACTIVATE,
	/* page has been sent to the disk successfully, page is unlocked */
	PAGE_SUCCESS,
	/* page is clean and locked */
	PAGE_CLEAN,
} pageout_t;

/*
 * pageout is called by shrink_page_list() for each dirty page.
 * Calls ->writepage().
 */
/* 将可以回收的页进行回写到磁盘，当页经过判断不能在回写后就可以回收时，则不会对页进行回写 
 * 在调用此之前，如果是匿名页，则已经加入到了swapcache中，并且已经对页进行过unmap操作，但是有可能又有进程映射了此页
 * 进入此函数前，page的PG_lock一定要置位
 */
static pageout_t pageout(struct page *page, struct address_space *mapping,
			 struct scan_control *sc)
{
	/*
	 * If the page is dirty, only perform writeback if that write
	 * will be non-blocking.  To prevent this allocation from being
	 * stalled by pagecache activity.  But note that there may be
	 * stalls if we need to run get_block().  We could test
	 * PagePrivate for that.
	 *
	 * If this process is currently in __generic_file_write_iter() against
	 * this page's queue, we can perform writeback even if that
	 * will block.
	 *
	 * If the page is swapcache, write it back even if that would
	 * block, for some throttling. This happens by accident, because
	 * swap_backing_dev_info is bust: it doesn't reflect the
	 * congestion state of the swapdevs.  Easy to fix, if needed.
	 */
	/* 判断此页是否可以进行回收
	 * 主要判断的是page->_count - page_has_private(page)是否为2，page_has_private(page)要么为1要么为0，为1说明此page有buffer_head
	 * 当_count为3时，说明此页回写后，剩下的工作只有移除buffer_head和从address_space的基树中移除此页，这两个操作了
	 * 当_count为2时，说明此页无buffer_head，当回写此页后，只需要将此页从address_space的基树中移除，此页就可以回收了
	 * 否则，此页还要保留在内存中，就不会对此页进行回收导致的回写，也就是说，即使是脏文件页，只要这个脏文件页不能很快释放，也不会对它进行回写
	 */
	if (!is_page_cache_freeable(page))
		return PAGE_KEEP;

	/* mapping为空的情况，一些用在特殊用途的页的mapping为空，日志缓冲区的页? */
	if (!mapping) {
		/*
		 * Some data journaling orphaned pages can have
		 * page->mapping == NULL while being dirty with clean buffers.
		 */
		/* 如果此页标记了PAGE_FLAGS_PRIVATE，说明此页有buffer_head，直接释放此页对应的buffer_head(链表头保存在page->private中)，然后此页就可以释放了 */
		if (page_has_private(page)) {
			/* 释放buffer_head，此页的page->_count-- */
			if (try_to_free_buffers(page)) {
				ClearPageDirty(page);
				pr_info("%s: orphaned page\n", __func__);
				return PAGE_CLEAN;
			}
		}
		return PAGE_KEEP;
	}
	/* 此页对应的mapping->a_ops->writepage函数为空，之后将此页移动到活动lru链表 */
	if (mapping->a_ops->writepage == NULL)
		return PAGE_ACTIVATE;
	/* 此页对应的mapping->backing_dev_info是否可用 */
	if (!may_write_to_queue(mapping->backing_dev_info, sc))
		return PAGE_KEEP;

	/* 这里会对page进行反向映射，把映射了此页的进程页表项中的_PAGE_RW和_PAGE_DIRTY标志
	 * 并且把page的PG_dirty也进行清空，并会对zone的NR_FILE_DIRTY进行--
	 */
	if (clear_page_dirty_for_io(page)) {
		int res;
		/* 回写控制结构 */
		struct writeback_control wbc = {
			/* 异步，回写时并不阻塞到回写结束 */
			.sync_mode = WB_SYNC_NONE,
			.nr_to_write = SWAP_CLUSTER_MAX,
			.range_start = 0,
			.range_end = LLONG_MAX,
			.for_reclaim = 1,
		};

		/* 设置此页正在进行回收 */
		SetPageReclaim(page);
		/* 将此page加入到块层的等待队列中，如果是文件页，回写时会对文件页所在基树的PAGECACHE_TAG_WRITEBACK标志置位，回写后清除PAGECACHE_TAG_WRITEBACK标志
		 * 在此函数中，会置位page的PG_writeback标志，说明此页正在进行回写
		 * 当回写完成后，会清除此PG_writeback标志，并且清除PG_lock标志
		 * 虽然表明是异步回写，但是有些文件系统比较特殊，只支持同步回写，所以也会进行同步回写，比如ramdisk
		 */
		res = mapping->a_ops->writepage(page, &wbc);
		/* 发生错误 */
		if (res < 0)
			handle_write_error(mapping, page, res);
		if (res == AOP_WRITEPAGE_ACTIVATE) {
			ClearPageReclaim(page);
			return PAGE_ACTIVATE;
		}

		/* page的PG_writeback没有置位，这种情况发生在同步回写或者writepage有问题的情况 
		 * 在同步回写的情况下，PG_writeback没有置位说明已经回写完成，那么清除PG_reclaim标志
		 */
		if (!PageWriteback(page)) {
			/* synchronous write or broken a_ops? */
			/* 清除页的PG_reclaim回收标志 */
			ClearPageReclaim(page);
		}
		trace_mm_vmscan_writepage(page, trace_reclaim_flags(page));
		/* 增加zone的回写计数 */
		inc_zone_page_state(page, NR_VMSCAN_WRITE);
		return PAGE_SUCCESS;
	}

	/* 这个页不是脏页，不需要回写 */
	return PAGE_CLEAN;
}

/*
 * Same as remove_mapping, but if the page is removed from the mapping, it
 * gets returned with a refcount of 0.
 */
static int __remove_mapping(struct address_space *mapping, struct page *page,
			    bool reclaimed)
{
	BUG_ON(!PageLocked(page));
	BUG_ON(mapping != page_mapping(page));

	spin_lock_irq(&mapping->tree_lock);
	/*
	 * The non racy check for a busy page.
	 *
	 * Must be careful with the order of the tests. When someone has
	 * a ref to the page, it may be possible that they dirty it then
	 * drop the reference. So if PageDirty is tested before page_count
	 * here, then the following race may occur:
	 *
	 * get_user_pages(&page);
	 * [user mapping goes away]
	 * write_to(page);
	 *				!PageDirty(page)    [good]
	 * SetPageDirty(page);
	 * put_page(page);
	 *				!page_count(page)   [good, discard it]
	 *
	 * [oops, our write_to data is lost]
	 *
	 * Reversing the order of the tests ensures such a situation cannot
	 * escape unnoticed. The smp_rmb is needed to ensure the page->flags
	 * load is not satisfied before that of page->_count.
	 *
	 * Note that if SetPageDirty is always performed via set_page_dirty,
	 * and thus under tree_lock, then this ordering is not required.
	 */
	/* page->_count是否等于2，如果是，则让page->_count = 0 
	 * 大多数情况下，到这里page->_count都为2
	 */
	if (!page_freeze_refs(page, 2))
		goto cannot_free;
	/* note: atomic_cmpxchg in page_freeze_refs provides the smp_rmb */
	if (unlikely(PageDirty(page))) {
		/* 此页为脏页，不能进行remove_mapping，把其page->_count设置为2 */
		page_unfreeze_refs(page, 2);
		goto cannot_free;
	}

	if (PageSwapCache(page)) {
		swp_entry_t swap = { .val = page_private(page) };
		mem_cgroup_swapout(page, swap);
		/* 将page从swapcache中删除 */
		__delete_from_swap_cache(page);
		spin_unlock_irq(&mapping->tree_lock);
		swapcache_free(swap);
	} else {
		void (*freepage)(struct page *);
		void *shadow = NULL;

		freepage = mapping->a_ops->freepage;
		/*
		 * Remember a shadow entry for reclaimed file cache in
		 * order to detect refaults, thus thrashing, later on.
		 *
		 * But don't store shadows in an address space that is
		 * already exiting.  This is not just an optizimation,
		 * inode reclaim needs to empty out the radix tree or
		 * the nodes are lost.  Don't plant shadows behind its
		 * back.
		 */
		if (reclaimed && page_is_file_cache(page) &&
		    !mapping_exiting(mapping))
			shadow = workingset_eviction(mapping, page);
		/* 将文件页从它的文件的address_space的基树中删除 */
		__delete_from_page_cache(page, shadow);
		spin_unlock_irq(&mapping->tree_lock);

		if (freepage != NULL)
			freepage(page);
	}

	return 1;

cannot_free:
	spin_unlock_irq(&mapping->tree_lock);
	return 0;
}

/*
 * Attempt to detach a locked page from its ->mapping.  If it is dirty or if
 * someone else has a ref on the page, abort and return 0.  If it was
 * successfully detached, return 1.  Assumes the caller has a single ref on
 * this page.
 */
int remove_mapping(struct address_space *mapping, struct page *page)
{
	if (__remove_mapping(mapping, page, false)) {
		/*
		 * Unfreezing the refcount with 1 rather than 2 effectively
		 * drops the pagecache ref for us without requiring another
		 * atomic operation.
		 */
		page_unfreeze_refs(page, 1);
		return 1;
	}
	return 0;
}

/**
 * putback_lru_page - put previously isolated page onto appropriate LRU list
 * @page: page to be put back to appropriate lru list
 *
 * Add previously isolated @page to appropriate LRU list.
 * Page may still be unevictable for other reasons.
 *
 * lru_lock must not be held, interrupts must be enabled.
 */
/* 将页放入lru链表中，调用这个函数前提是此页必须不能在lru链表上 */
void putback_lru_page(struct page *page)
{
	bool is_unevictable;
	/* 获取此页是不是unevictable的页 */
	int was_unevictable = PageUnevictable(page);

	VM_BUG_ON_PAGE(PageLRU(page), page);

redo:
	/* 清除此页描述符的unevictable标志，上面已经获取了此标志，这里清除是用于下下个判断 */
	ClearPageUnevictable(page);

	/* 如果是evictable的，注意这里判断并不是通过页描述符的PageUnevictable标志进行判断，这个标志在上面已经被清除
	 * 通过此页对应的address_space和此页的PG_mlock进行判断
	 */
	if (page_evictable(page)) {
		/*
		 * For evictable pages, we can use the cache.
		 * In event of a race, worst case is we end up with an
		 * unevictable page on [in]active list.
		 * We know how to handle that.
		 */
		is_unevictable = false;
		/* 将页加入到lru_add这个lru缓存中，这个缓存中的页都是原来不在lru上，准备加入到lru链表中
		 * page->_count++
		 */
		lru_cache_add(page);
	} else {
		/* 是unevictable的，会将此页放入LRU_UNEVICTABLE链表，这个链表上的页不能被换出 */
		/*
		 * Put unevictable pages directly on zone's unevictable
		 * list.
		 */
		is_unevictable = true;
		/* 将此页加入到LRU_UNEVICTABLE */
		add_page_to_unevictable_list(page);
		/*
		 * When racing with an mlock or AS_UNEVICTABLE clearing
		 * (page is unlocked) make sure that if the other thread
		 * does not observe our setting of PG_lru and fails
		 * isolation/check_move_unevictable_pages,
		 * we see PG_mlocked/AS_UNEVICTABLE cleared below and move
		 * the page back to the evictable list.
		 *
		 * The other side is TestClearPageMlocked() or shmem_lock().
		 */
		smp_mb();
	}

	/*
	 * page's status can change while we move it among lru. If an evictable
	 * page is on unevictable list, it never be freed. To avoid that,
	 * check after we added it to the list, again.
	 */
	/* 这里是检查一种情况，此页在上面加入到不可回收页的lru链表时，此页的状态发生了改变，变为可回收页了 */
	if (is_unevictable && page_evictable(page)) {
		/* 将此页从lru中拿出，page->_count++ */
		if (!isolate_lru_page(page)) {
			/* page->_count--，在isolate_lru_page()中会增加一次，这里释放一次 */
			put_page(page);
			/* 然后再次重新将它放入lru */
			goto redo;
		}
		/* This means someone else dropped this page from LRU
		 * So, it will be freed or putback to LRU again. There is
		 * nothing to do here.
		 */
	}

	/* 统计 */
	if (was_unevictable && !is_unevictable)
		count_vm_event(UNEVICTABLE_PGRESCUED);
	else if (!was_unevictable && is_unevictable)
		count_vm_event(UNEVICTABLE_PGCULLED);
	/* 减少此页的引用计数，page->_count++ */
	put_page(page);		/* drop ref from isolate */
}

enum page_references {
	PAGEREF_RECLAIM,
	PAGEREF_RECLAIM_CLEAN,
	PAGEREF_KEEP,
	PAGEREF_ACTIVATE,
};

/* 检查此页能否进行回收 */
static enum page_references page_check_references(struct page *page,
						  struct scan_control *sc)
{
	int referenced_ptes, referenced_page;
	unsigned long vm_flags;

	/* 返回此页最近被多少个进程访问过，通过映射了此页的页表项中的Accessed项进行判断，需要反向映射
	 * 反向映射时会清空映射了此页的页表项的Accessed标志
	 */
	referenced_ptes = page_referenced(page, 1, sc->target_mem_cgroup,
					  &vm_flags);
	/* 获取此页的PG_referenced并清除此标志，此标志用于标志此页最近是否被访问过 */
	referenced_page = TestClearPageReferenced(page);

	/*
	 * Mlock lost the isolation race with us.  Let try_to_unmap()
	 * move the page to the unevictable list.
	 */
	/* vma的vm_flags中有VM_LOCKED，则返回PAGEREF_RECLAIM，之后会把此页移动到lru_unevictable_page链表 */
	if (vm_flags & VM_LOCKED)
		return PAGEREF_RECLAIM;

	/*
	 * 如果是匿名页，只要最近此页被进程访问过，则将此页移动到活动lru链表，否则回收
	 * 如果是映射可执行文件的文件页，只要最近被进程访问过，就放到活动lru链表，否则回收
	 * 如果是其他的文件页，如果最近被多个进程访问过，移动到活动lru链表，如果只被1个进程访问过，但是PG_referenced置位了，也放入活动lru链表，其他情况回收
	 */

	/* 此页最近被进程访问过，通过映射了此页的页表项中的Accessed项进行判断，需要反向映射 */
	if (referenced_ptes) {
		/* 此页属于匿名页，最近被访问过，则移动到活动lru链表 */
		if (PageSwapBacked(page))
			return PAGEREF_ACTIVATE;
		/*
		 * All mapped pages start out with page table
		 * references from the instantiating fault, so we need
		 * to look twice if a mapped file page is used more
		 * than once.
		 *
		 * Mark it and spare it for another trip around the
		 * inactive list.  Another page table reference will
		 * lead to its activation.
		 *
		 * Note: the mark is set for activated pages as well
		 * so that recently deactivated but used pages are
		 * quickly recovered.
		 */
		/* 这里是此页是文件页 */
		
		/* 设置此文件页PG_referenced标志，因为此页最近被进程访问过 */
		SetPageReferenced(page);

		/* 
		 * 此页之前被设置了PG_referenced，或者访问过此页的进程多于1个 
		 * 把此文件页放到活动lru链表中
		 */
		if (referenced_page || referenced_ptes > 1)
			return PAGEREF_ACTIVATE;

		/*
		 * Activate file-backed executable pages after first usage.
		 */
		/* 此页是映射了可执行文件的页，页放入到活动lru链表中 */
		if (vm_flags & VM_EXEC)
			return PAGEREF_ACTIVATE;

		/* 保持在原来所在的lru链表中，这里是非活动lru链表
		 * 保持在非活动lru链表的页，是那些文件页，并且最近被访问过，但是只被访问过一次的页
		 * 文件页之前PG_referenced被置位，再被访问时，如果检查到PG_referenced已经被置位，则移动到活动文件页lru链表，否则不动
		 */
		return PAGEREF_KEEP;
	}

	/* Reclaim if clean, defer dirty pages to writeback */
	/* 如果此页是文件页，最近没被进程访问过，但此页的PG_referenced被置位，那就回收(映射可执行文件的页页可能在此回收) */
	if (referenced_page && !PageSwapBacked(page))
		return PAGEREF_RECLAIM_CLEAN;

	/* 此页进行回收 */
	return PAGEREF_RECLAIM;
}

/* Check if a page is dirty or under writeback */
static void page_check_dirty_writeback(struct page *page,
				       bool *dirty, bool *writeback)
{
	struct address_space *mapping;

	/*
	 * Anonymous pages are not handled by flushers and must be written
	 * from reclaim context. Do not stall reclaim based on them
	 */
	/* 如果页不是文件页 */
	if (!page_is_file_cache(page)) {
		*dirty = false;
		*writeback = false;
		return;
	}

	/* By default assume that the page flags are accurate */
	*dirty = PageDirty(page);
	*writeback = PageWriteback(page);

	/* Verify dirty/writeback state if the filesystem supports it */
	if (!page_has_private(page))
		return;

	mapping = page_mapping(page);
	/* 如果文件所属文件系统有特定is_dirty_writeback操作，则执行文件系统特定的is_dirty_writeback操作 */
	if (mapping && mapping->a_ops->is_dirty_writeback)
		mapping->a_ops->is_dirty_writeback(page, dirty, writeback);
}

/*
 * shrink_page_list() returns the number of reclaimed pages
 */
/* 在page_list中的页都是非活动lru链表的，并且都是同一类型的页(ANON/FILE)
 * 注意page_list中的页还没有被标注进行回收的标志(PG_reclaim)，并且如果为脏页的页(PG_dirty被设置)，那么只有在kswapd调用到此会进行writeback(回写到磁盘)操作
 * 到达这里之前，所有pagevec中的页都放回了lru链表中
 * force_reclaim: 表示是否强制进行回收，强制进行回收则不会判断此页是否应该回收，强制回收的意思是即使页最近被访问过了，也进行回收，除非页被mlock在内存中，或者unmap失败
 * ret_nr_dirty: 脏页数量(包括正在回写和没有回写的脏页)
 * ret_nr_unqueued_dirty: 是脏页但没有进行回写的页
 * ret_nr_congested: 正在进行回写，但是设备正忙
 * ret_nr_writeback: 正在进行回写但不是在回收的页框数量
 * ret_nr_immediate: 正在进行回写的回收页框数量
 */
static unsigned long shrink_page_list(struct list_head *page_list,
				      struct zone *zone,
				      struct scan_control *sc,
				      enum ttu_flags ttu_flags,
				      unsigned long *ret_nr_dirty,
				      unsigned long *ret_nr_unqueued_dirty,
				      unsigned long *ret_nr_congested,
				      unsigned long *ret_nr_writeback,
				      unsigned long *ret_nr_immediate,
				      bool force_reclaim)
{
	/* 初始化两个链表头 */
	LIST_HEAD(ret_pages);
	/* 这个链表保存本次回收就可以立即进行释放的页 */
	LIST_HEAD(free_pages);
	int pgactivate = 0;
	unsigned long nr_unqueued_dirty = 0;
	unsigned long nr_dirty = 0;
	unsigned long nr_congested = 0;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_writeback = 0;
	unsigned long nr_immediate = 0;

	/* 检查是否需要调度，需要则调度 */
	cond_resched();

	/* 将page_list中的页一个一个释放 */
	while (!list_empty(page_list)) {
		struct address_space *mapping;
		struct page *page;
		int may_enter_fs;
		enum page_references references = PAGEREF_RECLAIM_CLEAN;
		bool dirty, writeback;

		/* 检查是否需要调度，需要则调度 */
		cond_resched();

		/* 从page_list末尾拿出一个页 */
		page = lru_to_page(page_list);
		/* 将此页从page_list中删除 */
		list_del(&page->lru);

		/* 尝试对此页上锁，如果无法上锁，说明此页正在被其他路径控制，跳转到keep 
		 * 对页上锁后，所有访问此页的进程都会加入到zone->wait_table[hash_ptr(page, zone->wait_table_bits)]
		 */
		if (!trylock_page(page))
			goto keep;

		/* 在page_list的页一定都是非活动的 */
		VM_BUG_ON_PAGE(PageActive(page), page);
		/* 页所属的zone也要与传入的zone一致 */
		VM_BUG_ON_PAGE(page_zone(page) != zone, page);

		/* 扫描的页数量++ */
		sc->nr_scanned++;

		/* 如果此页被锁在内存中，则跳转到cull_mlocked */	
		if (unlikely(!page_evictable(page)))
			goto cull_mlocked;

		/* 如果扫描控制结构中标识不允许进行unmap操作，并且此页有被映射到页表中，跳转到keep_locked */
		if (!sc->may_unmap && page_mapped(page))
			goto keep_locked;

		/* Double the slab pressure for mapped and swapcache pages */
		/* 对于处于swapcache中或者有进程映射了的页，对sc->nr_scanned再进行一次++
		 * swapcache用于在页换出到swap时，页会先跑到swapcache中，当此页完全写入swap分区后，在没有进程对此页进行访问时，swapcache才会释放掉此页 
		 * 这样做是为了让sc->nr_scanned增加得更快?
		 */
		if (page_mapped(page) || PageSwapCache(page))
			sc->nr_scanned++;

		/* 本次回收是否允许执行IO操作 */
		may_enter_fs = (sc->gfp_mask & __GFP_FS) ||
			(PageSwapCache(page) && (sc->gfp_mask & __GFP_IO));

		/*
		 * The number of dirty pages determines if a zone is marked
		 * reclaim_congested which affects wait_iff_congested. kswapd
		 * will stall and start writing pages if the tail of the LRU
		 * is all dirty unqueued pages.
		 */
		/* 检查是否是脏页还有此页是否正在回写到磁盘 
		 * 这里面主要判断页描述符的PG_dirty和PG_writeback两个标志
		 * 匿名页当加入swapcache后，就会被标记PG_dirty
		 * 如果文件所属文件系统有特定is_dirty_writeback操作，则执行文件系统特定的is_dirty_writeback操作
		 */
		page_check_dirty_writeback(page, &dirty, &writeback);
		/* 如果是脏页或者正在回写的页，脏页数量++ */
		if (dirty || writeback)
			nr_dirty++;

		/* 是脏页但并没有正在回写，则增加没有进行回写的脏页计数 */
		if (dirty && !writeback)
			nr_unqueued_dirty++;

		/*
		 * Treat this page as congested if the underlying BDI is or if
		 * pages are cycling through the LRU so quickly that the
		 * pages marked for immediate reclaim are making it to the
		 * end of the LRU a second time.
		 */
		/* 获取此页对应的address_space，如果此页是匿名页，则为NULL */
		mapping = page_mapping(page);
		/* 如果此页映射的文件所在的磁盘设备等待队列中有数据(正在进行IO处理)或者此页已经在进行回写回收 */
		if ((mapping && bdi_write_congested(mapping->backing_dev_info)) ||
		    (writeback && PageReclaim(page)))
		    /* 可能比较晚才能进行阻塞回写的页的数量 
		 	 * 因为磁盘设备现在繁忙，队列中有太多需要写入的数据
		 	 */
			nr_congested++;

		/*
		 * If a page at the tail of the LRU is under writeback, there
		 * are three cases to consider.
		 *
		 * 1) If reclaim is encountering an excessive number of pages
		 *    under writeback and this page is both under writeback and
		 *    PageReclaim then it indicates that pages are being queued
		 *    for IO but are being recycled through the LRU before the
		 *    IO can complete. Waiting on the page itself risks an
		 *    indefinite stall if it is impossible to writeback the
		 *    page due to IO error or disconnected storage so instead
		 *    note that the LRU is being scanned too quickly and the
		 *    caller can stall after page list has been processed.
		 *
		 * 2) Global reclaim encounters a page, memcg encounters a
		 *    page that is not marked for immediate reclaim or
		 *    the caller does not have __GFP_IO. In this case mark
		 *    the page for immediate reclaim and continue scanning.
		 *
		 *    __GFP_IO is checked  because a loop driver thread might
		 *    enter reclaim, and deadlock if it waits on a page for
		 *    which it is needed to do the write (loop masks off
		 *    __GFP_IO|__GFP_FS for this reason); but more thought
		 *    would probably show more reasons.
		 *
		 *    Don't require __GFP_FS, since we're not going into the
		 *    FS, just waiting on its writeback completion. Worryingly,
		 *    ext4 gfs2 and xfs allocate pages with
		 *    grab_cache_page_write_begin(,,AOP_FLAG_NOFS), so testing
		 *    may_enter_fs here is liable to OOM on them.
		 *
		 * 3) memcg encounters a page that is not already marked
		 *    PageReclaim. memcg does not have any dirty pages
		 *    throttling so we could easily OOM just because too many
		 *    pages are in writeback and there is nothing else to
		 *    reclaim. Wait for the writeback to complete.
		 */
		/* 此页正在进行回写到磁盘，对于正在回写到磁盘的页，是无法进行回收的，除非等待此页回写完成 
		 * 此页正在进行回写有两种情况:
		 * 1.此页是正常的进行回写(脏太久了)
		 * 2.此页是刚不久前进行内存回收时，导致此页进行回写的
		 */
		if (PageWriteback(page)) {
			/* Case 1 above */

			/* 下面的判断都是基于此页正在进行回写到磁盘为前提 */

			/* 当前处于kswapd内核进程，并且此页正在进行回收(可能在等待IO)，然后zone也表明了很多页正在进行回写 
			 * 说明此页是已经在回写到磁盘，并且也正在进行回收的，本次回收不需要对此页进行回收
			 */
			if (current_is_kswapd() &&
			    PageReclaim(page) &&
			    test_bit(ZONE_WRITEBACK, &zone->flags)) {
			    /* 增加nr_immediate计数，此计数说明此页准备就可以回收了 */
				nr_immediate++;
				/* 跳转到keep_locked */
				goto keep_locked;

			/* Case 2 above */
			/* 此页正在进行正常的回写(不是因为要回收此页才进行的回写)
			 * 两种情况会进入这里:
			 * 1.本次是针对整个zone进行内存回收的
			 * 2.本次回收不允许进行IO操作
			 * 那么就标记这个页要回收，本次回收不对此页进行回收，当此页回写完成后，会判断这个PG_reclaim标记，如果置位了，把此页放到非活动lru链表末尾
			 * 快速回收会进入这种情况
			 */
			} else if (global_reclaim(sc) ||
			    !PageReclaim(page) || !(sc->gfp_mask & __GFP_IO)) {
				/*
				 * This is slightly racy - end_page_writeback()
				 * might have just cleared PageReclaim, then
				 * setting PageReclaim here end up interpreted
				 * as PageReadahead - but that does not matter
				 * enough to care.  What we do want is for this
				 * page to have PageReclaim set next time memcg
				 * reclaim reaches the tests above, so it will
				 * then wait_on_page_writeback() to avoid OOM;
				 * and it's also appropriate in global reclaim.
				 */
				/* 设置此页正在进行回收，因为此页正在进行回写，那设置称为进行回收后，回写完成后此页会被放到非活动lru链表末尾 */
				SetPageReclaim(page);
				/* 增加需要回写计数器 */
				nr_writeback++;

				goto keep_locked;

			/* Case 3 above */
			} else {
				/* 等待此页回写完成，回写完成后，尝试对此页进行回收，应该只有针对某个memcg进行回收时才会进入这 */
				wait_on_page_writeback(page);
			}
		}

		/*
		 * 此次回收时非强制进行回收，那要先判断此页需不需要移动到活动lru链表
		 * 如果是匿名页，只要最近此页被进程访问过，则将此页移动到活动lru链表头部，否则回收
		 * 如果是映射可执行文件的文件页，只要最近被进程访问过，就放到活动lru链表，否则回收
		 * 如果是其他的文件页，如果最近被多个进程访问过，移动到活动lru链表，如果只被1个进程访问过，但是PG_referenced置位了，也放入活动lru链表，其他情况回收
		 */
		if (!force_reclaim)
			references = page_check_references(page, sc);

		/* 当此次回收时非强制进行回收时 */
		switch (references) {
		/* 将页放到活动lru链表中 */
		case PAGEREF_ACTIVATE:
			goto activate_locked;
		/* 页继续保存在非活动lru链表中 */
		case PAGEREF_KEEP:
			goto keep_locked;

		/* 这两个在下面的代码都会尝试回收此页 
		 * 注意页所属的vma标记了VM_LOCKED时也会是PAGEREF_RECLAIM，因为后面会要把此页放到lru_unevictable_page链表
		 */
		case PAGEREF_RECLAIM:
		case PAGEREF_RECLAIM_CLEAN:
			; /* try to reclaim the page below */
		}

		/*
		 * Anonymous process memory has backing store?
		 * Try to allocate it some swap space here.
		 */
		/* page为匿名页，但是又不处于swapcache中，这里会尝试将其加入到swapcache中，这个swapcache作为swap缓冲区 
		 * 当页被换出或换入时，会先加入到swapcache，当完全换出或者完全换入时，才会从swapcache中移除
		 * 有了此swapcache，当一个页进行换出时，一个进程访问此页，可以直接从swapcache中获取此页的映射，然后swapcache终止此页的换出操作，这样就不用等页要完全换出后，再重新换回来
		 */
		if (PageAnon(page) && !PageSwapCache(page)) {
			/* 如果本次回收禁止io操作，则跳转到keep_locked，让此匿名页继续在非活动lru链表中 */
			if (!(sc->gfp_mask & __GFP_IO))
				goto keep_locked;
			/* 将页page加入到swap_cache，然后这个页被视为文件页，起始就是将页描述符信息保存到以swap页槽偏移量为索引的结点
 			 * 设置页描述符的private = swap页槽偏移量生成的页表项swp_entry_t，因为后面会设置所有映射了此页的页表项为此swp_entry_t
 			 * 设置页的PG_swapcache标志，表明此页在swapcache中，正在被换出
  			 * 标记页page为脏页(PG_dirty)，后面就会被换出
 			 */
 			 /* 执行成功后，页属于swapcache，并且此页的page->_count会++，但是由于引用此页的进程页表没有设置，进程还是可以正常访问这个页 */
			if (!add_to_swap(page, page_list))
				/* 失败，将此页加入到活动lru链表中 */
				goto activate_locked;
			/* 设置可能会用到文件系统相关的操作 */
			may_enter_fs = 1;

			/* Adding to swap updated mapping */
			/* 获取此匿名页所在的swapcache的address_space，这个是根据page->private中保存的swp_entry_t获得 */
			mapping = page_mapping(page);
		}

		/*
		 * The page is mapped into the page tables of one or more
		 * processes. Try to unmap it here.
		 */
		/* 这里是要对所有映射了此page的页表进行设置
		 * 匿名页会把对应的页表项设置为之前获取的swp_entry_t
		 */
		if (page_mapped(page) && mapping) {
			/* 对所有映射了此页的进程的页表进行此页的unmap操作
			 * ttu_flags基本都有TTU_UNMAP标志
			 * 如果是匿名页，那么page->private中是一个带有swap页槽偏移量的swp_entry_t，此后这个swp_entry_t可以转为页表项
			 * 执行完此后，匿名页在swapcache中，而对于引用了此页的进程而言，此页已经在swap中
			 * 但是当此匿名页还没有完全写到swap中时，如果此时有进程访问此页，会将此页映射到此进程页表中，并取消此页放入swap中的操作，放回匿名页的lru链表(在缺页中断中完成)
			 * 而对于文件页，只需要清空映射了此页的进程页表的页表项，不需要设置新的页表项
			 * 每一个进程unmap此页，此页的page->_count--
			 * 如果反向映射过程中page->_count == 0，则释放此页
			 */
			switch (try_to_unmap(page, ttu_flags)) {
			case SWAP_FAIL:
				goto activate_locked;
			case SWAP_AGAIN:
				goto keep_locked;
			case SWAP_MLOCK:
				goto cull_mlocked;
			case SWAP_SUCCESS:
				; /* try to free the page below */
			}
		}

		/* 如果页为脏页，有两种页
		 * 一种是当匿名页加入到swapcache中时，就被标记为了脏页
		 * 一种是脏的文件页
		 */
		if (PageDirty(page)) {
			/*
			 * Only kswapd can writeback filesystem pages to
			 * avoid risk of stack overflow but only writeback
			 * if many dirty pages have been encountered.
			 */
			/* 只有kswapd内核线程能够进行文件页的回写操作(kswapd中不会造成栈溢出?)，但是只有当zone中有很多脏页时，kswapd也才能进行脏文件页的回写
			 * 此标记说明zone的脏页很多，在回收时隔离出来的页都是没有进行回写的脏页时设置
			 * 也就是此zone脏页不够多，kswapd不用进行回写操作
			 * 当短时间内多次对此zone执行内存回收后，这个ZONE_DIRTY就会被设置，这样做的理由是: 优先回收匿名页和干净的文件页，说不定回收完这些zone中空闲内存就足够了，不需要再进行内存回收了
			 * 而对于匿名页，无论是否是kswapd都可以进行回写
			 */
			if (page_is_file_cache(page) &&
					(!current_is_kswapd() ||
					 !test_bit(ZONE_DIRTY, &zone->flags))) {
				/*
				 * Immediately reclaim when written back.
				 * Similar in principal to deactivate_page()
				 * except we already have the page isolated
				 * and know it's dirty
				 */
				/* 增加优先回收页的数量 */
				inc_zone_page_state(page, NR_VMSCAN_IMMEDIATE);
				/* 设置此页需要回收，这样当此页回写完成后，就会被放入到非活动lru链表尾部 
				 * 不过可惜这里只能等kswapd内核线程对此页进行回写，要么就等系统到期后自动将此页进行回写，非kswapd线程都不能对文件页进行回写
				 */
				SetPageReclaim(page);

				/* 让页移动到非活动lru链表头部，如上所说，当回写完成后，页会被移动到非活动lru链表尾部，而内存回收是从非活动lru链表尾部拿页出来回收的 */
				goto keep_locked;
			}

			/* 当zone没有标记ZONE_DIRTY时，kswapd内核线程则会执行到这里 */
			/* 当page_check_references()获取页的状态是PAGEREF_RECLAIM_CLEAN，则跳到keep_locked
			 * 页最近没被进程访问过，但此页的PG_referenced被置位
			 */
			if (references == PAGEREF_RECLAIM_CLEAN)
				goto keep_locked;
			/* 回收不允许执行文件系统相关操作，则让页移动到非活动lru链表头部 */
			if (!may_enter_fs)
				goto keep_locked;
			/* 回收不允许进行回写，则让页移动到非活动lru链表头部 */
			if (!sc->may_writepage)
				goto keep_locked;

			/* Page is dirty, try to write it out here */
			/* 将页进行回写到磁盘，这里只是将页加入到块层，调用结束并不是代表此页已经回写完成
			 * 主要调用page->mapping->a_ops->writepage进行回写，对于匿名页，也是swapcache的address_space->a_ops->writepage
			 * 页被加入到块层回写队列后，会置位页的PG_writeback，回写完成后清除PG_writeback位，所以在同步模式回写下，结束后PG_writeback位是0的，而异步模式下，PG_writeback很可能为1
			 * 此函数中会清除页的PG_dirty标志
			 * 会标记页的PG_reclaim
			 * 成功将页加入到块层后，页的PG_lock位会清空
			 * 也就是在一个页成功进入到回收导致的回写过程中，它的PG_writeback和PG_reclaim标志会置位，而它的PG_dirty和PG_lock标志会清除
			 * 而此页成功回写后，它的PG_writeback和PG_reclaim位都会被清除
			 */
			switch (pageout(page, mapping, sc)) {
			case PAGE_KEEP:
				/* 页会被移动到非活动lru链表头部 */
				goto keep_locked;
			case PAGE_ACTIVATE:
				/* 页会被移动到活动lru链表 */
				goto activate_locked;
			case PAGE_SUCCESS:
				/* 到这里，页的锁已经被释放，也就是PG_lock被清空 
				 * 对于同步回写(一些特殊文件系统只支持同步回写)，这里的PG_writeback、PG_reclaim、PG_dirty、PG_lock标志都是清0的
				 * 对于异步回写，PG_dirty、PG_lock标志都是为0，PG_writeback、PG_reclaim可能为1可能为0(回写完成为0，否则为1)
				 */

				/* 如果PG_writeback被置位，说明此页正在进行回写，这种情况是异步才会发生 */
				if (PageWriteback(page))
					goto keep;
				
				/* 此页为脏页，这种情况发生在此页最近又被写入了，让其保持在非活动lru链表中 
				 * 还有一种情况，就是匿名页加入到swapcache前，已经没有进程映射此匿名页了，而加入swapcache时不会判断
				 * 但是当对此匿名页进行回写时，会判断此页加入swapcache前是否有进程映射了，如果没有，此页可以直接释放，不需要写入磁盘
				 * 所以在此匿名页回写过程中，就会将此页从swap分区的address_space中的基树拿出来，然后标记为脏页，到这里就会进行判断脏页，之后会释放掉此页
				 */
				if (PageDirty(page))
					goto keep;

				/*
				 * A synchronous write - probably a ramdisk.  Go
				 * ahead and try to reclaim the page.
				 */
				/* 尝试上锁，因为在pageout中会释放page的锁，主要是PG_lock标志 */
				if (!trylock_page(page))
					goto keep;
				if (PageDirty(page) || PageWriteback(page))
					goto keep_locked;
				/* 获取page->mapping */
				mapping = page_mapping(page);

			/* 这个页不是脏页，不需要回写，这种情况只发生在文件页，匿名页当加入到swapcache中时就被设置为脏页 */
			case PAGE_CLEAN:
				; /* try to free the page below */
			}
		}

		/*
		 * If the page has buffers, try to free the buffer mappings
		 * associated with this page. If we succeed we try to free
		 * the page as well.
		 *
		 * We do this even if the page is PageDirty().
		 * try_to_release_page() does not perform I/O, but it is
		 * possible for a page to have PageDirty set, but it is actually
		 * clean (all its buffers are clean).  This happens if the
		 * buffers were written out directly, with submit_bh(). ext3
		 * will do this, as well as the blockdev mapping.
		 * try_to_release_page() will discover that cleanness and will
		 * drop the buffers and mark the page clean - it can be freed.
		 *
		 * Rarely, pages can have buffers and no ->mapping.  These are
		 * the pages which were not successfully invalidated in
		 * truncate_complete_page().  We try to drop those buffers here
		 * and if that worked, and the page is no longer mapped into
		 * process address space (page_count == 1) it can be freed.
		 * Otherwise, leave the page on the LRU so it is swappable.
		 */

		/* 这里的情况只有页已经完成回写后才会到达这里，比如同步回写时(pageout在页回写完成后才返回)，异步回写时，在运行到此之前已经把页回写到磁盘
		 * 没有完成回写的页不会到这里，在pageout()后就跳到keep了
		 */
		
		/* 通过页描述符的PAGE_FLAGS_PRIVATE标记判断是否有buffer_head，这个只有文件页有
		 * 这里不会通过page->private判断，原因是，当匿名页加入到swapcache时，也会使用page->private，而不会标记PAGE_FLAGS_PRIVATE
		 * 只有文件页会使用这个PAGE_FLAGS_PRIVATE，这个标记说明此文件页的page->private指向struct buffer_head链表头
		 */
		if (page_has_private(page)) {
			/* 因为页已经回写完成或者是干净不需要回写的页，释放page->private指向struct buffer_head链表，释放后page->private = NULL 
			 * 释放时必须要保证此页的PG_writeback位为0，也就是此页已经回写到磁盘中了
			 */
			if (!try_to_release_page(page, sc->gfp_mask))
				/* 释放失败，把此页移动到活动lru链表 */
				goto activate_locked;

			/* 一些特殊的页的mapping为空，比如一些日志的缓冲区，对于这些页如果引用计数为1则进行处理 */
			if (!mapping && page_count(page) == 1) {
				/* 对此页解锁，清除PG_lock */
				unlock_page(page);
				/* 对page->_count--，并判断是否为0，如果为0则释放掉此页 */
				if (put_page_testzero(page))
					goto free_it;
				else {
					/*
					 * rare race with speculative reference.
					 * the speculative reference will free
					 * this page shortly, so we may
					 * increment nr_reclaimed here (and
					 * leave it off the LRU).
					 */

					/* 这里不太明白，大概意思是这些页马上就会在其他地方被释放了，所以算作回收页 */
					
					nr_reclaimed++;
					continue;
				}
			}
		}

		/* 
		 * 经过上面的步骤，在没有进程再对此页进行访问的前提下，page->_count应该为2
		 * 表示只有将此页隔离出lru的链表和加入address_space的基树中对此页进行了引用，已经没有其他地方对此页进行引用，
		 * 然后将此页从address_space的基数中移除，然后page->_count - 2，这个页现在就只剩等待着被释放掉了
		 * 如果是匿名页，则是对应的swapcache的address_space的基树
		 * 如果是文件页，则是对应文件的address_space的基树
		 * 当page->_count为2时，才会将此页从address_space的基数中移除，然后再page->_count - 2
		 * 相反，如果此page->_count不为2，说明unmap后又有进程访问了此页，就不对此页进行释放了
		 * 同时，这里对于脏页也不能够进行释放，想象一下，如果一个进程访问了此页，写了数据，又unmap此页，那么此页的page->_count为2，同样也可以释放掉，但是写入的数据就丢失了
		 * 成功返回1，失败返回0
		 */
		if (!mapping || !__remove_mapping(mapping, page, true))
			goto keep_locked;

		/*
		 * At this point, we have no other references and there is
		 * no way to pick any more up (removed from LRU, removed
		 * from pagecache). Can use non-atomic bitops now (and
		 * we obviously don't have to worry about waking up a process
		 * waiting on the page lock, because there are no references.
		 */
		/* 释放page锁 */
		__clear_page_locked(page);
free_it:
		/* page->_count为0才会到这 */
		
		/* 此页可以马上回收，会把它加入到free_pages链表
		 * 到这里的页有三种情况，本次进行同步回写的页，干净的不需要回写的页，之前异步回收时完成异步回写的页
		 * 之前回收进行异步回写的页，不会立即释放，因为上次回收时，对这些页进行的工作有: 
		 * 匿名页: 加入swapcache，反向映射修改了映射了此页的进程页表项，将此匿名页回写到磁盘，将此页保存到非活动匿名页lru链表尾部
		 * 文件页: 反向映射修改了映射了此页的进程页表项，将此文件页回写到磁盘，将此页保存到非活动文件页lru链表尾部
		 * 也就是异步情况这两种页都没有进行实际的回收，而在这些页回写完成后，再进行回收时，这两种页的流程都会到这里进行回收
		 * 也就是本次能够真正回收到的页，可能是之前进行回收时已经处理得差不多并回写完成的页
		 */
		
		/* 回收页数量++ */
		nr_reclaimed++;

		/*
		 * Is there need to periodically free_page_list? It would
		 * appear not as the counts should be low
		 */
		/* 加入到free_pages链表 */
		list_add(&page->lru, &free_pages);
		/* 继续遍历页 */
		continue;

cull_mlocked:
		/* 当前页被mlock所在内存中的情况 */

		/* 此页为匿名页并且已经放入了swapcache中了 */
		if (PageSwapCache(page))
			/* 从swapcache中释放本页在基树的结点，会page->_count-- */
			try_to_free_swap(page);
		
		unlock_page(page);
		/* 把此页放回到lru链表中，因为此页已经被隔离出来了
		 * 加入可回收lru链表后page->_count++，但同时也会释放隔离的page->_count--
		 * 加入unevictablelru不会进行page->_count++
		 */
		putback_lru_page(page);
		continue;

activate_locked:
		/* Not a candidate for swapping, so reclaim swap space. */
		/* 这种是持有页锁(PG_lock)，并且需要把页移动到活动lru链表中的情况 */

		/* 如果此页为匿名页并且放入了swapcache中，并且swap使用率已经超过了50% */
		if (PageSwapCache(page) && vm_swap_full())
			/* 将此页从swapcache的基树中拿出来 */
			try_to_free_swap(page);
		VM_BUG_ON_PAGE(PageActive(page), page)
		/* 设置此页为活动页 */;
		SetPageActive(page);
		/* 需要放回到活动lru链表的页数量 */
		pgactivate++;
keep_locked:
		/* 希望页保持在原来的lru链表中，并且持有页锁的情况 */

		/* 释放页锁(PG_lock) */
		unlock_page(page);
keep:
		/* 希望页保持在原来的lru链表中的情况 */

		/* 把页加入到ret_pages链表中 */
		list_add(&page->lru, &ret_pages);
		VM_BUG_ON_PAGE(PageLRU(page) || PageUnevictable(page), page);
	}

	mem_cgroup_uncharge_list(&free_pages);
	/* 将free_pages中的页释放 */
	free_hot_cold_page_list(&free_pages, true);

	/* 将ret_pages链表加入到page_list中 */
	list_splice(&ret_pages, page_list);
	count_vm_events(PGACTIVATE, pgactivate);

	*ret_nr_dirty += nr_dirty;
	*ret_nr_congested += nr_congested;
	*ret_nr_unqueued_dirty += nr_unqueued_dirty;
	*ret_nr_writeback += nr_writeback;
	*ret_nr_immediate += nr_immediate;
	return nr_reclaimed;
}

unsigned long reclaim_clean_pages_from_list(struct zone *zone,
					    struct list_head *page_list)
{
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.priority = DEF_PRIORITY,
		.may_unmap = 1,
	};
	unsigned long ret, dummy1, dummy2, dummy3, dummy4, dummy5;
	struct page *page, *next;
	LIST_HEAD(clean_pages);

	list_for_each_entry_safe(page, next, page_list, lru) {
		if (page_is_file_cache(page) && !PageDirty(page) &&
		    !isolated_balloon_page(page)) {
			ClearPageActive(page);
			list_move(&page->lru, &clean_pages);
		}
	}

	ret = shrink_page_list(&clean_pages, zone, &sc,
			TTU_UNMAP|TTU_IGNORE_ACCESS,
			&dummy1, &dummy2, &dummy3, &dummy4, &dummy5, true);
	list_splice(&clean_pages, page_list);
	mod_zone_page_state(zone, NR_ISOLATED_FILE, -ret);
	return ret;
}

/*
 * Attempt to remove the specified page from its LRU.  Only take this page
 * if it is of the appropriate PageActive status.  Pages which are being
 * freed elsewhere are also ignored.
 *
 * page:	page to consider
 * mode:	one of the LRU isolation modes defined above
 *
 * returns 0 on success, -ve errno on failure.
 */
/* 将page从lru中拿出来，这里更多的是设置其参数，比如清除PageLRU标志，并没有实际动作从lru中拿出此页 
 * 返回0: 表示此页成功从lru链表中拿出来
 * 否则返回错误信息
 */
int __isolate_lru_page(struct page *page, isolate_mode_t mode)
{
	int ret = -EINVAL;

	/* Only take pages on the LRU. */
	/* 此页必须在lru中 */
	if (!PageLRU(page))
		return ret;

	/* Compaction should not handle unevictable pages but CMA can do so */
	/* 当前mode表示不处理被锁在内存中的页，并且此页被锁在内存中 */
	if (PageUnevictable(page) && !(mode & ISOLATE_UNEVICTABLE))
		return ret;

	ret = -EBUSY;

	/*
	 * To minimise LRU disruption, the caller can indicate that it only
	 * wants to isolate pages it will be able to operate on without
	 * blocking - clean pages for the most part.
	 *
	 * ISOLATE_CLEAN means that only clean pages should be isolated. This
	 * is used by reclaim when it is cannot write to backing storage
	 *
	 * ISOLATE_ASYNC_MIGRATE is used to indicate that it only wants to pages
	 * that it is possible to migrate without blocking
	 */
	if (mode & (ISOLATE_CLEAN|ISOLATE_ASYNC_MIGRATE)) {
		/* All the caller can do on PageWriteback is block */
		/* 如果页正在回写，则不处理，直接返回 */
		if (PageWriteback(page))
			return ret;

		/* 此页为脏页，当匿名页被加入到swapcache时就会被标记为脏页 */
		if (PageDirty(page)) {
			struct address_space *mapping;

			/* ISOLATE_CLEAN means only clean pages */
			/* mode中要求只隔离干净的页，直接返回 */
			if (mode & ISOLATE_CLEAN)
				return ret;

			/*
			 * Only pages without mappings or that have a
			 * ->migratepage callback are possible to migrate
			 * without blocking
			 */
			/* 获取此页对应的address_space结构，结构指向结构里的migratepage操作函数
			 * 如果匿名页在swap cache里，migratepage函数为swap_aops->migrate_page
			 */
			mapping = page_mapping(page);
			if (mapping && !mapping->a_ops->migratepage)
				return ret;
		}
	}

	/* 要求隔离没有被映射的页，而此页已经被映射(page->_mapcount >= 0)，则返回错误 */
	if ((mode & ISOLATE_UNMAPPED) && page_mapped(page))
		return ret;

	/* 除非page->_count为0，否则page->_count++ */
	if (likely(get_page_unless_zero(page))) {
		/*
		 * Be careful not to clear PageLRU until after we're
		 * sure the page is not being freed elsewhere -- the
		 * page release code relies on it.
		 */
		/* 清除此页在lru的标志，因为此页算是已经从lru链表中拿出来了 */
		ClearPageLRU(page);
		ret = 0;
	}

	return ret;
}

/*
 * zone->lru_lock is heavily contended.  Some of the functions that
 * shrink the lists perform better by taking out a batch of pages
 * and working on them outside the LRU lock.
 *
 * For pagecache intensive workloads, this function is the hottest
 * spot in the kernel (apart from copy_*_user functions).
 *
 * Appropriate locks must be held before calling this function.
 *
 * @nr_to_scan:	The number of pages to look through on the list.
 * @lruvec:	The LRU vector to pull pages from.
 * @dst:	The temp list to put pages on to.
 * @nr_scanned:	The number of pages that were scanned.
 * @sc:		The scan_control struct for this reclaim session
 * @mode:	One of the LRU isolation modes
 * @lru:	LRU list id for isolating
 *
 * returns how many pages were moved onto *@dst.
 */
/* 从lruvec中的lru类型的lru链表获取页，从lru链表尾开始拿，然后放入dst链表中
 * 调用此函数前必须给lruvec上锁
 */
static unsigned long isolate_lru_pages(unsigned long nr_to_scan,
		struct lruvec *lruvec, struct list_head *dst,
		unsigned long *nr_scanned, struct scan_control *sc,
		isolate_mode_t mode, enum lru_list lru)
{
	/* 获取lruvec中lru类型的链表头 */
	struct list_head *src = &lruvec->lists[lru];
	/* 获取到的页的数量 */
	unsigned long nr_taken = 0;
	unsigned long scan;

	/* 扫描nr_to_scan次，默认是32 */
	for (scan = 0; scan < nr_to_scan && !list_empty(src); scan++) {
		struct page *page;
		int nr_pages;

		/* 获取lru链表中的最后一页(src->prev)，但并没有从lru中删除此page */
		page = lru_to_page(src);
		prefetchw_prev_lru_page(page, src, flags);

		/* 此页必须在lru中 */
		VM_BUG_ON_PAGE(!PageLRU(page), page);

		/* 将page从lru中拿出来，__isolate_lru_page更多的在page描述符做变量修改工作，描述此页已不在lru中，但没有实际从lru中拿出来，实际拿出来在后面的list_move
		 * 隔离出来的页会page->_count++
		 */
		switch (__isolate_lru_page(page, mode)) {
		case 0:
			/* 如果是透明大页，只有头page会被加入到lru，这里计算透明大页用了多少个page，如果是常规页则为1 */
			nr_pages = hpage_nr_pages(page);
			/* 更新memcg中lru链表中的页的数量(只有开启了memcg才会在memcg中更新) */
			mem_cgroup_update_lru_size(lruvec, lru, -nr_pages);
			/* 从当前lru链表中删除，加入到dst链表中 */
			list_move(&page->lru, dst);
			/* 更新获取到的页的数量 */
			nr_taken += nr_pages;
			break;

		case -EBUSY:
			/* else it is being freed elsewhere */
			/* 放回src这个lru链表中 */
			list_move(&page->lru, src);
			continue;

		default:
			BUG();
		}
	}

	/* 总共扫描的页数量 */
	*nr_scanned = scan;
	trace_mm_vmscan_lru_isolate(sc->order, nr_to_scan, scan,
				    nr_taken, mode, is_file_lru(lru));
	return nr_taken;
}

/**
 * isolate_lru_page - tries to isolate a page from its LRU list
 * @page: page to isolate from its LRU list
 *
 * Isolates a @page from an LRU list, clears PageLRU and adjusts the
 * vmstat statistic corresponding to whatever LRU list the page was on.
 *
 * Returns 0 if the page was removed from an LRU list.
 * Returns -EBUSY if the page was not on an LRU list.
 *
 * The returned page will have PageLRU() cleared.  If it was found on
 * the active list, it will have PageActive set.  If it was found on
 * the unevictable list, it will have the PageUnevictable bit set. That flag
 * may need to be cleared by the caller before letting the page go.
 *
 * The vmstat statistic corresponding to the list on which the page was
 * found will be decremented.
 *
 * Restrictions:
 * (1) Must be called with an elevated refcount on the page. This is a
 *     fundamentnal difference from isolate_lru_pages (which is called
 *     without a stable reference).
 * (2) the lru_lock must not be held.
 * (3) interrupts must be enabled.
 */
/* 将page从lru中拿出来 */
int isolate_lru_page(struct page *page)
{
	int ret = -EBUSY;

	/* 此页的引用计数必须大于0 */
	VM_BUG_ON_PAGE(!page_count(page), page);

	if (PageLRU(page)) {
		/* 页所在的管理区 */
		struct zone *zone = page_zone(page);
		struct lruvec *lruvec;

		spin_lock_irq(&zone->lru_lock);
		/* 根据管理区获取管理区的lru链表 */
		lruvec = mem_cgroup_page_lruvec(page, zone);
		if (PageLRU(page)) {
			/* 获取此页应该放置的lru链表的类型 */
			int lru = page_lru(page);
			/* 增加此页的引用计数 */
			get_page(page);
			/* 清除此页在lru的标志 */
			ClearPageLRU(page);
			/* 将此页从lru拿出来 */
			del_page_from_lru_list(page, lruvec, lru);
			ret = 0;
		}
		spin_unlock_irq(&zone->lru_lock);
	}
	return ret;
}

/*
 * A direct reclaimer may isolate SWAP_CLUSTER_MAX pages from the LRU list and
 * then get resheduled. When there are massive number of tasks doing page
 * allocation, such sleeping direct reclaimers may keep piling up on each CPU,
 * the LRU list will go small and be scanned faster than necessary, leading to
 * unnecessary swapping, thrashing and OOM.
 */
/* 如果隔离的页数量多于非活动的页数量，则是隔离太多页了 */
static int too_many_isolated(struct zone *zone, int file,
		struct scan_control *sc)
{
	unsigned long inactive, isolated;

	/* 如果是在kswapd内核线程中调用到此，则直接返回0 */
	if (current_is_kswapd())
		return 0;

	/* 如果不是针对整个zone，而是针对某个memcg的，也忽略 */
	if (!global_reclaim(sc))
		return 0;

	if (file) {
		inactive = zone_page_state(zone, NR_INACTIVE_FILE);
		isolated = zone_page_state(zone, NR_ISOLATED_FILE);
	} else {
		inactive = zone_page_state(zone, NR_INACTIVE_ANON);
		isolated = zone_page_state(zone, NR_ISOLATED_ANON);
	}

	/*
	 * GFP_NOIO/GFP_NOFS callers are allowed to isolate more pages, so they
	 * won't get blocked by normal direct-reclaimers, forming a circular
	 * deadlock.
	 */
	/* 如果gfp_mask中标记了GFP_NOIO/GFP_NOFS，这两个标记是允许阻塞等待，和允许进行IO操作，那则允许隔离更多的页 */
	if ((sc->gfp_mask & GFP_IOFS) == GFP_IOFS)
		inactive >>= 3;

	/* 如果隔离的页数量多于非活动的页数量，则是隔离太多页了 */
	return isolated > inactive;
}

/* 将page_list中的页放回到对应类型的非活动lru链表中 */
static noinline_for_stack void
putback_inactive_pages(struct lruvec *lruvec, struct list_head *page_list)
{
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	/* lruvec对应的zone */
	struct zone *zone = lruvec_zone(lruvec);
	/* 初始化一个叫做pages_to_free的链表头 */
	LIST_HEAD(pages_to_free);

	/*
	 * Put back any unfreeable pages.
	 */
	/* 如果page_list链表不为空 */
	while (!list_empty(page_list)) {
		/* 从page_list链表尾部中获取一个页 */
		struct page *page = lru_to_page(page_list);
		int lru;

		/* 页不应该处于lru中 */
		VM_BUG_ON_PAGE(PageLRU(page), page);
		/* 将此页从page_list中删除 */
		list_del(&page->lru);
		/* 如果此页是需要固定在内存中的 */
		if (unlikely(!page_evictable(page))) {
			spin_unlock_irq(&zone->lru_lock);
			/* 这里会通过PageUnevictable(page)判断出此页是unevictable的，将此页放回unevictable类型的lru链表中 
			 * 会page->_count--
			 */
			putback_lru_page(page);
			spin_lock_irq(&zone->lru_lock);
			continue;
		}

		lruvec = mem_cgroup_page_lruvec(page, zone);

		SetPageLRU(page);
		/* 获取页的类型，anon或者file */
		lru = page_lru(page);
		/* 将页加入到对应类型的lru链表头部 */
		add_page_to_lru_list(page, lruvec, lru);

		/* 如果此页是活动页，这是有可能的，最近此页在其他CPU或调度过程中被访问了 */
		if (is_active_lru(lru)) {
			/* 获取此页的类型，文件页或者匿名页 */
			int file = is_file_lru(lru);
			/* 此页代表的页数量，大页的情况下是多少个普通页，普通页的时候为1 */
			int numpages = hpage_nr_pages(page);
			/* 统计到lruvec的recent_rotated中 */
			reclaim_stat->recent_rotated[file] += numpages;
		}
		
		/* 对page->_count--，并判断是否为0，如果为0，说明此页没有被任何进程引用 */
		if (put_page_testzero(page)) {
			/* 清除此页的PG_lru标志，说明此页不在lru中 */
			__ClearPageLRU(page);
			/* 清除此页的PG_active标志，说明此页不是活动的 */
			__ClearPageActive(page);
			/* 将此页从lru链表中删除 */
			del_page_from_lru_list(page, lruvec, lru);

			/* 此页是hugetlbfs中的大页 */
			if (unlikely(PageCompound(page))) {
				spin_unlock_irq(&zone->lru_lock);
				mem_cgroup_uncharge(page);
				/* 调用大页的析构函数 */
				(*get_compound_page_dtor(page))(page);
				spin_lock_irq(&zone->lru_lock);
			} else
				/* 加入到pages_to_free链表，准备释放此页 */
				list_add(&page->lru, &pages_to_free);
		}
	}

	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	/* 将pages_to_free中的页都放入到page_list中 */
	list_splice(&pages_to_free, page_list);
}

/*
 * If a kernel thread (such as nfsd for loop-back mounts) services
 * a backing device by writing to the page cache it sets PF_LESS_THROTTLE.
 * In that case we should only throttle if the backing device it is
 * writing to is congested.  In other cases it is safe to throttle.
 */
static int current_may_throttle(void)
{
	return !(current->flags & PF_LESS_THROTTLE) ||
		current->backing_dev_info == NULL ||
		bdi_write_congested(current->backing_dev_info);
}

/*
 * shrink_inactive_list() is a helper for shrink_zone().  It returns the number
 * of reclaimed pages
 */
/* 对lruvec这个lru链表描述符中的lru类型的lru链表进行内存回收，这个lru类型一定是LRU_INACTIVE_ANON或者LRU_INACTIVE_FILE类型
 * nr_to_scan: 最多扫描多少个页框
 * lruvec: lru链表描述符，里面有5个lru链表
 * sc: 扫描控制结构
 * lru: 需要扫描的lru链表
 * 返回本次回收的页框数量
 */
static noinline_for_stack unsigned long
shrink_inactive_list(unsigned long nr_to_scan, struct lruvec *lruvec,
		     struct scan_control *sc, enum lru_list lru)
{
	LIST_HEAD(page_list);
	unsigned long nr_scanned;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_taken;
	unsigned long nr_dirty = 0;
	unsigned long nr_congested = 0;
	unsigned long nr_unqueued_dirty = 0;
	unsigned long nr_writeback = 0;
	unsigned long nr_immediate = 0;
	isolate_mode_t isolate_mode = 0;
	/* 此非活动lru是否为非活动文件页lru */
	int file = is_file_lru(lru);
	/* lru所属的zone */
	struct zone *zone = lruvec_zone(lruvec);
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;

	/* 如果隔离的页数量多于非活动的页数量，则是隔离太多页了，个人猜测这里是控制并发
	 * 当zone的NR_INACTIVE_FILE/ANON < NR_ISOLATED_ANON时，有一种情况是其他CPU也在对此zone进行内存回收，所以NR_ISOLATED_ANON比较高
	 */
	while (unlikely(too_many_isolated(zone, file, sc))) {
		/* 这里会休眠等待100ms，如果是并发进行内存回收，另一个CPU可能也在执行内存回收 */
		congestion_wait(BLK_RW_ASYNC, HZ/10);

		/* We are about to die and free our memory. Return now. */
		/* 当前进程被其他进程kill了，这里接受到了kill信号 */
		if (fatal_signal_pending(current))
			return SWAP_CLUSTER_MAX;
	}

	/* 将当前cpu的pagevec中的页放入到lru链表中 
	 * 而其他CPU的pagevec中的页则不会放回到lru链表中
	 * 这样做似乎是因为效率问题
	 */
	lru_add_drain();

	if (!sc->may_unmap)
		isolate_mode |= ISOLATE_UNMAPPED;
	if (!sc->may_writepage)
		isolate_mode |= ISOLATE_CLEAN;

	/* 对lru链表上锁 */
	spin_lock_irq(&zone->lru_lock);

	/* 从lruvec这个lru链表描述符的lru类型的lru链表中隔离最多nr_to_scan个页出来，隔离时是从lru链表尾部开始拿，然后放到page_list 
	 * 返回隔离了多少个此非活动lru链表的页框
	 */
	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &page_list,
				     &nr_scanned, sc, isolate_mode, lru);

	/* 更新zone中对应lru中页的数量 */
	__mod_zone_page_state(zone, NR_LRU_BASE + lru, -nr_taken);
	/* 此zone对应隔离的ANON/FILE页框数量 */
	__mod_zone_page_state(zone, NR_ISOLATED_ANON + file, nr_taken);

	/* 如果是针对整个zone的内存回收，而不是某个memcg的内存回收的情况 */
	if (global_reclaim(sc)) {
		/* 统计zone中扫描的页框总数 */
		__mod_zone_page_state(zone, NR_PAGES_SCANNED, nr_scanned);
		/* 如果是在kswapd内核线程中调用到此的，则扫描的页框数量统计到zone的PGSCAN_KSWAPD */
		if (current_is_kswapd())
			__count_zone_vm_events(PGSCAN_KSWAPD, zone, nr_scanned);
		else
			/* 否则扫描的数量统计到zone的PGSCAN_DIRECT */
			__count_zone_vm_events(PGSCAN_DIRECT, zone, nr_scanned);
	}
	/* 释放lru锁 */
	spin_unlock_irq(&zone->lru_lock);

	/* 隔离出来的页数量为0 */
	if (nr_taken == 0)
		return 0;

	/* 上面的代码已经将非活动lru链表中的一些页拿出来放到page_list中了，这里是对page_list中的页进行内存回收 
	 * 此函数的步骤:
	 * 1.此页是否在进行回写(两种情况会导致回写，之前进行内存回收时导致此页进行了回写；此页为脏页，系统自动将其回写)，这种情况同步回收和异步回收有不同的处理
	 * 2.此次回收时非强制进行回收，那要先判断此页能不能进行回收
	 * 		如果是匿名页，只要最近此页被进程访问过，则将此页移动到活动lru链表头部，否则回收
	 * 		如果是映射可执行文件的文件页，只要最近被进程访问过，就放到活动lru链表，否则回收
	 * 		如果是其他的文件页，如果最近被多个进程访问过，移动到活动lru链表，如果只被1个进程访问过，但是PG_referenced置位了，也放入活动lru链表，其他情况回收
	 * 3.如果遍历到的page为匿名页，但是又不处于swapcache中，这里会尝试将其加入到swapcache中并把页标记为脏页，这个swapcache作为swap缓冲区，是一个address_space
	 * 4.对所有映射了此页的进程的页表进行此页的unmap操作
	 * 5.如果页为脏页，则进行回写，分同步和异步，同步情况是回写完成才返回，异步情况是加入块层的写入队列，标记页的PG_writeback表示正在回写就返回，此页将会被放到非活动lru链表头部
	 * 6.检查页的PG_writeback标志，如果此标志位0，则说明此页的回写完成(两种情况: 1.同步回收 2.之前异步回收对此页进行的回写已完成)，则从此页对应的address_space中的基树移除此页的结点，加入到free_pages链表
	 *		对于PG_writeback标志位1的，将其重新加入到page_list链表，这个链表之后会将里面的页放回到非活动lru链表末尾，下次进行回收时，如果页回写完成了就会被释放
	 * 7.对free_pages链表的页释放
	 *
	 * page_list中返回时有可能还有页，这些页是要放到非活动lru链表末尾的页，而这些页当中，有些页是正在进行回收的回写，当这些回写完成后，系统再次进行内存回收时，这些页就会被释放
	 *		而有一些页是不满足回收情况的页
	 * nr_dirty: page_list中脏页的数量
	 * nr_unqueued_dirty: page_list中脏页但并没有正在回写的页的数量
	 * nr_congested: page_list中正在进行回写并且设备正忙的页的数量(这些页可能回写很慢)
	 * nr_writeback: page_list中正在进行回写但不是在回收的页框数量
	 * nr_immediate: page_list中正在进行回写的回收页框数量
	 * 返回本次回收的页框数量
	 */
	nr_reclaimed = shrink_page_list(&page_list, zone, sc, TTU_UNMAP,
				&nr_dirty, &nr_unqueued_dirty, &nr_congested,
				&nr_writeback, &nr_immediate,
				false);

	/* 对lru上锁 */
	spin_lock_irq(&zone->lru_lock);

	/* 更新reclaim_stat中的recent_scanned */
	reclaim_stat->recent_scanned[file] += nr_taken;

	/* 如果是针对整个zone，而不是某个memcg的情况 */
	if (global_reclaim(sc)) {
		/* 如果是在kswakpd内核线程中 */
		if (current_is_kswapd())
			/* 更新到zone的PGSTEAL_KSWAPD */
			__count_zone_vm_events(PGSTEAL_KSWAPD, zone,
					       nr_reclaimed);
		else
			/* 不是在kswapd内核线程中，更新到PGSTEAL_DIRECT */
			__count_zone_vm_events(PGSTEAL_DIRECT, zone,
					       nr_reclaimed);
	}

	/* 
	 * 将page_list中剩余的页放回它对应的lru链表中，这里的页有三种情况:
	 * 1.最近被访问了，放到活动lru链表头部
	 * 2.此页需要锁在内存中，加入到unevictablelru链表
	 * 3.此页为非活动页，移动到非活动lru链表头部
	 * 当页正在进行回写回收，当回写完成后，通过判断页的PG_reclaim可知此页正在回收，会把页移动到非活动lru链表末尾，具体见end_page_writeback()函数
	 * 加入lru的页page->_count--
	 * 因为隔离出来时page->_count++，而在lru中是不需要对page->_count++的
	 */
	putback_inactive_pages(lruvec, &page_list);

	/* 更新此zone对应隔离的ANON/FILE页框数量，这里减掉了nr_taken，与此函数之前相对应 */
	__mod_zone_page_state(zone, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&zone->lru_lock);

	mem_cgroup_uncharge_list(&page_list);
	/* 释放page_list中剩余的页到伙伴系统中的每CPU页高速缓存中，以冷页处理 
	 * 这里剩余的就是page->_count == 0的页
	 */
	free_hot_cold_page_list(&page_list, true);

	/*
	 * If reclaim is isolating dirty pages under writeback, it implies
	 * that the long-lived page allocation rate is exceeding the page
	 * laundering rate. Either the global limits are not being effective
	 * at throttling processes due to the page distribution throughout
	 * zones or there is heavy usage of a slow backing device. The
	 * only option is to throttle from reclaim context which is not ideal
	 * as there is no guarantee the dirtying process is throttled in the
	 * same way balance_dirty_pages() manages.
	 *
	 * Once a zone is flagged ZONE_WRITEBACK, kswapd will count the number
	 * of pages under pages flagged for immediate reclaim and stall if any
	 * are encountered in the nr_immediate check below.
	 */
	/* 隔离出来的页都在进行回写(但不是回收造成的回写) */
	if (nr_writeback && nr_writeback == nr_taken)
		/* 标记ZONE的ZONE_WRITEBACK，标记此zone许多页在回写 */
		set_bit(ZONE_WRITEBACK, &zone->flags);

	/*
	 * memcg will stall in page writeback so only consider forcibly
	 * stalling for global reclaim
	 */
	/* 本次内存回收是针对整个zone的，这里面主要对zone的flags做一些标记 */
	if (global_reclaim(sc)) {
		/*
		 * Tag a zone as congested if all the dirty pages scanned were
		 * backed by a congested BDI and wait_iff_congested will stall.
		 */
		if (nr_dirty && nr_dirty == nr_congested)
			set_bit(ZONE_CONGESTED, &zone->flags);

		/*
		 * If dirty pages are scanned that are not queued for IO, it
		 * implies that flushers are not keeping up. In this case, flag
		 * the zone ZONE_DIRTY and kswapd will start writing pages from
		 * reclaim context.
		 */
		if (nr_unqueued_dirty == nr_taken)
			set_bit(ZONE_DIRTY, &zone->flags);

		/*
		 * If kswapd scans pages marked marked for immediate
		 * reclaim and under writeback (nr_immediate), it implies
		 * that pages are cycling through the LRU faster than
		 * they are written so also forcibly stall.
		 */
		/* 有一些页是因为回收导致它们在回写，则等待一下设备 */
		if (nr_immediate && current_may_throttle())
			congestion_wait(BLK_RW_ASYNC, HZ/10);
	}

	/*
	 * Stall direct reclaim for IO completions if underlying BDIs or zone
	 * is congested. Allow kswapd to continue until it starts encountering
	 * unqueued dirty pages or cycling through the LRU too quickly.
	 */
	/* 非kswapd的情况下，如果现在设备回写压力较大 */
	if (!sc->hibernation_mode && !current_is_kswapd() &&
	    current_may_throttle())
	    /* 等待一下设备 */
		wait_iff_congested(zone, BLK_RW_ASYNC, HZ/10);

	trace_mm_vmscan_lru_shrink_inactive(zone->zone_pgdat->node_id,
		zone_idx(zone),
		nr_scanned, nr_reclaimed,
		sc->priority,
		trace_shrink_flags(file));
	return nr_reclaimed;
}

/*
 * This moves pages from the active list to the inactive list.
 *
 * We move them the other way if the page is referenced by one or more
 * processes, from rmap.
 *
 * If the pages are mostly unmapped, the processing is fast and it is
 * appropriate to hold zone->lru_lock across the whole operation.  But if
 * the pages are mapped, the processing is slow (page_referenced()) so we
 * should drop zone->lru_lock around each page.  It's impossible to balance
 * this, so instead we remove the pages from the LRU while processing them.
 * It is safe to rely on PG_active against the non-LRU pages in here because
 * nobody will play with that bit on a non-LRU page.
 *
 * The downside is that we have to touch page->_count against each page.
 * But we had to alter page->flags anyway.
 */

/* 将list链表中的页放入到lruvec->lists[lru]链表中，不需要放入的页放到pages_to_free链表中 */
static void move_active_pages_to_lru(struct lruvec *lruvec,
				     struct list_head *list,
				     struct list_head *pages_to_free,
				     enum lru_list lru)
{
	/* 根据lruvec获取对应的zone管理区 */
	struct zone *zone = lruvec_zone(lruvec);
	unsigned long pgmoved = 0;
	struct page *page;
	int nr_pages;

	/* 遍历list中每一个页描述符 */
	while (!list_empty(list)) {
		/* 从list末尾获取一个页描述符 */
		page = lru_to_page(list);
		/* 获取对应的lruvec，是否会有情况导致这里获取的lruvec与传入的lruvec不一致?一般情况是一致的 */
		lruvec = mem_cgroup_page_lruvec(page, zone);

		/* 如果page在LRU链表上，则提示一个BUG，这时page应该在list上，而list不应该是lru中的一个链表 */
		VM_BUG_ON_PAGE(PageLRU(page), page);
		/* 设置page标志其在lru上 */
		SetPageLRU(page);

		/* 如果页描述符描述的是一个大页，获取其对应的多少个正常页，比如2M大页，那正常页则是512个 */
		nr_pages = hpage_nr_pages(page);
		/* 更新链表中lruvec->lists[lru]中的计数 */
		mem_cgroup_update_lru_size(lruvec, lru, nr_pages);
		/* 将页描述符移动到lruvec->lists[lru]上 */
		list_move(&page->lru, &lruvec->lists[lru]);
		/* 计数器 */
		pgmoved += nr_pages;

		/* 这里对页的引用次数 page->_count--，然后判断是否为0
		 * 如果此页的引用次数 page->_count--后等于0，说明只有隔离的时候对其page->_count进行了++，也就是说此页已经没有其他进程或模块引用了
		 * 这种情况将此页放到page_to_free中，之后会准备释放，因为此页在lru中，所以引用次数为1说明没有页表引用了此页
		 * 由于调用此函数前，此页基本是先被隔离到一个链表里的，而隔离的时候会对此page->_count++，这里正好成对
		 */
		if (put_page_testzero(page)) {
			/* 清除在lru中的标志 */
			__ClearPageLRU(page);
			/* 清除此页是活动页的标志 */
			__ClearPageActive(page);
			/* 将其从lru中移除，并会减少统计 */
			del_page_from_lru_list(page, lruvec, lru);

			/* 如果是大页 */
			if (unlikely(PageCompound(page))) {
				spin_unlock_irq(&zone->lru_lock);
				mem_cgroup_uncharge(page);
				(*get_compound_page_dtor(page))(page);
				spin_lock_irq(&zone->lru_lock);
			} else
				/* 不是大页的情况，加入到pages_to_free链表中 */
				list_add(&page->lru, pages_to_free);
		}
	}
	/* 统计，这里注意，当一些页又从lru中移除的时候，并没有减少pgmoved计数，因为调用del_page_from_lru_list时已经先减掉了移除的页 */
	__mod_zone_page_state(zone, NR_LRU_BASE + lru, pgmoved);
	/* 如果目标lru并不是activate的lru，这里也要统计 */
	if (!is_active_lru(lru))
		__count_vm_events(PGDEACTIVATE, pgmoved);
}

/*
 * 从lruvec中的lru类型的链表中获取一些页，并移动到非活动lru链表头部，注意此函数会以lru参数为类型，比如lru参数为LRU_ACTIVE_ANON，那只会处理ANON类型的页，不会处理FILE类型的页
 * 只有代码段的页最近被访问了，会将其加入到活动lru链表头部，其他页即使最近被访问了，也移动到非活动lru链表
 * 从lruvec中的lru类型的链表中拿出一些页之后，会判断这些页的去处，然后将page->_count = 1的页进行释放，因为说明此页只有隔离的时候对其page->_count进行了++，已经没有进程或模块引用此页
 * 将其释放到伙伴系统的每CPU高速缓存中
 * nr_to_scan: 默认是32，扫描次数，如果扫描的全是普通页，那最多扫描32个页，如果全是大页，最多扫描(大页/普通页)*32个页
 * lruvec: 需要扫描的lru链表(里面包括一个zone中所有类型的lru链表)
 * sc: 扫描控制结构
 * lru: 需要扫描的类型，是active_file或者active_anon的lru链表
 */
static void shrink_active_list(unsigned long nr_to_scan,
			       struct lruvec *lruvec,
			       struct scan_control *sc,
			       enum lru_list lru)
{
	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long vm_flags;
	/* 从lru中获取到的页存放在这，到最后这里面还有剩余的页的话，就把它们释放回伙伴系统 */
	LIST_HEAD(l_hold);	/* The pages which were snipped off */
	/* 移动到活动lru链表头部的页的链表 */
	LIST_HEAD(l_active);
	/* 将要移动到非活动lru链表的页放在这 */
	LIST_HEAD(l_inactive);
	struct page *page;
	/* lruvec的统计结构 */
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	unsigned long nr_rotated = 0;
	isolate_mode_t isolate_mode = 0;
	/* lru是否属于LRU_INACTIVE_FILE或者LRU_ACTIVE_FILE */
	int file = is_file_lru(lru);
	/* lruvec所属的zone */
	struct zone *zone = lruvec_zone(lruvec);

	/* 将当前CPU的多个pagevec中的页都放入lru链表中 */
	lru_add_drain();

	/* 从kswapd调用过来的情况下，sc->may_unmap为1
	 * 直接内存回收的情况，sc->may_unmap为1
	 * 快速内存回收的情况，sc->may_unmap与zone_reclaim_mode有关
	 */
	if (!sc->may_unmap)
		isolate_mode |= ISOLATE_UNMAPPED;

	
	/* 从kswapd调用过来的情况下，sc->may_writepage与latptop_mode有关
	 * 直接内存回收的情况，sc->may_writepage与latptop_mode有关
	 * 快速内存回收的情况，sc->may_writepage与zone_reclaim_mode有关
	 */
	if (!sc->may_writepage)
		isolate_mode |= ISOLATE_CLEAN;

	/* 对zone的lru_lock上锁 */
	spin_lock_irq(&zone->lru_lock);

	/* 从lruvec中lru类型链表的尾部拿出一些页隔离出来，放入到l_hold中，lru类型一般是LRU_ACTIVE_ANON或LRU_ACTIVE_FILE
	 * 也就是从活动的lru链表中隔离出一些页，从活动lru链表的尾部依次拿出
	 * 当sc->may_unmap为0时，则不会将有进程映射的页隔离出来
	 * 当sc->may_writepage为0时，则不会将脏页和正在回写的页隔离出来
	 * 隔离出来的页会page->_count++
	 * nr_taken保存拿出的页的数量
	 */
	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &l_hold,
				     &nr_scanned, sc, isolate_mode, lru);
	if (global_reclaim(sc))
		__mod_zone_page_state(zone, NR_PAGES_SCANNED, nr_scanned);

	reclaim_stat->recent_scanned[file] += nr_taken;

	/* 做统计 */
	__count_zone_vm_events(PGREFILL, zone, nr_scanned);
	__mod_zone_page_state(zone, NR_LRU_BASE + lru, -nr_taken);
	__mod_zone_page_state(zone, NR_ISOLATED_ANON + file, nr_taken);
	/* 释放lru链表锁 */
	spin_unlock_irq(&zone->lru_lock);

	/* 将l_hold中的页一个一个处理 */
	while (!list_empty(&l_hold)) {
		/* 是否需要调度，需要则调度 */
		cond_resched();
		/* 将页从l_hold中拿出来 */
		page = lru_to_page(&l_hold);
		list_del(&page->lru);

		/* 如果页是unevictable(不可回收)的，则放回到LRU_UNEVICTABLE这个lru链表中，这个lru链表中的页不能被交换出去 */
		if (unlikely(!page_evictable(page))) {
			/* 放回到page所应该属于的lru链表中 
			 * 而这里实际上是将页放到zone的LRU_UNEVICTABLE链表中
			 */
			putback_lru_page(page);
			continue;
		}

		/* buffer_heads的数量超过了结点允许的最大值的情况 */
		if (unlikely(buffer_heads_over_limit)) {
			/* 文件页才有的page才有PAGE_FLAGS_PRIVATE标志 */
			if (page_has_private(page) && trylock_page(page)) {
				if (page_has_private(page))
					/* 释放此文件页所拥有的buffer_head链表中的buffer_head，并且page->_count-- */
					try_to_release_page(page, 0);
				unlock_page(page);
			}
		}

		/* 检查此页面最近是否有被访问过，通过映射了此页的页表项的Accessed进行检查，并且会清除页表项的Accessed标志
		 * 如果此页最近被访问过，则进入if
		 */
		if (page_referenced(page, 0, sc->target_mem_cgroup,
				    &vm_flags)) {
			/* 如果是大页，则记录一共多少个页，如果是普通页，则是1 */
			nr_rotated += hpage_nr_pages(page);
			/*
			 * Identify referenced, file-backed active pages and
			 * give them one more trip around the active list. So
			 * that executable code get better chances to stay in
			 * memory under moderate memory pressure.  Anon pages
			 * are not likely to be evicted by use-once streaming
			 * IO, plus JVM can create lots of anon VM_EXEC pages,
			 * so we ignore them here.
			 */
			/* 如果此页映射的是代码段，则将其放到l_active链表中，此链表之后会把页放入页对应的活动lru链表中
			 * 可以看出对于代码段的页，还是比较倾向于将它们放到活动文件页lru链表的
			 * 当代码段没被访问过时，也是有可能换到非活动文件页lru链表的
			 */
			if ((vm_flags & VM_EXEC) && page_is_file_cache(page)) {
				list_add(&page->lru, &l_active);
				continue;
			}
		}
		/* 将页放到l_inactive链表中
		 * 只有最近访问过的代码段的页不会被放入，其他即使被访问过了，也会被放入l_inactive
		 */
		ClearPageActive(page);	/* we are de-activating */
		list_add(&page->lru, &l_inactive);
	}

	/*
	 * Move pages back to the lru list.
	 */
	spin_lock_irq(&zone->lru_lock);
	/*
	 * Count referenced pages from currently used mappings as rotated,
	 * even though only some of them are actually re-activated.  This
	 * helps balance scan pressure between file and anonymous pages in
	 * get_scan_count.
	 */
	/* 记录的是最近有被访问过的页的数量，之后这些页被返回到active链表 */
	reclaim_stat->recent_rotated[file] += nr_rotated;

	/* 将l_active链表中的页移动到lruvec->lists[lru]中，这里是将active的页移动到active的lru链表头部 */
	move_active_pages_to_lru(lruvec, &l_active, &l_hold, lru);
	/* 将l_inactive链表中的页移动到lruvec->lists[lru - LRU_ACITVE]中，这里是将active的页移动到inactive的lru头部 */
	move_active_pages_to_lru(lruvec, &l_inactive, &l_hold, lru - LRU_ACTIVE);
	__mod_zone_page_state(zone, NR_ISOLATED_ANON + file, -nr_taken);
	spin_unlock_irq(&zone->lru_lock);

	mem_cgroup_uncharge_list(&l_hold);
	/* 剩下的页的处理，剩下的都是page->_count为0的页，作为冷页放回到伙伴系统的每CPU单页框高速缓存中 */
	free_hot_cold_page_list(&l_hold, true);
}

#ifdef CONFIG_SWAP
static int inactive_anon_is_low_global(struct zone *zone)
{
	unsigned long active, inactive;

	active = zone_page_state(zone, NR_ACTIVE_ANON);
	inactive = zone_page_state(zone, NR_INACTIVE_ANON);

	if (inactive * zone->inactive_ratio < active)
		return 1;

	return 0;
}

/**
 * inactive_anon_is_low - check if anonymous pages need to be deactivated
 * @lruvec: LRU vector to check
 *
 * Returns true if the zone does not have enough inactive anon pages,
 * meaning some active anon pages need to be deactivated.
 */
/* 判断非活动匿名页是否处于low水平 */
static int inactive_anon_is_low(struct lruvec *lruvec)
{
	/*
	 * If we don't have swap space, anonymous page deactivation
	 * is pointless.
	 */
	/* 如果没有swap分区，则total_swap_pages为0，这种情况是不处理匿名页的 */
	if (!total_swap_pages)
		return 0;

	/* 会检查inactive的匿名页数量是否低于整个zone的匿名页数量的25% */
	/* 使用memcg的情况 */
	if (!mem_cgroup_disabled())
		return mem_cgroup_inactive_anon_is_low(lruvec);

	/* 没有使用memcg的情况 */
	return inactive_anon_is_low_global(lruvec_zone(lruvec));
}
#else
static inline int inactive_anon_is_low(struct lruvec *lruvec)
{
	return 0;
}
#endif

/**
 * inactive_file_is_low - check if file pages need to be deactivated
 * @lruvec: LRU vector to check
 *
 * When the system is doing streaming IO, memory pressure here
 * ensures that active file pages get deactivated, until more
 * than half of the file pages are on the inactive list.
 *
 * Once we get to that situation, protect the system's working
 * set from being evicted by disabling active file page aging.
 *
 * This uses a different ratio than the anonymous pages, because
 * the page cache uses a use-once replacement algorithm.
 */
/* 非活动文件页数量是否太少 */
static int inactive_file_is_low(struct lruvec *lruvec)
{
	unsigned long inactive;
	unsigned long active;

	/* 非活动文件页数量 */
	inactive = get_lru_size(lruvec, LRU_INACTIVE_FILE);
	/* 活动文件页数量 */
	active = get_lru_size(lruvec, LRU_ACTIVE_FILE);

	/* 活动文件页数量多于非活动文件页数量，那就说明非活动文件页数量太少 */
	return active > inactive;
}

static int inactive_list_is_low(struct lruvec *lruvec, enum lru_list lru)
{
	if (is_file_lru(lru))
		return inactive_file_is_low(lruvec);
	else
		return inactive_anon_is_low(lruvec);
}

/*
 * 对lru链表进行处理
 * lru: lru链表的类型
 * nr_to_scan: 需要扫描的页框数量，此值 <= 32，当链表长度不足32时，就为链表长度
 * lruvec: lru链表描述符，与lru参数结合就得出待处理的lru链表
 * sc: 扫描控制结构
 */
static unsigned long shrink_list(enum lru_list lru, unsigned long nr_to_scan,
				 struct lruvec *lruvec, struct scan_control *sc)
{
	/* 如果lru类型是活动lru(包括活动匿名页lru和活动文件页lru) */
	if (is_active_lru(lru)) {
		/* 如果此活动lru对应的非活动lru链表中维护的页框数量太少，则会从活动lru链表中移动一些到对应非活动lru链表中 
		 * 这里需要注意，文件页和匿名页的非活动lru链表中是否少计算方式是不同的
		 * 匿名页的话，有一个经验值表示大概多少匿名页保存到非活动匿名页lru链表
		 * 文件页的话，大概非活动文件页数量要大于活动文件页
		 * 而如果遇到page->_count == 0的页，则会将它们释放到每CPU页框高速缓存中
		 */
		if (inactive_list_is_low(lruvec, lru))
			/* 从活动lru中移动一些页框到非活动lru中，移动nr_to_scan个，nr_to_scan <= 32，从活动lru链表末尾拿出页框移动到非活动lru链表头 
			 * 只有代码段的页最近被访问了，会将其加入到活动lru链表头部，其他页即使最近被访问了，也移动到非活动lru链表
			 */
			shrink_active_list(nr_to_scan, lruvec, sc, lru);
		return 0;
	}

	/* 如果lru类似是非活动lru，那么会对此lru类型的lru链表中的页框进行回收 */
	return shrink_inactive_list(nr_to_scan, lruvec, sc, lru);
}

enum scan_balance {
	SCAN_EQUAL,
	SCAN_FRACT,
	SCAN_ANON,
	SCAN_FILE,
};

/*
 * Determine how aggressively the anon and file LRU lists should be
 * scanned.  The relative value of each set of LRU lists is determined
 * by looking at the fraction of the pages scanned we did rotate back
 * onto the active list instead of evict.
 *
 * nr[0] = anon inactive pages to scan; nr[1] = anon active pages to scan
 * nr[2] = file inactive pages to scan; nr[3] = file active pages to scan
 */

/* 对这个lru链表描述符中的每个lru链表，计算它们本次扫描应该扫描的页框数量
 * 保存在nr中
 */
static void get_scan_count(struct lruvec *lruvec, int swappiness,
			   struct scan_control *sc, unsigned long *nr)
{
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	u64 fraction[2];
	u64 denominator = 0;	/* gcc */
	/* 获取lruvec所在的zone */
	struct zone *zone = lruvec_zone(lruvec);
	unsigned long anon_prio, file_prio;
	enum scan_balance scan_balance;
	unsigned long anon, file;
	bool force_scan = false;
	unsigned long ap, fp;
	enum lru_list lru;
	bool some_scanned;
	int pass;

	/*
	 * If the zone or memcg is small, nr[l] can be 0.  This
	 * results in no scanning on this priority and a potential
	 * priority drop.  Global direct reclaim can go to the next
	 * zone and tends to have no problems. Global kswapd is for
	 * zone balancing and it needs to scan a minimum amount. When
	 * reclaiming for a memcg, a priority drop can cause high
	 * latencies, so it's better to scan a minimum amount there as
	 * well.
	 */
	/* 如果当前是kswapd内核进程，并且此zone不能够进行内存回收 */
	if (current_is_kswapd() && !zone_reclaimable(zone))
		/* 设置强制进行扫描 */
		force_scan = true;
	/* 如果不是针对整个zone进行内存回收 */
	if (!global_reclaim(sc))
		/* 设置强制进行扫描 */
		force_scan = true;

	/* If we have no swap space, do not bother scanning anon pages. */
	/* 如果扫描控制结构设置了不进行swap交换或者没有空闲的swap空间 */
	if (!sc->may_swap || (get_nr_swap_pages() <= 0)) {
		/* 标记只扫描文件页lru */
		scan_balance = SCAN_FILE;
		/* 跳转到out */
		goto out;
	}

	/*
	 * Global reclaim will swap to prevent OOM even with no
	 * swappiness, but memcg users want to use this knob to
	 * disable swapping for individual groups completely when
	 * using the memory controller's swap limit feature would be
	 * too expensive.
	 */
	/* 如果扫描控制结构是针对某个memcg进行回收，并且swappiness等于0 */
	if (!global_reclaim(sc) && !swappiness) {
		/* 标记只扫描文件页 */
		scan_balance = SCAN_FILE;
		/* 跳转到out */
		goto out;
	}

	/*
	 * Do not apply any pressure balancing cleverness when the
	 * system is close to OOM, scan both anon and file equally
	 * (unless the swappiness setting disagrees with swapping).
	 */
	/* 如果sc->priority == 0，并且swappiness不为0 
	 * sc->priority代表一次扫描(总页框 >> sc->priority)个页框，这个总页框可以是一个memcg在一个zone的总共的页框数，也可以是一个zone的页框数，也可以是一个lru链表长度，看调用者怎么用
	 */
	if (!sc->priority && swappiness) {
		/* 文件页匿名页都扫描 */
		scan_balance = SCAN_EQUAL;
		/* 跳转到out */
		goto out;
	}

	/*
	 * Prevent the reclaimer from falling into the cache trap: as
	 * cache pages start out inactive, every cache fault will tip
	 * the scan balance towards the file LRU.  And as the file LRU
	 * shrinks, so does the window for rotation from references.
	 * This means we have a runaway feedback loop where a tiny
	 * thrashing file LRU becomes infinitely more attractive than
	 * anon pages.  Try to detect this based on file LRU size.
	 */
	/* 针对zone进行全局回收的情况 */
	if (global_reclaim(sc)) {
		unsigned long zonefile;
		unsigned long zonefree;

		/* zone中空闲页框数量 */
		zonefree = zone_page_state(zone, NR_FREE_PAGES);
		/* zone中所有的文件页数量 */
		zonefile = zone_page_state(zone, NR_ACTIVE_FILE) +
			   zone_page_state(zone, NR_INACTIVE_FILE);

		/* 如果所有文件页加上空闲页框数量都小于zone的高阀值 
		 * 说明所有文件页都释放了都不能达到高阀值，页需要对匿名页进行扫描
		 */
		if (unlikely(zonefile + zonefree <= high_wmark_pages(zone))) {
			/* 设置对匿名页进行扫描 */
			scan_balance = SCAN_ANON;
			/* 跳转到out */
			goto out;
		}
	}

	/*
	 * There is enough inactive page cache, do not reclaim
	 * anything from the anonymous working set right now.
	 */
	/* 非活动文件页lru链表长于活动文件页lru链表 */
	if (!inactive_file_is_low(lruvec)) {
		/* 则只扫描文件页 */
		scan_balance = SCAN_FILE;
		goto out;
	}

	/* 上面情况都没有执行到，就使用公式去计算本次扫描此lru链表的匿名页和文件页的数量 */
	scan_balance = SCAN_FRACT;

	/*
	 * With swappiness at 100, anonymous and file have the same priority.
	 * This scanning priority is essentially the inverse of IO cost.
	 */
	/* 当swappiness为100时，扫描匿名页的优先级和扫描文件页的优先级相等 */
	/* 扫描匿名页的优先级 */
	anon_prio = swappiness;
	/* 扫描文件页的优先级，是 200 - 扫描匿名页优先级 */
	file_prio = 200 - anon_prio;

	/*
	 * OK, so we have swap space and a fair amount of page cache
	 * pages.  We use the recently rotated / recently scanned
	 * ratios to determine how valuable each cache is.
	 *
	 * Because workloads change over time (and to avoid overflow)
	 * we keep these statistics as a floating average, which ends
	 * up weighing recent references more than old ones.
	 *
	 * anon in [0], file in [1]
	 */

	/* 匿名页数量 */
	anon  = get_lru_size(lruvec, LRU_ACTIVE_ANON) +
		get_lru_size(lruvec, LRU_INACTIVE_ANON);
	/* 文件页数量 */
	file  = get_lru_size(lruvec, LRU_ACTIVE_FILE) +
		get_lru_size(lruvec, LRU_INACTIVE_FILE);

	spin_lock_irq(&zone->lru_lock);
	/* 如果此lru链表描述符中最近扫描过的匿名页数量超过了lru中所有匿名页的数量的四分之一 */
	if (unlikely(reclaim_stat->recent_scanned[0] > anon / 4)) {
		/* 统计最近扫描过的匿名页数量减半 */
		reclaim_stat->recent_scanned[0] /= 2;
		/* 统计最近加入匿名页活动链表的匿名页数量减半 */
		reclaim_stat->recent_rotated[0] /= 2;
	}
	
	/* 如果此lru链表描述符中最近扫描过的匿名页数量超过了lru中所有匿名页的数量的四分之一 */
	if (unlikely(reclaim_stat->recent_scanned[1] > file / 4)) {
		/* 统计最近扫描过的文件页数量减半 */
		reclaim_stat->recent_scanned[1] /= 2;
		/* 统计最近加入文件页活动链表的文件页数量减半 */
		reclaim_stat->recent_rotated[1] /= 2;
	}

	/*
	 * The amount of pressure on anon vs file pages is inversely
	 * proportional to the fraction of recently scanned pages on
	 * each list that were recently referenced and in active use.
	 */
	/* 计算影响扫描匿名页长度的因子 */
	ap = anon_prio * (reclaim_stat->recent_scanned[0] + 1);
	ap /= reclaim_stat->recent_rotated[0] + 1;
	/* 计算影响扫描文件页长度的因子 */
	fp = file_prio * (reclaim_stat->recent_scanned[1] + 1);
	fp /= reclaim_stat->recent_rotated[1] + 1;
	spin_unlock_irq(&zone->lru_lock);

	/* 两个因子保存在这 */
	fraction[0] = ap;
	fraction[1] = fp;
	denominator = ap + fp + 1;
out:
	some_scanned = false;
	/* Only use force_scan on second pass. */
	/* 这里会循环两次
	 * 第一次循环，如果所有的lru链表的扫描长度都为0，则进行第二次扫描，第二次扫描会设置一个最小的扫描长度，要么是lru链表长度要么就是SWAP_CLUSTER_MAX(32)
	 */
	for (pass = 0; !some_scanned && pass < 2; pass++) {
		/* 以这个顺序遍历LRU，LRU_INACTIVE_ANON，LRU_ACTIVE_ANON，LRU_INACTIVE_FILE，LRU_ACTIVE_FILE */
		for_each_evictable_lru(lru) {
			/* 是否为文件页的lru */
			int file = is_file_lru(lru);
			unsigned long size;
			unsigned long scan;

			/* 获取此lru长度 */
			size = get_lru_size(lruvec, lru);
			/* 计算对此lru的扫描长度，与扫描控制结构中的优先级有关，优先级越小，扫描得越多 */
			scan = size >> sc->priority;

			/* 如果对此lru的扫描长度是0，那么在第二轮的时候，则会设置一个最小的扫描长度 */
			if (!scan && pass && force_scan)
				/* 最小的扫描长度要么是此lru链表长度，要么是SWAP_CLUSTER_MAX(32) */
				scan = min(size, SWAP_CLUSTER_MAX);

			switch (scan_balance) {
			/* 如果sc->priority == 0并且swappiness不为0时，会是这种情况，将lru链表中所有页都进行一次扫描 */
			case SCAN_EQUAL:
				/* Scan lists relative to size */
				break;
			/* 其他情况都不成立，则用此情况 */
			case SCAN_FRACT:
				/*
				 * Scan types proportional to swappiness and
				 * their relative recent reclaim efficiency.
				 */
				/* 计算出此lru应该扫描的页框数量 */
				scan = div64_u64(scan * fraction[file],
							denominator);
				break;
				
			/* 如果扫描控制结构设置了不进行swap交换或者没有空闲的swap空间 */
			/* 如果扫描控制结构是针对某个memcg进行回收，并且swappiness等于0 */
			/* 非活动文件页lru链表长于活动文件页lru链表 */
			/* 上面这三种情况只对文件页进行扫描 */
			case SCAN_FILE:
			/* 当针对整个zone进行内存回收时，此zone的所有文件页都释放了都不能达到高阀值，那就只对匿名页进行扫描
		 	 */
			case SCAN_ANON:
				/* Scan one type exclusively */
				/* 标记了SCAN_FILE说明只扫描文件页，而SCAN_ANON为只扫描匿名页 
				 */
				if ((scan_balance == SCAN_FILE) != file)
					scan = 0;
				break;
			default:
				/* Look ma, no brain */
				BUG();
			}
			/* 保存此lru应该扫描的页框数量 */
			nr[lru] = scan;
			/*
			 * Skip the second pass and don't force_scan,
			 * if we found something to scan.
			 */
			/* 用于判断整个lru链表描述符中的所有lru都计算过后，是否总的扫描数量还是0 */
			some_scanned |= !!scan;
		}
	}
}

/*
 * This is a basic per-zone page freer.  Used by both kswapd and direct reclaim.
 */
/* 对lru链表描述符lruvec中的lru链表进行内存回收，此lruvec有可能属于一个memcg，也可能是属于一个zone 
 * lruvec: lru链表描述符，里面有5个lru链表，活动/非活动匿名页lru链表，活动/非活动文件页lru链表，禁止换出页链表
 * swappiness: 扫描匿名页的亲和力，其值越低，就扫描越少的匿名页，当为0时，基本不会扫描匿名页lru链表，除非针对整个zone进行内存回收时，此zone的所有文件页都释放了都不能达到高阀值，那就只对匿名页进行扫描
 * sc: 扫描控制结构
 */
static void shrink_lruvec(struct lruvec *lruvec, int swappiness,
			  struct scan_control *sc)
{
	unsigned long nr[NR_LRU_LISTS];
	unsigned long targets[NR_LRU_LISTS];
	unsigned long nr_to_scan;
	enum lru_list lru;
	unsigned long nr_reclaimed = 0;
	/* 需要回收的页框数量 */
	unsigned long nr_to_reclaim = sc->nr_to_reclaim;
	struct blk_plug plug;
	bool scan_adjusted;

	/* 对这个lru链表描述符中的每个lru链表，计算它们本次扫描应该扫描的页框数量 
	 * 计算好的每个lru链表需要扫描的页框数量保存在nr中
	 * 每个lru链表需要扫描多少与sc->priority有关，sc->priority越小，那么扫描得越多
	 */
	get_scan_count(lruvec, swappiness, sc, nr);

	/* Record the original scan target for proportional adjustments later */
	/* 将nr的数据复制到targets中 */
	memcpy(targets, nr, sizeof(nr));

	/*
	 * Global reclaiming within direct reclaim at DEF_PRIORITY is a normal
	 * event that can occur when there is little memory pressure e.g.
	 * multiple streaming readers/writers. Hence, we do not abort scanning
	 * when the requested number of pages are reclaimed when scanning at
	 * DEF_PRIORITY on the assumption that the fact we are direct
	 * reclaiming implies that kswapd is not keeping up and it is best to
	 * do a batch of work at once. For memcg reclaim one check is made to
	 * abort proportional reclaim if either the file or anon lru has already
	 * dropped to zero at the first pass.
	 */
	/* 是否将nr[]中的数量页数都扫描完才停止
	 * 如果是针对整个zone进行扫描，并且不是在kswapd内核线程中调用的，优先级为默认优先级，就会无视需要回收的页框数量，只有将nr[]中的数量页数都扫描完才停止
	 * 快速回收不会这样做(快速回收的优先级不是DEF_PRIORITY)
	 */
	scan_adjusted = (global_reclaim(sc) && !current_is_kswapd() &&
			 sc->priority == DEF_PRIORITY);

	/* 初始化这个struct blk_plug
	 * 主要初始化list，mq_list，cb_list这三个链表头
	 * 然后current->plug = plug
	 */
	blk_start_plug(&plug);
	/* 如果LRU_INACTIVE_ANON，LRU_ACTIVE_FILE，LRU_INACTIVE_FILE这三个其中一个需要扫描的页框数没有扫描完，那扫描就会继续 
	 * 注意这里不会判断LRU_ACTIVE_ANON需要扫描的页框数是否扫描完，这里原因大概是因为系统不太希望对匿名页lru链表中的页回收
	 */
	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
					nr[LRU_INACTIVE_FILE]) {
		unsigned long nr_anon, nr_file, percentage;
		unsigned long nr_scanned;

		/* 以LRU_INACTIVE_ANON，LRU_INACTIVE_ANON，LRU_INACTIVE_FILE，LRU_ACTIVE_FILE这个顺序遍历lru链表 
		 * 然后对遍历到的lru链表进行扫描，一次最多32个页框
		 */
		for_each_evictable_lru(lru) {
			/* nr[lru类型]如果有页框需要扫描 */
			if (nr[lru]) {
				/* 获取本次需要扫描的页框数量，nr[lru]与SWAP_CLUSTER_MAX的最小值 
				 * 也就是每一轮最多只扫描SWAP_CLUSTER_MAX(32)个页框
				 */
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				/* nr[lru类型]减掉本次需要扫描的页框数量 */
				nr[lru] -= nr_to_scan;

				/* 对此lru类型的lru链表进行内存回收 
				 * 一次扫描的页框数是nr[lru]与SWAP_CLUSTER_MAX的最小值，也就是如果全部能回收，一次也就只能回收SWAP_CLUSTER_MAX(32)个页框
				 * 都是从lru链表末尾向前扫描
				 * 本次回收的页框数保存在nr_reclaimed中
				 */
				nr_reclaimed += shrink_list(lru, nr_to_scan,
							    lruvec, sc);
			}
		}

		/* 没有回收到足够页框，或者需要忽略需要回收的页框数量，尽可能多的回收页框，则继续进行回收
		 * 当scan_adjusted为真时，扫描到nr[三个类型]数组中的数都为0为止，会忽略是否回收到足够页框，即使回收到足够页框也继续进行扫描
		 * 也就是尽可能的回收页框，越多越好，alloc_pages()会是这种情况
		 */
		if (nr_reclaimed < nr_to_reclaim || scan_adjusted)
			continue;

		/*
		 * For kswapd and memcg, reclaim at least the number of pages
		 * requested. Ensure that the anon and file LRUs are scanned
		 * proportionally what was requested by get_scan_count(). We
		 * stop reclaiming one LRU and reduce the amount scanning
		 * proportional to the original scan target.
		 */

		/* kswapd和针对某个memcg进行回收的情况中会调用到此，已经回收到了足够数量的页框，调用到此是用于判断是否还要继续扫描，因为已经回收到了足够页框了 */

		/* 扫描一遍后，剩余需要扫描的文件页数量和匿名页数量 */
		nr_file = nr[LRU_INACTIVE_FILE] + nr[LRU_ACTIVE_FILE];
		nr_anon = nr[LRU_INACTIVE_ANON] + nr[LRU_ACTIVE_ANON];

		/*
		 * It's just vindictive to attack the larger once the smaller
		 * has gone to zero.  And given the way we stop scanning the
		 * smaller below, this makes sure that we only make one nudge
		 * towards proportionality once we've got nr_to_reclaim.
		 */

		/* 已经扫描完成了，退出循环 */
		if (!nr_file || !nr_anon)
			break;

		/* 下面就是计算再扫描多少页框，会对nr[]中的数进行相应的减少 
		 * 调用到这里肯定是kswapd进程或者针对memcg的页框回收，并且已经回收到了足够的页框了
		 * 如果nr[]中还剩余很多数量的页框没有扫描，这里就通过计算，减少一些nr[]待扫描的数量
		 * 设置scan_adjusted，之后把nr[]中剩余的数量扫描完成
		 */

		if (nr_file > nr_anon) {
			/* 剩余需要扫描的文件页多于剩余需要扫描的匿名页时 */

			/* 原始的需要扫描匿名页数量 */
			unsigned long scan_target = targets[LRU_INACTIVE_ANON] +
						targets[LRU_ACTIVE_ANON] + 1;
			lru = LRU_BASE;
			/* 计算剩余的需要扫描的匿名页数量占 */
			percentage = nr_anon * 100 / scan_target;
		} else {
			/* 剩余需要扫描的文件页少于剩余需要扫描的匿名页时 */
			unsigned long scan_target = targets[LRU_INACTIVE_FILE] +
						targets[LRU_ACTIVE_FILE] + 1;
			lru = LRU_FILE;
			percentage = nr_file * 100 / scan_target;
		}

		/* Stop scanning the smaller of the LRU */
		nr[lru] = 0;
		nr[lru + LRU_ACTIVE] = 0;

		/*
		 * Recalculate the other LRU scan count based on its original
		 * scan target and the percentage scanning already complete
		 */
		lru = (lru == LRU_FILE) ? LRU_BASE : LRU_FILE;
		nr_scanned = targets[lru] - nr[lru];
		nr[lru] = targets[lru] * (100 - percentage) / 100;
		nr[lru] -= min(nr[lru], nr_scanned);

		lru += LRU_ACTIVE;
		nr_scanned = targets[lru] - nr[lru];
		nr[lru] = targets[lru] * (100 - percentage) / 100;
		nr[lru] -= min(nr[lru], nr_scanned);

		scan_adjusted = true;
	}
	blk_finish_plug(&plug);
	/* 总共回收的页框数量 */
	sc->nr_reclaimed += nr_reclaimed;

	/*
	 * Even if we did not try to evict anon pages at all, we want to
	 * rebalance the anon lru active/inactive ratio.
	 */
	/* 非活动匿名页lru链表中页数量太少 */
	if (inactive_anon_is_low(lruvec))
		/* 从活动匿名页lru链表中移动一些页去非活动匿名页lru链表，最多32个 */
		shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
				   sc, LRU_ACTIVE_ANON);

	/* 如果太多脏页进行回写了，这里就睡眠100ms */
	throttle_vm_writeout(sc->gfp_mask);
}

/* Use reclaim/compaction for costly allocs or under memory pressure */
static bool in_reclaim_compaction(struct scan_control *sc)
{
	if (IS_ENABLED(CONFIG_COMPACTION) && sc->order &&
			(sc->order > PAGE_ALLOC_COSTLY_ORDER ||
			 sc->priority < DEF_PRIORITY - 2))
		return true;

	return false;
}

/*
 * Reclaim/compaction is used for high-order allocation requests. It reclaims
 * order-0 pages before compacting the zone. should_continue_reclaim() returns
 * true if more pages should be reclaimed such that when the page allocator
 * calls try_to_compact_zone() that it will have enough free pages to succeed.
 * It will give up earlier than that if there is difficulty reclaiming pages.
 */
/* 判断是否继续对zone进行内存回收，主要是检查空闲页框数量能不能进行内存压缩
 * nr_reclaimed: 本次回收的数量
 * nr_scanned: 本次扫描的数量
 */
static inline bool should_continue_reclaim(struct zone *zone,
					unsigned long nr_reclaimed,
					unsigned long nr_scanned,
					struct scan_control *sc)
{
	unsigned long pages_for_compaction;
	unsigned long inactive_lru_pages;

	/* If not in reclaim/compaction mode, stop */
	/* 如果不是在进行内存回收或者内存压缩，则返回 */
	if (!in_reclaim_compaction(sc))
		return false;

	/* Consider stopping depending on scan and reclaim activity */
	if (sc->gfp_mask & __GFP_REPEAT) {
		/*
		 * For __GFP_REPEAT allocations, stop reclaiming if the
		 * full LRU list has been scanned and we are still failing
		 * to reclaim pages. This full LRU scan is potentially
		 * expensive but a __GFP_REPEAT caller really wants to succeed
		 */
		if (!nr_reclaimed && !nr_scanned)
			return false;
	} else {
		/*
		 * For non-__GFP_REPEAT allocations which can presumably
		 * fail without consequence, stop if we failed to reclaim
		 * any pages from the last SWAP_CLUSTER_MAX number of
		 * pages that were scanned. This will return to the
		 * caller faster at the risk reclaim/compaction and
		 * the resulting allocation attempt fails
		 */
		if (!nr_reclaimed)
			return false;
	}

	/*
	 * If we have not reclaimed enough pages for compaction and the
	 * inactive lists are large enough, continue reclaiming
	 */
	/* 这里是保存比目标order大一级的order代表的页框数量 */
	pages_for_compaction = (2UL << sc->order);
	/* 非活动页数量 = 非活动文件页数量 */
	inactive_lru_pages = zone_page_state(zone, NR_INACTIVE_FILE);
	/* 如果还有空闲swap空间 */
	if (get_nr_swap_pages() > 0)
		/* 非活动页数量 += 非活动匿名页数量 */
		inactive_lru_pages += zone_page_state(zone, NR_INACTIVE_ANON);
	/* 如果回收的页框没有达到要求回收的页框order值再大一级的order代表的页数量，并且非活动页数量足够回收再大一级的order代表的页数量，就让此zone继续回收 */
	if (sc->nr_reclaimed < pages_for_compaction &&
			inactive_lru_pages > pages_for_compaction)
		return true;

	/* If compaction would go ahead or the allocation would succeed, stop */
	switch (compaction_suitable(zone, sc->order)) {
	case COMPACT_PARTIAL:
	case COMPACT_CONTINUE:
		return false;
	default:
		return true;
	}
}

/* 对zone进行内存回收 
 * 返回是否回收到了页框，而不是十分回收到了sc中指定数量的页框
 * 即使没回收到sc中指定数量的页框，只要回收到了页框，就返回真
 */
static bool shrink_zone(struct zone *zone, struct scan_control *sc)
{
	unsigned long nr_reclaimed, nr_scanned;
	bool reclaimable = false;

	do {
		/* 当内存回收是针对整个zone时，sc->target_mem_cgroup为NULL */
		struct mem_cgroup *root = sc->target_mem_cgroup;
		struct mem_cgroup_reclaim_cookie reclaim = {
			.zone = zone,
			.priority = sc->priority,
		};
		struct mem_cgroup *memcg;

		/* 本次开始前回收到的页框数量 
		 * 第一次时是0
		 */
		nr_reclaimed = sc->nr_reclaimed;
		/* 本次开始前扫描过的页框数量
		 * 第一次时是0
		 */
		nr_scanned = sc->nr_scanned;

		/* 获取最上层的memcg
		 * 如果没有指定开始的root，则默认是root_mem_cgroup
		 * root_mem_cgroup管理的每个zone的lru链表就是每个zone完整的lru链表
 		 */
		memcg = mem_cgroup_iter(root, NULL, &reclaim);
		do {
			struct lruvec *lruvec;
			int swappiness;

			/* 获取此memcg在此zone的lru链表 
			 * 如果内核没有开启memcg，那么就是zone->lruvec
			 */
			lruvec = mem_cgroup_zone_lruvec(zone, memcg);
			/* 从memcg中获取swapiness，此值代表了进行swap的频率，此值较低时，那么就更多的进行文件页的回收，此值较高时，则更多进行匿名页的回收 */
			swappiness = mem_cgroup_swappiness(memcg);

			/* 对此memcg的lru链表进行回收工作 
			 * 此lru链表中的所有页都是属于此zone的
			 * 每个memcg中都会为每个zone维护一个lru链表
			 */
			shrink_lruvec(lruvec, swappiness, sc);

			/*
			 * Direct reclaim and kswapd have to scan all memory
			 * cgroups to fulfill the overall scan target for the
			 * zone.
			 *
			 * Limit reclaim, on the other hand, only cares about
			 * nr_to_reclaim pages to be reclaimed and it will
			 * retry with decreasing priority if one round over the
			 * whole hierarchy is not sufficient.
			 */
			/* 如果是对于整个zone进行回收，那么会遍历所有memcg，对所有memcg中此zone的lru链表进行回收 
			 * 而如果只是针对某个memcg进行回收，如果回收到了足够内存则返回，如果没回收到足够内存，则对此memcg下面的memcg进行回收
			 */
			if (!global_reclaim(sc) &&
					sc->nr_reclaimed >= sc->nr_to_reclaim) {
				mem_cgroup_iter_break(root, memcg);
				break;
			}
			/* 下一个memcg，对于整个zone进行回收和对某个memcg进行回收但回收数量不足时会执行到此 */
			memcg = mem_cgroup_iter(root, memcg, &reclaim);
		} while (memcg);
		
		/* 计算此memcg的内存压力，保存到memcg->vmpressure */
		vmpressure(sc->gfp_mask, sc->target_mem_cgroup,
			   sc->nr_scanned - nr_scanned,
			   sc->nr_reclaimed - nr_reclaimed);

		if (sc->nr_reclaimed - nr_reclaimed)
			reclaimable = true;

	/* 判断是否再次此zone进行内存回收 
	 * 继续对此zone进行内存回收有两种情况:
	 * 1. 没有回收到比目标order值多一倍的数量页框，并且非活动lru链表中的页框数量 > 目标order多一倍的页
	 * 2. 此zone不满足内存压缩的条件，则继续对此zone进行内存回收
	 * 而当本次内存回收完全没有回收到页框时则返回，这里大概意思就是想回收比order更多的页框
	 */
	} while (should_continue_reclaim(zone, sc->nr_reclaimed - nr_reclaimed,
					 sc->nr_scanned - nr_scanned, sc));

	return reclaimable;
}

/*
 * Returns true if compaction should go ahead for a high-order request, or
 * the high-order allocation would succeed without compaction.
 */
/* 判断此zone是否需要进行内存压缩 */
static inline bool compaction_ready(struct zone *zone, int order)
{
	unsigned long balance_gap, watermark;
	bool watermark_ok;

	/*
	 * Compaction takes time to run and there are potentially other
	 * callers using the pages just freed. Continue reclaiming until
	 * there is a buffer of free pages available to give compaction
	 * a reasonable chance of completing and allocating the page
	 */
	/* 这一段的意思就是
	 * 此zone的空闲内存高于此zone的高阀值 + balance_gap + 2^order页框数
	 * 此zone有很多空闲内存
	 */
	balance_gap = min(low_wmark_pages(zone), DIV_ROUND_UP(
			zone->managed_pages, KSWAPD_ZONE_BALANCE_GAP_RATIO));
	watermark = high_wmark_pages(zone) + balance_gap + (2UL << order);
	watermark_ok = zone_watermark_ok_safe(zone, 0, watermark, 0, 0);

	/*
	 * If compaction is deferred, reclaim up to a point where
	 * compaction will have a chance of success when re-enabled
	 */

	/* 对此zone进行一次内存压缩推迟
	 * 但是如果watermark_ok是true，那么这里就会返回true
	 */
	if (compaction_deferred(zone, order))
		return watermark_ok;

	/*
	 * If compaction is not ready to start and allocation is not likely
	 * to succeed without it, then keep reclaiming.
	 */
	/* 检查此zone能否进行内存压缩 */
	if (compaction_suitable(zone, order) == COMPACT_SKIPPED)
		return false;

	return watermark_ok;
}

/*
 * This is the direct reclaim path, for page-allocating processes.  We only
 * try to reclaim pages from zones which will satisfy the caller's allocation
 * request.
 *
 * We reclaim from a zone even if that zone is over high_wmark_pages(zone).
 * Because:
 * a) The caller may be trying to free *extra* pages to satisfy a higher-order
 *    allocation or
 * b) The target zone may be at high_wmark_pages(zone) but the lower zones
 *    must go *over* high_wmark_pages(zone) to satisfy the `incremental min'
 *    zone defense algorithm.
 *
 * If a zone is deemed to be full of pinned pages then just give it a light
 * scan then give up on it.
 *
 * Returns true if a zone was reclaimable.
 */
/*  */
static bool shrink_zones(struct zonelist *zonelist, struct scan_control *sc)
{
	struct zoneref *z;
	struct zone *zone;
	unsigned long nr_soft_reclaimed;
	unsigned long nr_soft_scanned;
	unsigned long lru_pages = 0;
	struct reclaim_state *reclaim_state = current->reclaim_state;
	gfp_t orig_mask;
	/* 内存回收控制结构，内存回收的相关结果和相关参数会在这里面 */
	struct shrink_control shrink = {
		.gfp_mask = sc->gfp_mask,
	};
	enum zone_type requested_highidx = gfp_zone(sc->gfp_mask);
	bool reclaimable = false;

	/*
	 * If the number of buffer_heads in the machine exceeds the maximum
	 * allowed level, force direct reclaim to scan the highmem zone as
	 * highmem pages could be pinning lowmem pages storing buffer_heads
	 */
	orig_mask = sc->gfp_mask;
	/* 如果buffer_head数量超过了系统限制的值，则设置__GFP_HIGHMEM */
	if (buffer_heads_over_limit)
		sc->gfp_mask |= __GFP_HIGHMEM;

	nodes_clear(shrink.nodes_to_scan);


	/* 遍历zonelist中的每个zone */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					gfp_zone(sc->gfp_mask), sc->nodemask) {
					
		/* 检查此zone是否管理着页框，如果没有，则跳过 */
		if (!populated_zone(zone))
			continue;
		/*
		 * Take care memory controller reclaiming has small influence
		 * to global LRU.
		 */
		/* 检查sc中的target_mem_cgroup是否是对整个zone进行内存回收，还是对cgroup中的某个组，如果是对整个zone，则进入判断 */
		if (global_reclaim(sc)) {
			/* 跟cpuset有关 */
			if (!cpuset_zone_allowed_hardwall(zone, GFP_KERNEL))
				continue;

			/* 计算zone能够回收的内存页框总数，也就是没有锁在内存中的匿名页和文件页之和 */
			lru_pages += zone_reclaimable_pages(zone);
			/* 设置内存回收控制结构允许回收的node中加入此zone所在的node */
			node_set(zone_to_nid(zone), shrink.nodes_to_scan);

			/* 检查扫描控制结构的优先级是否是默认优先级(DEF_PRIORITY)，如果不是默认优先级，则检查此zone能否进行内存回收
			 * 判断zone是否能够进行内存回收，判断的标准是 扫描的页数 < (所有可回收页框的数量 * 6)，也就是已经对此zone已经扫描过6遍它的所有可回收页框了 
			 */
			if (sc->priority != DEF_PRIORITY &&
			    !zone_reclaimable(zone))
				continue;	/* Let kswapd poll it */

			/*
			 * If we already have plenty of memory free for
			 * compaction in this zone, don't free any more.
			 * Even though compaction is invoked for any
			 * non-zero order, only frequent costly order
			 * reclamation is disruptive enough to become a
			 * noticeable problem, like transparent huge
			 * page allocations.
			 */
			/* 如果此zone已经有足够的空闲内存了，那有可能是此zone碎片太多，这里检查是否需要进行内存压缩 */
			if (IS_ENABLED(CONFIG_COMPACTION) &&
			    sc->order > PAGE_ALLOC_COSTLY_ORDER &&
			    zonelist_zone_idx(z) <= requested_highidx &&
			    compaction_ready(zone, sc->order)) {
			    /* 需要进行内存压缩，设置扫描控制结构中可以进行内存压缩标志 
				 * 然后下一个zone，也就是此zone空闲内存足够，不需要回收，只需要内存压缩，这里此zone就不会继续往下走，去做内存回收了
				 */
				sc->compaction_ready = true;
				continue;
			}

			/*
			 * This steals pages from memory cgroups over softlimit
			 * and returns the number of reclaimed pages and
			 * scanned pages. This works for global memory pressure
			 * and balancing, not for a memcg's limit.
			 */
			nr_soft_scanned = 0;
			/* 
			 * 进行软回收，这个回收跟cgroup的memory子系统中的soft_limit_in_bytes文件有关
			 * 此参数的意思是所属memory组的进程使用的内存可以超过soft_limit_in_bytes，但是在内存不足时，优先回收超过部分
			 * 这里就是先回收超过这部分
			 * 需要注意，cgroup中memory面向的是进程，而这里面向的是zone，也就是说，回收时是回收进程在此zone中使用的可回收内存
			 */
			nr_soft_reclaimed = mem_cgroup_soft_limit_reclaim(zone,
						sc->order, sc->gfp_mask,
						&nr_soft_scanned);
			/* 总的回收数量更新加上本次软回收的数量 */
			sc->nr_reclaimed += nr_soft_reclaimed;
			/* 总共扫描的数量加上本次软回收总扫描的页框数量 */
			sc->nr_scanned += nr_soft_scanned;
			/* 对此zone的软回收回收到了页框，则标记reclaimable为true，reclaimable用于判断本次对zonelist进行的内存回收是否回收到页框 */
			if (nr_soft_reclaimed)
				reclaimable = true;
			/* need some check for avoid more shrink_zone() */
		}

		/* 对zone进行内存回收 */
		if (shrink_zone(zone, sc))
			reclaimable = true;

		if (global_reclaim(sc) &&
		    !reclaimable && zone_reclaimable(zone))
			reclaimable = true;
	}

	/*
	 * Don't shrink slabs when reclaiming memory from over limit cgroups
	 * but do shrink slab at least once when aborting reclaim for
	 * compaction to avoid unevenly scanning file/anon LRU pages over slab
	 * pages.
	 */
	if (global_reclaim(sc)) {
		shrink_slab(&shrink, sc->nr_scanned, lru_pages);
		if (reclaim_state) {
			sc->nr_reclaimed += reclaim_state->reclaimed_slab;
			reclaim_state->reclaimed_slab = 0;
		}
	}

	/*
	 * Restore to original mask to avoid the impact on the caller if we
	 * promoted it to __GFP_HIGHMEM.
	 */
	sc->gfp_mask = orig_mask;

	return reclaimable;
}

/*
 * This is the main entry point to direct page reclaim.
 *
 * If a full scan of the inactive list fails to free enough memory then we
 * are "out of memory" and something needs to be killed.
 *
 * If the caller is !__GFP_FS then the probability of a failure is reasonably
 * high - the zone may be full of dirty or under-writeback pages, which this
 * caller can't do much about.  We kick the writeback threads and take explicit
 * naps in the hope that some of these pages can be written.  But if the
 * allocating task holds filesystem locks which prevent writeout this might not
 * work, and the allocation attempt will fail.
 *
 * returns:	0, if no pages reclaimed
 * 		else, the number of pages reclaimed
 */
static unsigned long do_try_to_free_pages(struct zonelist *zonelist,
					  struct scan_control *sc)
{
	unsigned long total_scanned = 0;
	unsigned long writeback_threshold;
	bool zones_reclaimable;

	delayacct_freepages_start();

	if (global_reclaim(sc))
		count_vm_event(ALLOCSTALL);

	do {
		vmpressure_prio(sc->gfp_mask, sc->target_mem_cgroup,
				sc->priority);
		sc->nr_scanned = 0;
		zones_reclaimable = shrink_zones(zonelist, sc);

		total_scanned += sc->nr_scanned;
		if (sc->nr_reclaimed >= sc->nr_to_reclaim)
			break;

		if (sc->compaction_ready)
			break;

		/*
		 * If we're getting trouble reclaiming, start doing
		 * writepage even in laptop mode.
		 */
		if (sc->priority < DEF_PRIORITY - 2)
			sc->may_writepage = 1;

		/*
		 * Try to write back as many pages as we just scanned.  This
		 * tends to cause slow streaming writers to write data to the
		 * disk smoothly, at the dirtying rate, which is nice.   But
		 * that's undesirable in laptop mode, where we *want* lumpy
		 * writeout.  So in laptop mode, write out the whole world.
		 */
		writeback_threshold = sc->nr_to_reclaim + sc->nr_to_reclaim / 2;
		if (total_scanned > writeback_threshold) {
			wakeup_flusher_threads(laptop_mode ? 0 : total_scanned,
						WB_REASON_TRY_TO_FREE_PAGES);
			sc->may_writepage = 1;
		}
	} while (--sc->priority >= 0);

	delayacct_freepages_end();

	if (sc->nr_reclaimed)
		return sc->nr_reclaimed;

	/* Aborted reclaim to try compaction? don't OOM, then */
	if (sc->compaction_ready)
		return 1;

	/* Any of the zones still reclaimable?  Don't OOM. */
	if (zones_reclaimable)
		return 1;

	return 0;
}

static bool pfmemalloc_watermark_ok(pg_data_t *pgdat)
{
	struct zone *zone;
	unsigned long pfmemalloc_reserve = 0;
	unsigned long free_pages = 0;
	int i;
	bool wmark_ok;

	for (i = 0; i <= ZONE_NORMAL; i++) {
		zone = &pgdat->node_zones[i];
		if (!populated_zone(zone))
			continue;

		pfmemalloc_reserve += min_wmark_pages(zone);
		free_pages += zone_page_state(zone, NR_FREE_PAGES);
	}

	/* If there are no reserves (unexpected config) then do not throttle */
	if (!pfmemalloc_reserve)
		return true;

	wmark_ok = free_pages > pfmemalloc_reserve / 2;

	/* kswapd must be awake if processes are being throttled */
	if (!wmark_ok && waitqueue_active(&pgdat->kswapd_wait)) {
		pgdat->classzone_idx = min(pgdat->classzone_idx,
						(enum zone_type)ZONE_NORMAL);
		wake_up_interruptible(&pgdat->kswapd_wait);
	}

	return wmark_ok;
}

/*
 * Throttle direct reclaimers if backing storage is backed by the network
 * and the PFMEMALLOC reserve for the preferred node is getting dangerously
 * depleted. kswapd will continue to make progress and wake the processes
 * when the low watermark is reached.
 *
 * Returns true if a fatal signal was delivered during throttling. If this
 * happens, the page allocator should not consider triggering the OOM killer.
 */
static bool throttle_direct_reclaim(gfp_t gfp_mask, struct zonelist *zonelist,
					nodemask_t *nodemask)
{
	struct zoneref *z;
	struct zone *zone;
	pg_data_t *pgdat = NULL;

	/*
	 * Kernel threads should not be throttled as they may be indirectly
	 * responsible for cleaning pages necessary for reclaim to make forward
	 * progress. kjournald for example may enter direct reclaim while
	 * committing a transaction where throttling it could forcing other
	 * processes to block on log_wait_commit().
	 */
	if (current->flags & PF_KTHREAD)
		goto out;

	/*
	 * If a fatal signal is pending, this process should not throttle.
	 * It should return quickly so it can exit and free its memory
	 */
	if (fatal_signal_pending(current))
		goto out;

	/*
	 * Check if the pfmemalloc reserves are ok by finding the first node
	 * with a usable ZONE_NORMAL or lower zone. The expectation is that
	 * GFP_KERNEL will be required for allocating network buffers when
	 * swapping over the network so ZONE_HIGHMEM is unusable.
	 *
	 * Throttling is based on the first usable node and throttled processes
	 * wait on a queue until kswapd makes progress and wakes them. There
	 * is an affinity then between processes waking up and where reclaim
	 * progress has been made assuming the process wakes on the same node.
	 * More importantly, processes running on remote nodes will not compete
	 * for remote pfmemalloc reserves and processes on different nodes
	 * should make reasonable progress.
	 */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					gfp_mask, nodemask) {
		if (zone_idx(zone) > ZONE_NORMAL)
			continue;

		/* Throttle based on the first usable node */
		pgdat = zone->zone_pgdat;
		if (pfmemalloc_watermark_ok(pgdat))
			goto out;
		break;
	}

	/* If no zone was usable by the allocation flags then do not throttle */
	if (!pgdat)
		goto out;

	/* Account for the throttling */
	count_vm_event(PGSCAN_DIRECT_THROTTLE);

	/*
	 * If the caller cannot enter the filesystem, it's possible that it
	 * is due to the caller holding an FS lock or performing a journal
	 * transaction in the case of a filesystem like ext[3|4]. In this case,
	 * it is not safe to block on pfmemalloc_wait as kswapd could be
	 * blocked waiting on the same lock. Instead, throttle for up to a
	 * second before continuing.
	 */
	if (!(gfp_mask & __GFP_FS)) {
		wait_event_interruptible_timeout(pgdat->pfmemalloc_wait,
			pfmemalloc_watermark_ok(pgdat), HZ);

		goto check_pending;
	}

	/* Throttle until kswapd wakes the process */
	wait_event_killable(zone->zone_pgdat->pfmemalloc_wait,
		pfmemalloc_watermark_ok(pgdat));

check_pending:
	if (fatal_signal_pending(current))
		return true;

out:
	return false;
}

unsigned long try_to_free_pages(struct zonelist *zonelist, int order,
				gfp_t gfp_mask, nodemask_t *nodemask)
{
	unsigned long nr_reclaimed;
	struct scan_control sc = {
		/* 打算回收32个页框 */
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.gfp_mask = (gfp_mask = memalloc_noio_flags(gfp_mask)),
		/* 本次内存分配的order值 */
		.order = order,
		/* 允许进行回收的node掩码 */
		.nodemask = nodemask,
		/* 优先级为默认的12 */
		.priority = DEF_PRIORITY,
		/* 与/proc/sys/vm/laptop_mode文件有关
		 * laptop_mode为0，则允许进行回写操作，即使允许回写，直接内存回收也不能对脏文件页进行回写
		 * 不过允许回写时，可以对非文件页进行回写
		 */
		.may_writepage = !laptop_mode,
		/* 允许进行unmap操作 */
		.may_unmap = 1,
		/* 允许进行非文件页的操作 */
		.may_swap = 1,
	};

	/*
	 * Do not enter reclaim if fatal signal was delivered while throttled.
	 * 1 is returned so that the page allocator does not OOM kill at this
	 * point.
	 */
	if (throttle_direct_reclaim(gfp_mask, zonelist, nodemask))
		return 1;

	trace_mm_vmscan_direct_reclaim_begin(order,
				sc.may_writepage,
				gfp_mask);

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	trace_mm_vmscan_direct_reclaim_end(nr_reclaimed);

	return nr_reclaimed;
}

#ifdef CONFIG_MEMCG

unsigned long mem_cgroup_shrink_node_zone(struct mem_cgroup *memcg,
						gfp_t gfp_mask, bool noswap,
						struct zone *zone,
						unsigned long *nr_scanned)
{
	struct scan_control sc = {
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.target_mem_cgroup = memcg,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = !noswap,
	};
	struct lruvec *lruvec = mem_cgroup_zone_lruvec(zone, memcg);
	int swappiness = mem_cgroup_swappiness(memcg);

	sc.gfp_mask = (gfp_mask & GFP_RECLAIM_MASK) |
			(GFP_HIGHUSER_MOVABLE & ~GFP_RECLAIM_MASK);

	trace_mm_vmscan_memcg_softlimit_reclaim_begin(sc.order,
						      sc.may_writepage,
						      sc.gfp_mask);

	/*
	 * NOTE: Although we can get the priority field, using it
	 * here is not a good idea, since it limits the pages we can scan.
	 * if we don't reclaim here, the shrink_zone from balance_pgdat
	 * will pick up pages from other mem cgroup's as well. We hack
	 * the priority and make it zero.
	 */
	shrink_lruvec(lruvec, swappiness, &sc);

	trace_mm_vmscan_memcg_softlimit_reclaim_end(sc.nr_reclaimed);

	*nr_scanned = sc.nr_scanned;
	return sc.nr_reclaimed;
}

unsigned long try_to_free_mem_cgroup_pages(struct mem_cgroup *memcg,
					   unsigned long nr_pages,
					   gfp_t gfp_mask,
					   bool may_swap)
{
	struct zonelist *zonelist;
	unsigned long nr_reclaimed;
	int nid;
	struct scan_control sc = {
		.nr_to_reclaim = max(nr_pages, SWAP_CLUSTER_MAX),
		.gfp_mask = (gfp_mask & GFP_RECLAIM_MASK) |
				(GFP_HIGHUSER_MOVABLE & ~GFP_RECLAIM_MASK),
		.target_mem_cgroup = memcg,
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = may_swap,
	};

	/*
	 * Unlike direct reclaim via alloc_pages(), memcg's reclaim doesn't
	 * take care of from where we get pages. So the node where we start the
	 * scan does not need to be the current node.
	 */
	nid = mem_cgroup_select_victim_node(memcg);

	zonelist = NODE_DATA(nid)->node_zonelists;

	trace_mm_vmscan_memcg_reclaim_begin(0,
					    sc.may_writepage,
					    sc.gfp_mask);

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	trace_mm_vmscan_memcg_reclaim_end(nr_reclaimed);

	return nr_reclaimed;
}
#endif

/* 将active_anon这个lru链表中的页拿出一些放到inactive_anon这个lru链表头部，但并不一定拿多少放多少，还需要一些判断 */
static void age_active_anon(struct zone *zone, struct scan_control *sc)
{
	struct mem_cgroup *memcg;

	if (!total_swap_pages)
		return;

	/* 这里会获取root的memcg */
	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		/* 获取zone的lruvec链表 
		 * 当启用memcg时，此链表保存在memcg->nodeinfo[nodeID]->zoneinfo[zoneID]
		 * 没有启用memcg时，保存在zone->lruvec
		 */
		struct lruvec *lruvec = mem_cgroup_zone_lruvec(zone, memcg);

		/* 判断非活动匿名页是否处于low水平，判断标准是inactive的匿名页数量是否低于整个zone的匿名页数量的25%
		 * 如果非活动匿名页低于low阀值，则要将一些active中的匿名页移动到inactive中
		 */
		if (inactive_anon_is_low(lruvec))
			shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
					   sc, LRU_ACTIVE_ANON);

		/* 下一个memcg */
		memcg = mem_cgroup_iter(NULL, memcg, NULL);
	} while (memcg);
}

/* 判断zone是否平衡 
 * 如果zone的空闲页面数量高于高警戒位，则表明此zone是平衡的
 * 再判断是否需要进行内存压缩，如果需要，那此zone也算是不平衡的zone
 */
static bool zone_balanced(struct zone *zone, int order,
			  unsigned long balance_gap, int classzone_idx)
{
	/* 如果zone的空闲页面数量高于高警戒位，则表明此zone是平衡的 */
	if (!zone_watermark_ok_safe(zone, order, high_wmark_pages(zone) +
				    balance_gap, classzone_idx, 0))
		return false;

	/* 再判断是否需要进行内存压缩，如果需要，那此zone也算是不平衡的zone */
	if (IS_ENABLED(CONFIG_COMPACTION) && order &&
	    compaction_suitable(zone, order) == COMPACT_SKIPPED)
		return false;

	return true;
}

/*
 * pgdat_balanced() is used when checking if a node is balanced.
 *
 * For order-0, all zones must be balanced!
 *
 * For high-order allocations only zones that meet watermarks and are in a
 * zone allowed by the callers classzone_idx are added to balanced_pages. The
 * total of balanced pages must be at least 25% of the zones allowed by
 * classzone_idx for the node to be considered balanced. Forcing all zones to
 * be balanced for high orders can cause excessive reclaim when there are
 * imbalanced zones.
 * The choice of 25% is due to
 *   o a 16M DMA zone that is balanced will not balance a zone on any
 *     reasonable sized machine
 *   o On all other machines, the top zone must be at least a reasonable
 *     percentage of the middle zones. For example, on 32-bit x86, highmem
 *     would need to be at least 256M for it to be balance a whole node.
 *     Similarly, on x86-64 the Normal zone would need to be at least 1G
 *     to balance a node on its own. These seemed like reasonable ratios.
 */
/* 用于检测node是否平衡
 * 如果order为0，只要其中一个zone不平衡则返回false
 * 如果order不为0，balanced_pages小于node结点所有页框的1/4都会返回false 
 */
static bool pgdat_balanced(pg_data_t *pgdat, int order, int classzone_idx)
{
	/* 整个node的classzone_idx中的zone所管理的全部页框数量 */
	unsigned long managed_pages = 0;
	/* 存放平衡的页框数量，当一个zone平衡时，那整个zone的页框都为平衡页框 */
	unsigned long balanced_pages = 0;
	int i;

	/* Check the watermark levels */
	for (i = 0; i <= classzone_idx; i++) {
		struct zone *zone = pgdat->node_zones + i;

		if (!populated_zone(zone))
			continue;

		/* managed_pages保存node中所有的页数量 */
		managed_pages += zone->managed_pages;

		/*
		 * A special case here:
		 *
		 * balance_pgdat() skips over all_unreclaimable after
		 * DEF_PRIORITY. Effectively, it considers them balanced so
		 * they must be considered balanced here as well!
		 */
		/* 此zone是否能够进行内存回收，如果不能够，则直接当做是平衡的zone，判断标准是zone的NR_PAGES_SCANNED是否小于所有可回收页框的1/6 */
		if (!zone_reclaimable(zone)) {
			balanced_pages += zone->managed_pages;
			continue;
		}

		/* 判断zone是否平衡，主要判断是否高于高阀值和是否需要进行内存压缩，如果不平衡，则直接返回false */
		if (zone_balanced(zone, order, 0, i))
			balanced_pages += zone->managed_pages;
		else if (!order)
			return false;
	}

	if (order)
		return balanced_pages >= (managed_pages >> 2);
	else
		return true;
}

/*
 * Prepare kswapd for sleeping. This verifies that there are no processes
 * waiting in throttle_direct_reclaim() and that watermarks have been met.
 *
 * Returns true if kswapd is ready to sleep
 */
/* 如果整个node平衡则返回true，否则返回false */
static bool prepare_kswapd_sleep(pg_data_t *pgdat, int order, long remaining,
					int classzone_idx)
{
	/* If a direct reclaimer woke kswapd within HZ/10, it's premature */
	if (remaining)
		return false;

	/*
	 * The throttled processes are normally woken up in balance_pgdat() as
	 * soon as pfmemalloc_watermark_ok() is true. But there is a potential
	 * race between when kswapd checks the watermarks and a process gets
	 * throttled. There is also a potential race if processes get
	 * throttled, kswapd wakes, a large process exits thereby balancing the
	 * zones, which causes kswapd to exit balance_pgdat() before reaching
	 * the wake up checks. If kswapd is going to sleep, no process should
	 * be sleeping on pfmemalloc_wait, so wake them now if necessary. If
	 * the wake up is premature, processes will wake kswapd and get
	 * throttled again. The difference from wake ups in balance_pgdat() is
	 * that here we are under prepare_to_wait().
	 */
	/* 查看pgdat->pfmemalloc_wait是否有等待的进程，有则把他们全部唤醒 */
	if (waitqueue_active(&pgdat->pfmemalloc_wait))
		wake_up_all(&pgdat->pfmemalloc_wait);

	/* 返回整个node是否平衡
	 * 如果order为0，只要其中一个zone不平衡则返回false
 	 * 如果order不为0，balanced_pages小于node结点所有页框的1/4都会返回false 
 	 */
	return pgdat_balanced(pgdat, order, classzone_idx);
}

/*
 * kswapd shrinks the zone by the number of pages required to reach
 * the high watermark.
 *
 * Returns true if kswapd scanned at least the requested number of pages to
 * reclaim or if the lack of progress was due to pages under writeback.
 * This is used to determine if the scanning priority needs to be raised.
 */
static bool kswapd_shrink_zone(struct zone *zone,
			       int classzone_idx,
			       struct scan_control *sc,
			       unsigned long lru_pages,
			       unsigned long *nr_attempted)
{
	int testorder = sc->order;
	unsigned long balance_gap;
	struct reclaim_state *reclaim_state = current->reclaim_state;
	struct shrink_control shrink = {
		.gfp_mask = sc->gfp_mask,
	};
	bool lowmem_pressure;

	/* Reclaim above the high watermark. */
	/* 这里基本把需要回收的页框数量设置为这个zone的高阀值，说明希望尽可能的回收页框 */
	sc->nr_to_reclaim = max(SWAP_CLUSTER_MAX, high_wmark_pages(zone));

	/*
	 * Kswapd reclaims only single pages with compaction enabled. Trying
	 * too hard to reclaim until contiguous free pages have become
	 * available can hurt performance by evicting too much useful data
	 * from memory. Do not reclaim more than needed for compaction.
	 */
	if (IS_ENABLED(CONFIG_COMPACTION) && sc->order &&
			compaction_suitable(zone, sc->order) !=
				COMPACT_SKIPPED)
		testorder = 0;

	/*
	 * We put equal pressure on every zone, unless one zone has way too
	 * many pages free already. The "too many pages" is defined as the
	 * high wmark plus a "gap" where the gap is either the low
	 * watermark or 1% of the zone, whichever is smaller.
	 */
	balance_gap = min(low_wmark_pages(zone), DIV_ROUND_UP(
			zone->managed_pages, KSWAPD_ZONE_BALANCE_GAP_RATIO));

	/*
	 * If there is no low memory pressure or the zone is balanced then no
	 * reclaim is necessary
	 */
	/* 判断是否要对此zone进行内存回收
	 * 对于低端内存，只要可用内存高于高阀值，并且不需要进行内存压缩即可
	 * 对于高端内存，如果buffer_head超过了系统限定值，则要进行回收
	 */
	lowmem_pressure = (buffer_heads_over_limit && is_highmem(zone));
	if (!lowmem_pressure && zone_balanced(zone, testorder,
						balance_gap, classzone_idx))
		return true;

	/* 对此zone进行回收 */
	shrink_zone(zone, sc);
	/* 将需要扫描的node结点清除 */
	nodes_clear(shrink.nodes_to_scan);
	/* 将此zone所在node结点赋值上去 */
	node_set(zone_to_nid(zone), shrink.nodes_to_scan);

	reclaim_state->reclaimed_slab = 0;
	/* 回收slab */
	shrink_slab(&shrink, sc->nr_scanned, lru_pages);
	sc->nr_reclaimed += reclaim_state->reclaimed_slab;

	/* Account for the number of pages attempted to reclaim */
	*nr_attempted += sc->nr_to_reclaim;
	/* 清除zone的ZONE_WRITEBACK标志 */
	clear_bit(ZONE_WRITEBACK, &zone->flags);

	/*
	 * If a zone reaches its high watermark, consider it to be no longer
	 * congested. It's possible there are dirty pages backed by congested
	 * BDIs but as pressure is relieved, speculatively avoid congestion
	 * waits.
	 */
	/* 如果zone平衡了(可用页框 - 2^testorder后还达到了高阀值)，则清除ZONE_CONGESTED和ZONE_DIRTY标志 */
	if (zone_reclaimable(zone) &&
	    zone_balanced(zone, testorder, 0, classzone_idx)) {
		clear_bit(ZONE_CONGESTED, &zone->flags);
		clear_bit(ZONE_DIRTY, &zone->flags);
	}

	return sc->nr_scanned >= sc->nr_to_reclaim;
}

/*
 * For kswapd, balance_pgdat() will work across all this node's zones until
 * they are all at high_wmark_pages(zone).
 *
 * Returns the final order kswapd was reclaiming at
 *
 * There is special handling here for zones which are full of pinned pages.
 * This can happen if the pages are all mlocked, or if they are all used by
 * device drivers (say, ZONE_DMA).  Or if they are all in use by hugetlb.
 * What we do is to detect the case where all pages in the zone have been
 * scanned twice and there has been zero successful reclaim.  Mark the zone as
 * dead and from now on, only perform a short scan.  Basically we're polling
 * the zone for when the problem goes away.
 *
 * kswapd scans the zones in the highmem->normal->dma direction.  It skips
 * zones which have free_pages > high_wmark_pages(zone), but once a zone is
 * found to have free_pages <= high_wmark_pages(zone), we scan that zone and the
 * lower zones regardless of the number of free pages in the lower zones. This
 * interoperates with the page allocator fallback scheme to ensure that aging
 * of pages is balanced across the zones.
 */
/* 对node中的classzone_idx的zone进行内存平衡操作，将node结点的所有zone的空闲页框提高到high的阀值，返回总共回收的页框数量
 * 同时也会判断是否需要进行内存压缩
 */
static unsigned long balance_pgdat(pg_data_t *pgdat, int order,
							int *classzone_idx)
{
	int i;
	int end_zone = 0;	/* Inclusive.  0 = ZONE_DMA */
	unsigned long nr_soft_reclaimed;
	unsigned long nr_soft_scanned;
	/* 扫描控制结构 */
	struct scan_control sc = {
		/* (__GFP_WAIT | __GFP_IO | __GFP_FS)
		 * 此次内存回收允许进行IO和文件系统操作，有可能阻塞
		 */
		.gfp_mask = GFP_KERNEL,
		/* 需要回收的页框 */
		.order = order,
		/* 这个优先级决定了一次扫描多少队列 */
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
	};
	count_vm_event(PAGEOUTRUN);

	do {
		unsigned long lru_pages = 0;
		unsigned long nr_attempted = 0;
		/* 是否可以提高优先级，默认可以 */
		bool raise_priority = true;
		/* 是否需要进行内存压缩，如果order>0则需要 */
		bool pgdat_needs_compaction = (order > 0);

		sc.nr_reclaimed = 0;

		/*
		 * Scan in the highmem->dma direction for the highest
		 * zone which needs scanning
		 */
		/* 遍历node结点中所有的zone，找到第一个不平衡的管理区(空闲内存与高阀值比较)，从highmem往dma找，找到了第一个不平衡的zone就退出这个循环 */
		for (i = pgdat->nr_zones - 1; i >= 0; i--) {
			/* 获取此节点的第i个zone描述符 */
			struct zone *zone = pgdat->node_zones + i;

			/* 检查此zone是否管理着页框(比如内存小的时候就没有ZONE_HIGHMEM，但是有ZONE_HIGHMEM描述符)，也就是检查zone->present_zone */
			if (!populated_zone(zone))
				continue;

			/* 检查此zone是否可进行页框回收，可回收页框数量 = NR_ACTIVE_FILE + NR_INACTIVE_FILE + NR_ACTIVE_ANON + NR_INACTIVE_ANON */		
			/* NR_ACTIVE_FILE和NR_INACTIVE_FILE并不会返回到swap中，而是会直接将脏页写入到文件中，只有NR_ACTIVE_ANON和NR_INACTIVE_ANON会写入到swap中 */
			if (sc.priority != DEF_PRIORITY &&
			    !zone_reclaimable(zone))
				continue;

			/*
			 * Do some background aging of the anon list, to give
			 * pages a chance to be referenced before reclaiming.
			 */
			/* 更新非活动匿名页lru链表，匿名页主要是进程的堆和栈和私有匿名mmap区
			 * 这里主要判断非活动匿名页lru链表中页数量是否过少，过少的情况下则从活动匿名页lru链表拿出一些页放入非活动匿名页lru链表头部
			 */
			age_active_anon(zone, &sc);

			/*
			 * If the number of buffer_heads in the machine
			 * exceeds the maximum allowed level and this node
			 * has a highmem zone, force kswapd to reclaim from
			 * it to relieve lowmem pressure.
			 */
			/* 如果buffer_heads的数量超过了结点允许的最大值，并且遍历到的zone为highmem区域，则标记结束zone为这个highmem高端内存区，之后会强制kswapd回收这些buffer_heads来释放内存的压力 */
			if (buffer_heads_over_limit && is_highmem_idx(i)) {
				end_zone = i;
				break;
			}

			/* 检查此zone是否是平衡的，其实就是zone中空闲内存减去2的order次方数量页框后，页框数量还大于高阀值 */
			if (!zone_balanced(zone, order, 0, 0)) {
				/* 不平衡，记录到end_zone，退出这个循环 */
				end_zone = i;
				break;
			} else {
				/*
				 * If balanced, clear the dirty and congested
				 * flags
				 */
				/* 平衡情况，则清除ZONE_CONGESTED和ZONE_DIRTY标志 */
				clear_bit(ZONE_CONGESTED, &zone->flags);
				clear_bit(ZONE_DIRTY, &zone->flags);
			}
		}

		/* node上所有管理区都是平衡的，退出 */
		if (i < 0)
			goto out;

		/* 有不平衡的管理区，从dma往上遍历管理区 */
		for (i = 0; i <= end_zone; i++) {
			/* 获取遍历到的管理区描述符 */
			struct zone *zone = pgdat->node_zones + i;
			
			/* 检查此zone是否管理着页框(比如内存小的时候就没有ZONE_HIGHMEM，但是有ZONE_HIGHMEM描述符)，也就是检查zone->present_zone */
			if (!populated_zone(zone))
				continue;

			/* 获取此管理区可回收的页框总数量，也就是NR_ACTIVE_FILE + NR_INACTIVE_FILE + NR_ACTIVE_ANON + NR_INACTIVE_ANON */
			lru_pages += zone_reclaimable_pages(zone);

			/*
			 * If any zone is currently balanced then kswapd will
			 * not call compaction as it is expected that the
			 * necessary pages are already available.
			 */
			/* 如果order > 0，则pgdat_needs_compaction = true，如果有任何一个管理区减去2的order次方数量的页框后页框数量还大于低阀值，则将pgdat_needs_compaction设置为false
			 * pgdat_needs_compaction代表是否需要内存压缩
			 */
			if (pgdat_needs_compaction &&
					zone_watermark_ok(zone, order,
						low_wmark_pages(zone),
						*classzone_idx, 0))
				pgdat_needs_compaction = false;
		}

		/*
		 * If we're getting trouble reclaiming, start doing writepage
		 * even in laptop mode.
		 */
		if (sc.priority < DEF_PRIORITY - 2)
			sc.may_writepage = 1;

		/*
		 * Now scan the zone in the dma->highmem direction, stopping
		 * at the last zone which needs scanning.
		 *
		 * We do this because the page allocator works in the opposite
		 * direction.  This prevents the page allocator from allocating
		 * pages behind kswapd's direction of progress, which would
		 * cause too much scanning of the lower zones.
		 */
		/* 再次从dma区向上遍历 */
		for (i = 0; i <= end_zone; i++) {
			/* zone描述符 */
			struct zone *zone = pgdat->node_zones + i;

			/* 检查此zone是否管理着页框(比如内存小的时候就没有ZONE_HIGHMEM，但是有ZONE_HIGHMEM描述符)，也就是检查zone->present_zone */
			if (!populated_zone(zone))
				continue;

			if (sc.priority != DEF_PRIORITY &&
			    !zone_reclaimable(zone))
				continue;

			/* 当前zone扫描的页框数初始化为0 */
			sc.nr_scanned = 0;

			/* 保存总共扫描的页框数 */
			nr_soft_scanned = 0;
			/*
			 * Call soft limit reclaim before calling shrink_zone.
			 */
			/* 返回回收的数量 */
			nr_soft_reclaimed = mem_cgroup_soft_limit_reclaim(zone,
							order, sc.gfp_mask,
							&nr_soft_scanned);
			sc.nr_reclaimed += nr_soft_reclaimed;

			/*
			 * There should be no need to raise the scanning
			 * priority if enough pages are already being scanned
			 * that that high watermark would be met at 100%
			 * efficiency.
			 */
			/* 里面也会检查此zone是否是平衡的，其实就是zone中空闲内存减去2的order次方数量页框后，页框数量还大于高阀值 
			 * 不会对平衡的zone进行内存回收
			 */
			if (kswapd_shrink_zone(zone, end_zone, &sc,
					lru_pages, &nr_attempted))
				raise_priority = false;
		}

		/*
		 * If the low watermark is met there is no need for processes
		 * to be throttled on pfmemalloc_wait as they should not be
		 * able to safely make forward progress. Wake them
		 */
		if (waitqueue_active(&pgdat->pfmemalloc_wait) &&
				pfmemalloc_watermark_ok(pgdat))
			wake_up(&pgdat->pfmemalloc_wait);

		/*
		 * Fragmentation may mean that the system cannot be rebalanced
		 * for high-order allocations in all zones. If twice the
		 * allocation size has been reclaimed and the zones are still
		 * not balanced then recheck the watermarks at order-0 to
		 * prevent kswapd reclaiming excessively. Assume that a
		 * process requested a high-order can direct reclaim/compact.
		 */
		if (order && sc.nr_reclaimed >= 2UL << order)
			order = sc.order = 0;

		/* Check if kswapd should be suspending */
		if (try_to_freeze() || kthread_should_stop())
			break;

		/*
		 * Compact if necessary and kswapd is reclaiming at least the
		 * high watermark number of pages as requsted
		 */
		/* 判断node是否进行内存压缩，内存回收达到期望值则进行压缩 
		 * 判断标准:
		 * 如果有任何一个管理区减去2的order次方数量的页框后页框数量小于low阀值，则进行压缩
		 * 回收的页数量sc.nr_reclaimed > nr_attempted
		 */
		if (pgdat_needs_compaction && sc.nr_reclaimed > nr_attempted)
			compact_pgdat(pgdat, order);

		/*
		 * Raise priority if scanning rate is too low or there was no
		 * progress in reclaiming pages
		 */
		if (raise_priority || !sc.nr_reclaimed)
			sc.priority--;
	} while (sc.priority >= 1 &&
		 !pgdat_balanced(pgdat, order, *classzone_idx));

out:
	/*
	 * Return the order we were reclaiming at so prepare_kswapd_sleep()
	 * makes a decision on the order we were last reclaiming at. However,
	 * if another caller entered the allocator slow path while kswapd
	 * was awake, order will remain at the higher level
	 */
	*classzone_idx = end_zone;
	return order;
}

/* 此函数会进行检查整个node是否平衡，如果平衡，会睡眠，如果不平衡，则返回 */
static void kswapd_try_to_sleep(pg_data_t *pgdat, int order, int classzone_idx)
{
	long remaining = 0;
	DEFINE_WAIT(wait);

	if (freezing(current) || kthread_should_stop())
		return;
	
	/* 加入到pgdat->kswapd_wait等待队列中，但并没有进行睡眠，但进程状态被设置为了TASK_INTERRUPTIBLE */
	prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);

	/* Try to sleep for a short interval */
	/* 在prepare_kswapd_sleep()中会检查是否需要睡眠，判断标准是整个node结点是否需要进行内存回收，不需要进行内存回收则返回true */
	if (prepare_kswapd_sleep(pgdat, order, remaining, classzone_idx)) {
		/* remaining保存的是还没超时就被唤醒时，剩余的超时时间 */
		remaining = schedule_timeout(HZ/10);
		/* 从pgdat->kswapd_wait等待队列中移除 */
		finish_wait(&pgdat->kswapd_wait, &wait);
		/* 再重新加入到pgdat->kswapd_wait等待队列中，但并没有进行睡眠，但进程状态被设置为了TASK_INTERRUPTIBLE */
		prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);
	}

	/*
	 * After a short sleep, check if it was a premature sleep. If not, then
	 * go fully to sleep until explicitly woken up.
	 */
	/* 继续判断是否需要进行内存回收，如果上面的remaining有剩余，说明是被其他进程唤醒的，则跳过这段，不进行睡眠
	 * 这段会再次检查整个node是否平衡，如果平衡则进行一个长时间的睡眠，因为上面把进程状态设置为了TASK_INTERRUPTIBLE，并且主动调用了schedule()。当没有其他进程唤醒此kswapd时，会一直睡眠
	 */
	if (prepare_kswapd_sleep(pgdat, order, remaining, classzone_idx)) {
		trace_mm_vmscan_kswapd_sleep(pgdat->node_id);

		/*
		 * vmstat counters are not perfectly accurate and the estimated
		 * value for counters such as NR_FREE_PAGES can deviate from the
		 * true value by nr_online_cpus * threshold. To avoid the zone
		 * watermarks being breached while under pressure, we reduce the
		 * per-cpu vmstat threshold while kswapd is awake and restore
		 * them before going back to sleep.
		 */
		set_pgdat_percpu_threshold(pgdat, calculate_normal_threshold);

		/*
		 * Compaction records what page blocks it recently failed to
		 * isolate pages from and skips them in the future scanning.
		 * When kswapd is going to sleep, it is reasonable to assume
		 * that pages and compaction may succeed so reset the cache.
		 */
		/* 清除所有pageblock的跳过扫描标志 */
		reset_isolation_suitable(pgdat);

		/* 睡眠 */
		if (!kthread_should_stop())
			schedule();
		
		/* 被唤醒 */
		set_pgdat_percpu_threshold(pgdat, calculate_pressure_threshold);
	} else {
		if (remaining)
			count_vm_event(KSWAPD_LOW_WMARK_HIT_QUICKLY);
		else
			count_vm_event(KSWAPD_HIGH_WMARK_HIT_QUICKLY);
	}
	/* 设置kswapd的状态为TASK_RUNNING，并从pgdat->kswapd_wait这个等待队列中删除 */
	finish_wait(&pgdat->kswapd_wait, &wait);
}

/*
 * The background pageout daemon, started as a kernel thread
 * from the init process.
 *
 * This basically trickles out pages so that we have _some_
 * free memory available even if there is no other activity
 * that frees anything up. This is needed for things like routing
 * etc, where we otherwise might have all activity going on in
 * asynchronous contexts that cannot page things out.
 *
 * If there are applications that are active memory-allocators
 * (most normal use), this basically shouldn't matter.
 */
/* 页面回收线程使用的函数
 * 申请页框但缺页时会被唤醒
 */
static int kswapd(void *p)
{
	unsigned long order, new_order;
	unsigned balanced_order;
	int classzone_idx, new_classzone_idx;
	int balanced_classzone_idx;
	pg_data_t *pgdat = (pg_data_t*)p;
	struct task_struct *tsk = current;

	/* 保存本次页面回收状态 */
	struct reclaim_state reclaim_state = {
		.reclaimed_slab = 0,
	};
	/* node结点所包含的cpu的掩码 */
	const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);

	lockdep_set_current_reclaim_state(GFP_KERNEL);

	/* 如果cpumask不为空，也就是node有所属的CPU */
	if (!cpumask_empty(cpumask))
		/* 则设置此kswapd进程允许在这些CPU上运行 */
		set_cpus_allowed_ptr(tsk, cpumask);
	current->reclaim_state = &reclaim_state;

	/*
	 * Tell the memory management that we're a "memory allocator",
	 * and that if we need more memory we should get access to it
	 * regardless (see "__alloc_pages()"). "kswapd" should
	 * never get caught in the normal page freeing logic.
	 *
	 * (Kswapd normally doesn't need memory anyway, but sometimes
	 * you need a small amount of memory in order to be able to
	 * page out something else, and this flag essentially protects
	 * us from recursively trying to free more memory as we're
	 * trying to free the first piece of memory in the first place).
	 */
	tsk->flags |= PF_MEMALLOC | PF_SWAPWRITE | PF_KSWAPD;
	/* 设置当前kswapd是可冷冻的，一般内核线程是不能冷冻的，冷冻是防止休眠时破坏文件系统 */
	set_freezable();

	order = new_order = 0;
	balanced_order = 0;
	/* classzone_idx和new_classzone_idx初始化是node结点中最后一个区，用于node_zones[]数组的下标 */
	classzone_idx = new_classzone_idx = pgdat->nr_zones - 1;
	/* node中最后一个区 */
	balanced_classzone_idx = classzone_idx;
	/* 主要循环，基本上kswapd的99%运行时间都花费在里面，在这个循环中会执行 休眠->唤醒->回收内存->休眠 这样一个循环 */
	for ( ; ; ) {
		bool ret;

		/*
		 * If the last balance_pgdat was unsuccessful it's unlikely a
		 * new request of a similar or harder type will succeed soon
		 * so consider going to sleep on the basis we reclaimed at
		 */
		if (balanced_classzone_idx >= new_classzone_idx &&
					balanced_order == new_order) {
			/* 获取需要回收的页框数量的order值，这个pgdat->kswapd_max_order会在wakeup_kswapd()中设置，是待回收的页框数的order值 */
			new_order = pgdat->kswapd_max_order;
			/* 获取需要回收页框的zone分区id */
			new_classzone_idx = pgdat->classzone_idx;
			/* 重新设置node的kswapd_max_order = 0和classzone_idx = 最后一个zone */
			pgdat->kswapd_max_order =  0;
			pgdat->classzone_idx = pgdat->nr_zones - 1;
		}

		/* 第一次循环不会进入这个if 
		 * 进入这里的情况是又需要2^new_order的页框，因为order保存的是上一轮进行回收的order值，new_order保存的是又被写入到pgdat->kswapd_max_order里的值
		 * 也就是在swap回收内存的过程中，内核又需求更多的页框
		 */
		if (order < new_order || classzone_idx > new_classzone_idx) {
			/*
			 * Don't sleep if someone wants a larger 'order'
			 * allocation or has tigher zone constraints
			 */
			order = new_order;
			classzone_idx = new_classzone_idx;
		} else {
			/* 此函数会进行检查整个node的zone是否平衡，如果平衡，会睡眠，如果不平衡，则返回
			 * 如果因为内存不足而调用wakeup_kswapd()唤醒了，在wakeup_kswapd()中设置pgdat->kswapd_max_order和pgdat->classzone_idx
			 * 计算是否平衡可以看calculate_normal_threshold()函数，
			 */
			kswapd_try_to_sleep(pgdat, balanced_order,
						balanced_classzone_idx);
			/* order保存本次需要回收的页框的order数，此值会在wakeup_kswapd()中设置 */
			order = pgdat->kswapd_max_order;
			/* classzone_idx保存针对的管理区，此值会在wakeup_kswapd()中设置 */
			classzone_idx = pgdat->classzone_idx;
			new_order = order;
			new_classzone_idx = classzone_idx;
			/* 设置kswapd_max_order为0 */
			pgdat->kswapd_max_order = 0;
			/* pgdat->classzone_idx为整个node的zone */
			pgdat->classzone_idx = pgdat->nr_zones - 1;
		}

		/* 检查能否进行冷冻，在系统为suspended状态下，冷冻的进程会被挂起休眠 */
		ret = try_to_freeze();
		if (kthread_should_stop())
			break;

		/*
		 * We can speed up thawing tasks if we don't call balance_pgdat
		 * after returning from the refrigerator
		 */
		/* 确认kswapd能够进入冷冻状态，才能进行页框回收，防止过程中系统会suspended导致kswapd破坏文件系统 */
		if (!ret) {
			trace_mm_vmscan_kswapd_wake(pgdat->node_id, order);
			balanced_classzone_idx = classzone_idx;
			/* node平衡调节函数，整个kswapd中最重要的地方
			 * pgdata: 结点
			 * order: 要回收的页框order值，这个值会在wakeup_kswapd()中设置
			 * balanced_classzone_idx: 针对的管理区列表，这个值会在wakeup_kswapd()中设置
			 */
			balanced_order = balance_pgdat(pgdat, order,
						&balanced_classzone_idx);
		}
	}

	tsk->flags &= ~(PF_MEMALLOC | PF_SWAPWRITE | PF_KSWAPD);
	current->reclaim_state = NULL;
	lockdep_clear_current_reclaim_state();

	return 0;
}

/*
 * A zone is low on free memory, so wake its kswapd task to service it.
 */
/* 唤醒kswapd内核线程，只有在zone中可用页框数量低于zone的高警戒位才会唤醒 */
void wakeup_kswapd(struct zone *zone, int order, enum zone_type classzone_idx)
{
	pg_data_t *pgdat;

	if (!populated_zone(zone))
		return;

	if (!cpuset_zone_allowed_hardwall(zone, GFP_KERNEL))
		return;
	pgdat = zone->zone_pgdat;
	if (pgdat->kswapd_max_order < order) {
		pgdat->kswapd_max_order = order;
		pgdat->classzone_idx = min(pgdat->classzone_idx, classzone_idx);
	}
	/* 已处于唤醒队列，正在等待被唤醒 */
	if (!waitqueue_active(&pgdat->kswapd_wait))
		return;
	/* 检查是否平衡，如果zone的空闲页面数量高于高警戒位，则表明此zone是平衡的 */
	if (zone_balanced(zone, order, 0, 0))
		return;

	trace_mm_vmscan_wakeup_kswapd(pgdat->node_id, zone_idx(zone), order);
	wake_up_interruptible(&pgdat->kswapd_wait);
}

#ifdef CONFIG_HIBERNATION
/*
 * Try to free `nr_to_reclaim' of memory, system-wide, and return the number of
 * freed pages.
 *
 * Rather than trying to age LRUs the aim is to preserve the overall
 * LRU order by reclaiming preferentially
 * inactive > active > active referenced > active mapped
 */
unsigned long shrink_all_memory(unsigned long nr_to_reclaim)
{
	struct reclaim_state reclaim_state;
	struct scan_control sc = {
		.nr_to_reclaim = nr_to_reclaim,
		.gfp_mask = GFP_HIGHUSER_MOVABLE,
		.priority = DEF_PRIORITY,
		.may_writepage = 1,
		.may_unmap = 1,
		.may_swap = 1,
		.hibernation_mode = 1,
	};
	struct zonelist *zonelist = node_zonelist(numa_node_id(), sc.gfp_mask);
	struct task_struct *p = current;
	unsigned long nr_reclaimed;

	p->flags |= PF_MEMALLOC;
	lockdep_set_current_reclaim_state(sc.gfp_mask);
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	p->reclaim_state = NULL;
	lockdep_clear_current_reclaim_state();
	p->flags &= ~PF_MEMALLOC;

	return nr_reclaimed;
}
#endif /* CONFIG_HIBERNATION */

/* It's optimal to keep kswapds on the same CPUs as their memory, but
   not required for correctness.  So if the last cpu in a node goes
   away, we get changed to run anywhere: as the first one comes back,
   restore their cpu bindings. */
static int cpu_callback(struct notifier_block *nfb, unsigned long action,
			void *hcpu)
{
	int nid;

	if (action == CPU_ONLINE || action == CPU_ONLINE_FROZEN) {
		for_each_node_state(nid, N_MEMORY) {
			pg_data_t *pgdat = NODE_DATA(nid);
			const struct cpumask *mask;

			mask = cpumask_of_node(pgdat->node_id);

			if (cpumask_any_and(cpu_online_mask, mask) < nr_cpu_ids)
				/* One of our CPUs online: restore mask */
				set_cpus_allowed_ptr(pgdat->kswapd, mask);
		}
	}
	return NOTIFY_OK;
}

/*
 * This kswapd start function will be called by init and node-hot-add.
 * On node-hot-add, kswapd will moved to proper cpus if cpus are hot-added.
 */
int kswapd_run(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	int ret = 0;

	if (pgdat->kswapd)
		return 0;

	pgdat->kswapd = kthread_run(kswapd, pgdat, "kswapd%d", nid);
	if (IS_ERR(pgdat->kswapd)) {
		/* failure at boot is fatal */
		BUG_ON(system_state == SYSTEM_BOOTING);
		pr_err("Failed to start kswapd on node %d\n", nid);
		ret = PTR_ERR(pgdat->kswapd);
		pgdat->kswapd = NULL;
	}
	return ret;
}

/*
 * Called by memory hotplug when all memory in a node is offlined.  Caller must
 * hold mem_hotplug_begin/end().
 */
void kswapd_stop(int nid)
{
	struct task_struct *kswapd = NODE_DATA(nid)->kswapd;

	if (kswapd) {
		kthread_stop(kswapd);
		NODE_DATA(nid)->kswapd = NULL;
	}
}

static int __init kswapd_init(void)
{
	int nid;

	swap_setup();
	for_each_node_state(nid, N_MEMORY)
 		kswapd_run(nid);
	hotcpu_notifier(cpu_callback, 0);
	return 0;
}

module_init(kswapd_init)

#ifdef CONFIG_NUMA
/*
 * Zone reclaim mode
 *
 * If non-zero call zone_reclaim when the number of free pages falls below
 * the watermarks.
 */
int zone_reclaim_mode __read_mostly;

#define RECLAIM_OFF 0
#define RECLAIM_ZONE (1<<0)	/* Run shrink_inactive_list on the zone */
#define RECLAIM_WRITE (1<<1)	/* Writeout pages during reclaim */
#define RECLAIM_SWAP (1<<2)	/* Swap pages out during reclaim */

/*
 * Priority for ZONE_RECLAIM. This determines the fraction of pages
 * of a node considered for each zone_reclaim. 4 scans 1/16th of
 * a zone.
 */
#define ZONE_RECLAIM_PRIORITY 4

/*
 * Percentage of pages in a zone that must be unmapped for zone_reclaim to
 * occur.
 */
int sysctl_min_unmapped_ratio = 1;

/*
 * If the number of slab pages in a zone grows beyond this percentage then
 * slab reclaim needs to occur.
 */
int sysctl_min_slab_ratio = 5;

/* 返回zone未进行映射的文件页总数 */
static inline unsigned long zone_unmapped_file_pages(struct zone *zone)
{
	/* zone中已经映射了的文件页 */
	unsigned long file_mapped = zone_page_state(zone, NR_FILE_MAPPED);
	/* zone中在文件页lru链表中的文件页总数 */
	unsigned long file_lru = zone_page_state(zone, NR_INACTIVE_FILE) +
		zone_page_state(zone, NR_ACTIVE_FILE);

	/*
	 * It's possible for there to be more file mapped pages than
	 * accounted for by the pages on the file LRU lists because
	 * tmpfs pages accounted for as ANON can also be FILE_MAPPED
	 */
	/* 返回zone未进行映射的文件页总数 */
	return (file_lru > file_mapped) ? (file_lru - file_mapped) : 0;
}

/* Work out how many page cache pages we can reclaim in this reclaim_mode */
/* 计算此zone可以回收的文件页数量 */
static long zone_pagecache_reclaimable(struct zone *zone)
{
	long nr_pagecache_reclaimable;
	long delta = 0;

	/*
	 * If RECLAIM_SWAP is set, then all file pages are considered
	 * potentially reclaimable. Otherwise, we have to worry about
	 * pages like swapcache and zone_unmapped_file_pages() provides
	 * a better estimate
	 */
	
	if (zone_reclaim_mode & RECLAIM_SWAP)
		/* 整个zone中加入到page cache中的页数量，当匿名页加入到swapcache后，也会算入其中 */
		nr_pagecache_reclaimable = zone_page_state(zone, NR_FILE_PAGES);
	else
		/* zone回收模式中禁止了回收匿名页，则到这
	 	 * 返回zone未进行映射的文件页总数，从文件页lru链表长度获取文件页总数，而不是NR_FILE_PAGES
	 	 */
		nr_pagecache_reclaimable = zone_unmapped_file_pages(zone);

	/* If we can't clean pages, remove dirty pages from consideration */
	if (!(zone_reclaim_mode & RECLAIM_WRITE))
		/* 如果回收模式禁止将脏页回写，那么此zone所有可以回收的页要剔除此zone的脏页 */
		delta += zone_page_state(zone, NR_FILE_DIRTY);

	/* Watch for any possible underflows due to delta */
	/* 有种情况是，所有可回收的页都是脏页，这里就将delta = nr_pagecache_reclaimable
	 * 后面相减就为0，也就如果回收模式禁止将脏页回写，那么此zone可回收页的数量就是0
	 */
	if (unlikely(delta > nr_pagecache_reclaimable))
		delta = nr_pagecache_reclaimable;

	/* 返回此zone可以回收的页数量 */
	return nr_pagecache_reclaimable - delta;
}

/*
 * Try to free up some pages from this zone through reclaim.
 */
/* 从get_page_from_freelist()这个分配路径从调用到的回收内存函数 
 * 对于扫描到的非活动匿名页lru链表中的页: 可能进行回写，也可能进行unmap
 * 对于扫描到的非活动文件页lru链表中的页: 不会进行回写，可能进行unmap
 * 只回收page->_count为0的页，也就是基本上可以直接回收的页(这些页已经进行过unmap、进行过回收回写)
 * 回收到的页框数量达到 1<< order值，就返回true，否则返回false
 */
static int __zone_reclaim(struct zone *zone, gfp_t gfp_mask, unsigned int order)
{
	/* Minimum pages needed in order to stay on node */
	/* 目标回收的页框数量 */
	const unsigned long nr_pages = 1 << order;
	struct task_struct *p = current;
	struct reclaim_state reclaim_state;
	/*
	 * 由于是分配导致的回收，这里就叫做快速回收，这里将所有page->_count为0的页都进行回收
	 * 当对一个页进行回收时，会对此页进行unmap操作，然后将此页回写到磁盘中，由于在大多数内存回收的情况下，回写是异步的，也就是本次内存回收对此页提交一个回写申请，然后就返回了
	 * 之后回写完成后，块层会通过此页的PG_reclaim判断到此页是因为要回收所以才回写的，就把此页放到非活动lru链表末尾
	 * 当此页回写完成后，下次执行内存回收时，就可以发现此页的page->_count为0，直接回收此页
	 * 也就是当页为脏页时，基本上本次回收都不会回收这些页，只有这些页回写完成后，由下次内存回收进行回收
	 * 快速回收就是回收的是这些已经表明了要回收，并且已经回写完成的页，它是由前面某次内存回收处理好的页
	 */
	struct scan_control sc = {
		/* 最少一次回收SWAP_CLUSTER_MAX，最多一次回收1 << order个，应该是1024个 */
		.nr_to_reclaim = max(nr_pages, SWAP_CLUSTER_MAX),
		/* 当前进程明确禁止分配内存的IO操作(禁止__GFP_IO，__GFP_FS标志)，那么则清除__GFP_IO，__GFP_FS标志，表示不进行IO操作 */
		.gfp_mask = (gfp_mask = memalloc_noio_flags(gfp_mask)),
		.order = order,
		/* 优先级为4，默认是12，会比12一次扫描更多lru链表中的页框，而且扫描次数会比优先级为12的少，并且如果回收过程中回收到了足够页框，就会返回 */
		.priority = ZONE_RECLAIM_PRIORITY,
		/* 通过/proc/sys/vm/zone_reclaim_mode文件设置是否允许将脏页回写到磁盘，即使允许，快速内存回收页不能对脏文件页进行回写操作
		 * 当zone_reclaim_mode为0时，在这里是不允许页框回写的
		 */
		.may_writepage = !!(zone_reclaim_mode & RECLAIM_WRITE),
		/* 通过/proc/sys/vm/zone_reclaim_mode文件设置是否允许将匿名页回写到swap分区 
		 * 当zone_reclaim_mode为0时，在这里是不允许匿名页回写的
		 */
		.may_unmap = !!(zone_reclaim_mode & RECLAIM_SWAP),
		/* 允许对匿名页lru链表操作 */
		.may_swap = 1,
		/* 本结构还有一个
		 * .target_mem_cgroup 表示是针对某个memcg，还是针对整个zone进行内存回收的，这里为空，也就是说这里是针对整个zone进行内存回收的
		 */
	};
	struct shrink_control shrink = {
		.gfp_mask = sc.gfp_mask,
	};
	unsigned long nr_slab_pages0, nr_slab_pages1;

	/* 检查是否需要调度，需要则调度 */
	cond_resched();
	/*
	 * We need to be able to allocate from the reserves for RECLAIM_SWAP
	 * and we also need to be able to write out pages for RECLAIM_WRITE
	 * and RECLAIM_SWAP.
	 */
	/* 设置当前进程允许回写匿名页 */
	p->flags |= PF_MEMALLOC | PF_SWAPWRITE;
	lockdep_set_current_reclaim_state(gfp_mask);
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;

	/* 此zone可回收页数量多于min_unmapped_pages时，才对此zone进行回收 */
	if (zone_pagecache_reclaimable(zone) > zone->min_unmapped_pages) {
		/*
		 * Free memory by calling shrink zone with increasing
		 * priorities until we have enough memory freed.
		 */
		do {
			/* 对此zone进行内存回收，内存回收的主要函数 */
			shrink_zone(zone, &sc);
			/* 没有回收到足够页框，并且循环次数没达到优先级次数，继续 */
		} while (sc.nr_reclaimed < nr_pages && --sc.priority >= 0);
	}

	/* 此zone中当前可回收slab的页框数量 */
	nr_slab_pages0 = zone_page_state(zone, NR_SLAB_RECLAIMABLE);
	/* 此zone中当前可回收slab使用的页框数量多于zone允许的最小slab使用的页框数量 
	 * 内存回收同时想把zone的slab正在使用的页框数量压低，也会尝试回收nr_pages个页框
	 */
	if (nr_slab_pages0 > zone->min_slab_pages) {
		/*
		 * shrink_slab() does not currently allow us to determine how
		 * many pages were freed in this zone. So we take the current
		 * number of slab pages and shake the slab until it is reduced
		 * by the same nr_pages that we used for reclaiming unmapped
		 * pages.
		 */
		nodes_clear(shrink.nodes_to_scan);
		node_set(zone_to_nid(zone), shrink.nodes_to_scan);
		for (;;) {
			/* 获取zone能够回收的内存页框总数，也就是没有锁在内存中的匿名页和文件页之和 */
			unsigned long lru_pages = zone_reclaimable_pages(zone);

			/* No reclaimable slab or very low memory pressure */
			if (!shrink_slab(&shrink, sc.nr_scanned, lru_pages))
				break;

			/* Freed enough memory */
			nr_slab_pages1 = zone_page_state(zone,
							NR_SLAB_RECLAIMABLE);
			if (nr_slab_pages1 + nr_pages <= nr_slab_pages0)
				break;
		}

		/*
		 * Update nr_reclaimed by the number of slab pages we
		 * reclaimed from this zone.
		 */
		nr_slab_pages1 = zone_page_state(zone, NR_SLAB_RECLAIMABLE);
		/* 从slab中回收到了一点页框，加入到总回收到的页框数量中 */
		if (nr_slab_pages1 < nr_slab_pages0)
			sc.nr_reclaimed += nr_slab_pages0 - nr_slab_pages1;
	}

	p->reclaim_state = NULL;
	current->flags &= ~(PF_MEMALLOC | PF_SWAPWRITE);
	lockdep_clear_current_reclaim_state();
	return sc.nr_reclaimed >= nr_pages;
}

/* 对zone进行内存回收
 * zone: 进行内存回收的zone
 * gfp_mask: 内存分配标志
 * order: 需要回收页框数量的order值
 * 回收到了2^order数量的页框时，才会返回真，即使回收了，没达到这个数量，也返回假
 */
int zone_reclaim(struct zone *zone, gfp_t gfp_mask, unsigned int order)
{
	int node_id;
	int ret;

	/*
	 * Zone reclaim reclaims unmapped file backed pages and
	 * slab pages if we are over the defined limits.
	 *
	 * A small portion of unmapped file backed pages is needed for
	 * file I/O otherwise pages read by file I/O will be immediately
	 * thrown out if the zone is overallocated. So we do not reclaim
	 * if less than a specified percentage of the zone is used by
	 * unmapped file backed pages.
	 */
	/* zone的可回收内存数量必须要超过zone的min_unmapped_pages 
	 * 也就是所有可回收内存页进行unmap操作后，这些unmap完的可回收内存页数量都达不到min_unmapped_pages
	 * 可回收slab页数量大小也要大于min_slab_pages才能进行回收
	 */
	if (zone_pagecache_reclaimable(zone) <= zone->min_unmapped_pages &&
	    zone_page_state(zone, NR_SLAB_RECLAIMABLE) <= zone->min_slab_pages)
		return ZONE_RECLAIM_FULL;

	/* 如果此zone最近扫描的页框数量已经超过此zone可回收页框数量的6倍了
	 * 就没有必要再对进行此zone进行扫描了
	 */
	if (!zone_reclaimable(zone))
		return ZONE_RECLAIM_FULL;

	/*
	 * Do not scan if the allocation should not be delayed.
	 */
	/* 分配标志中表示禁止等待，还有进程标志中有PF_MEMALLOC的情况，则返回 */
	if (!(gfp_mask & __GFP_WAIT) || (current->flags & PF_MEMALLOC))
		return ZONE_RECLAIM_NOSCAN;

	/*
	 * Only run zone reclaim on the local zone or on zones that do not
	 * have associated processors. This will favor the local processor
	 * over remote processors and spread off node memory allocations
	 * as wide as possible.
	 */
	node_id = zone_to_nid(zone);
	if (node_state(node_id, N_CPU) && node_id != numa_node_id())
		return ZONE_RECLAIM_NOSCAN;

	/* 设置此zone正在进行内存回收的锁，主要设置zone->flags的ZONE_RECLAIM_LOCKED标志 */
	if (test_and_set_bit(ZONE_RECLAIM_LOCKED, &zone->flags))
		return ZONE_RECLAIM_NOSCAN;

	/* 进行快速内存回收 
	 * 回收到了2^order数量的页框时，才会返回真，即使回收了，没达到这个数量，也返回假
	 */
	ret = __zone_reclaim(zone, gfp_mask, order);
	/* 释放此zone正在进行内存回收的锁，清除此zone的ZONE_RECLAIM_LOCKED标志，表示此zone已经回收完成 */
	clear_bit(ZONE_RECLAIM_LOCKED, &zone->flags);

	if (!ret)
		/* 内存回收失败计数器 */
		count_vm_event(PGSCAN_ZONE_RECLAIM_FAILED);

	return ret;
}
#endif

/*
 * page_evictable - test whether a page is evictable
 * @page: the page to test
 *
 * Test whether page is evictable--i.e., should be placed on active/inactive
 * lists vs unevictable list.
 *
 * Reasons page might not be evictable:
 * (1) page's mapping marked unevictable
 * (2) page is part of an mlocked VMA
 *
 */
int page_evictable(struct page *page)
{
	return !mapping_unevictable(page_mapping(page)) && !PageMlocked(page);
}

#ifdef CONFIG_SHMEM
/**
 * check_move_unevictable_pages - check pages for evictability and move to appropriate zone lru list
 * @pages:	array of pages to check
 * @nr_pages:	number of pages to check
 *
 * Checks pages for evictability and moves them to the appropriate lru list.
 *
 * This function is only used for SysV IPC SHM_UNLOCK.
 */
void check_move_unevictable_pages(struct page **pages, int nr_pages)
{
	struct lruvec *lruvec;
	struct zone *zone = NULL;
	int pgscanned = 0;
	int pgrescued = 0;
	int i;

	for (i = 0; i < nr_pages; i++) {
		struct page *page = pages[i];
		struct zone *pagezone;

		pgscanned++;
		pagezone = page_zone(page);
		if (pagezone != zone) {
			if (zone)
				spin_unlock_irq(&zone->lru_lock);
			zone = pagezone;
			spin_lock_irq(&zone->lru_lock);
		}
		lruvec = mem_cgroup_page_lruvec(page, zone);

		if (!PageLRU(page) || !PageUnevictable(page))
			continue;

		if (page_evictable(page)) {
			enum lru_list lru = page_lru_base_type(page);

			VM_BUG_ON_PAGE(PageActive(page), page);
			ClearPageUnevictable(page);
			del_page_from_lru_list(page, lruvec, LRU_UNEVICTABLE);
			add_page_to_lru_list(page, lruvec, lru);
			pgrescued++;
		}
	}

	if (zone) {
		__count_vm_events(UNEVICTABLE_PGRESCUED, pgrescued);
		__count_vm_events(UNEVICTABLE_PGSCANNED, pgscanned);
		spin_unlock_irq(&zone->lru_lock);
	}
}
#endif /* CONFIG_SHMEM */
