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

/* ɨ����ƽṹ�������ڴ���պ��ڴ�ѹ�� */
struct scan_control {
	/* How many pages shrink_list() should reclaim */
	/* ��Ҫ���յ�ҳ������ */
	unsigned long nr_to_reclaim;

	/* This context's GFP mask */
	/* �����ڴ�ʱʹ�õķ����־ */
	gfp_t gfp_mask;

	/* Allocation order */
	/* �����ڴ�ʱʹ�õ�orderֵ����Ϊֻ�������ڴ棬Ȼ���ڴ治��ʱ�Ż����ɨ�� */
	int order;

	/*
	 * Nodemask of nodes allowed by the caller. If NULL, all nodes
	 * are scanned.
	 */
	/* ִ��ɨ���node������� */
	nodemask_t	*nodemask;

	/*
	 * The memory cgroup that hit its limit and as a result is the
	 * primary target of this reclaim invocation.
	 */
	/* Ŀ��memcg����������zone�ģ����ΪNULL */
	struct mem_cgroup *target_mem_cgroup;

	/* Scan (total_size >> priority) pages at once */
	/* ɨ�����ȼ�������һ��ɨ��(total_size >> priority)��ҳ�� 
	 * ���ȼ�Խ�ͣ�һ��ɨ���ҳ��������Խ��
	 * ���ȼ�Խ�ߣ�һ��ɨ���������Խ��
	 * Ĭ�����ȼ�Ϊ12
	 */
	int priority;

	/* �Ƿ��ܹ����л�д����(������־��__GFP_IO��__GFP_FS�й�) */
	unsigned int may_writepage:1;

	/* Can mapped pages be reclaimed? */
	/* �ܷ����unmap���������ǽ�����ӳ���˴�ҳ��ҳ������� */
	unsigned int may_unmap:1;

	/* Can pages be swapped as part of reclaim? */
	/* �Ƿ��ܹ�����swap������������ܣ���ɨ������ҳlru���� */
	unsigned int may_swap:1;

	unsigned int hibernation_mode:1;

	/* One of the zones is ready for compaction */
	/* ɨ���������ǣ������ڴ�����ж��Ƿ���Ҫ�����ڴ�ѹ�� */
	unsigned int compaction_ready:1;

	/* Incremented by the number of inactive pages that were scanned */
	/* �Ѿ�ɨ���ҳ������ */
	unsigned long nr_scanned;

	/* Number of pages freed so far during a call to shrink_zones() */
	/* �Ѿ����յ�ҳ������ */
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

/* ����zone�ܹ����յ��ڴ�ҳ��������Ҳ����û�������ڴ��е�����ҳ���ļ�ҳ֮�� */
static unsigned long zone_reclaimable_pages(struct zone *zone)
{
	int nr;

	nr = zone_page_state(zone, NR_ACTIVE_FILE) +
	     zone_page_state(zone, NR_INACTIVE_FILE);

	/* ������swap����� */
	if (get_nr_swap_pages() > 0)
		nr += zone_page_state(zone, NR_ACTIVE_ANON) +
		      zone_page_state(zone, NR_INACTIVE_ANON);

	return nr;
}

/* �ж�zone�Ƿ��ܹ������ڴ���գ��жϵı�׼�� ɨ���ҳ�� < (���пɻ���ҳ������� * 6) 
 * Ҳ�����Ѿ��Դ�zone�����пɻ���ҳ��ɨ���6���ˣ����zone���ܽ����ڴ����
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

	/* ����shrinker_list������ȡÿһ��struct shrinker�ṹ 
	 * ����һЩslabʱ����Ϊ��Щslab�ǿ���ֱ�ӻ��յģ�����˵vfsʹ�õ�struct dentry��struct inode���������struct dentry��slabʱ�������register_shrinker()����ע��һ��struct shrinker
	 * ���struct shrinker���뵽shrinker_list�У���ʾ����Щslab��ʹ������ʹ��ʱҲ���Խ��л��գ���ʹ�õĶ����ͷŵ�
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
/* �����Ի��յ�ҳ���л�д�����̣���ҳ�����жϲ����ڻ�д��Ϳ��Ի���ʱ���򲻻��ҳ���л�д 
 * �ڵ��ô�֮ǰ�����������ҳ�����Ѿ����뵽��swapcache�У������Ѿ���ҳ���й�unmap�����������п������н���ӳ���˴�ҳ
 * ����˺���ǰ��page��PG_lockһ��Ҫ��λ
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
	/* �жϴ�ҳ�Ƿ���Խ��л���
	 * ��Ҫ�жϵ���page->_count - page_has_private(page)�Ƿ�Ϊ2��page_has_private(page)ҪôΪ1ҪôΪ0��Ϊ1˵����page��buffer_head
	 * ��_countΪ3ʱ��˵����ҳ��д��ʣ�µĹ���ֻ���Ƴ�buffer_head�ʹ�address_space�Ļ������Ƴ���ҳ��������������
	 * ��_countΪ2ʱ��˵����ҳ��buffer_head������д��ҳ��ֻ��Ҫ����ҳ��address_space�Ļ������Ƴ�����ҳ�Ϳ��Ի�����
	 * ���򣬴�ҳ��Ҫ�������ڴ��У��Ͳ���Դ�ҳ���л��յ��µĻ�д��Ҳ����˵����ʹ�����ļ�ҳ��ֻҪ������ļ�ҳ���ܺܿ��ͷţ�Ҳ����������л�д
	 */
	if (!is_page_cache_freeable(page))
		return PAGE_KEEP;

	/* mappingΪ�յ������һЩ����������;��ҳ��mappingΪ�գ���־��������ҳ? */
	if (!mapping) {
		/*
		 * Some data journaling orphaned pages can have
		 * page->mapping == NULL while being dirty with clean buffers.
		 */
		/* �����ҳ�����PAGE_FLAGS_PRIVATE��˵����ҳ��buffer_head��ֱ���ͷŴ�ҳ��Ӧ��buffer_head(����ͷ������page->private��)��Ȼ���ҳ�Ϳ����ͷ��� */
		if (page_has_private(page)) {
			/* �ͷ�buffer_head����ҳ��page->_count-- */
			if (try_to_free_buffers(page)) {
				ClearPageDirty(page);
				pr_info("%s: orphaned page\n", __func__);
				return PAGE_CLEAN;
			}
		}
		return PAGE_KEEP;
	}
	/* ��ҳ��Ӧ��mapping->a_ops->writepage����Ϊ�գ�֮�󽫴�ҳ�ƶ����lru���� */
	if (mapping->a_ops->writepage == NULL)
		return PAGE_ACTIVATE;
	/* ��ҳ��Ӧ��mapping->backing_dev_info�Ƿ���� */
	if (!may_write_to_queue(mapping->backing_dev_info, sc))
		return PAGE_KEEP;

	/* ������page���з���ӳ�䣬��ӳ���˴�ҳ�Ľ���ҳ�����е�_PAGE_RW��_PAGE_DIRTY��־
	 * ���Ұ�page��PG_dirtyҲ������գ������zone��NR_FILE_DIRTY����--
	 */
	if (clear_page_dirty_for_io(page)) {
		int res;
		/* ��д���ƽṹ */
		struct writeback_control wbc = {
			/* �첽����дʱ������������д���� */
			.sync_mode = WB_SYNC_NONE,
			.nr_to_write = SWAP_CLUSTER_MAX,
			.range_start = 0,
			.range_end = LLONG_MAX,
			.for_reclaim = 1,
		};

		/* ���ô�ҳ���ڽ��л��� */
		SetPageReclaim(page);
		/* ����page���뵽���ĵȴ������У�������ļ�ҳ����дʱ����ļ�ҳ���ڻ�����PAGECACHE_TAG_WRITEBACK��־��λ����д�����PAGECACHE_TAG_WRITEBACK��־
		 * �ڴ˺����У�����λpage��PG_writeback��־��˵����ҳ���ڽ��л�д
		 * ����д��ɺ󣬻������PG_writeback��־���������PG_lock��־
		 * ��Ȼ�������첽��д��������Щ�ļ�ϵͳ�Ƚ����⣬ֻ֧��ͬ����д������Ҳ�����ͬ����д������ramdisk
		 */
		res = mapping->a_ops->writepage(page, &wbc);
		/* �������� */
		if (res < 0)
			handle_write_error(mapping, page, res);
		if (res == AOP_WRITEPAGE_ACTIVATE) {
			ClearPageReclaim(page);
			return PAGE_ACTIVATE;
		}

		/* page��PG_writebackû����λ���������������ͬ����д����writepage���������� 
		 * ��ͬ����д������£�PG_writebackû����λ˵���Ѿ���д��ɣ���ô���PG_reclaim��־
		 */
		if (!PageWriteback(page)) {
			/* synchronous write or broken a_ops? */
			/* ���ҳ��PG_reclaim���ձ�־ */
			ClearPageReclaim(page);
		}
		trace_mm_vmscan_writepage(page, trace_reclaim_flags(page));
		/* ����zone�Ļ�д���� */
		inc_zone_page_state(page, NR_VMSCAN_WRITE);
		return PAGE_SUCCESS;
	}

	/* ���ҳ������ҳ������Ҫ��д */
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
	/* page->_count�Ƿ����2������ǣ�����page->_count = 0 
	 * ���������£�������page->_count��Ϊ2
	 */
	if (!page_freeze_refs(page, 2))
		goto cannot_free;
	/* note: atomic_cmpxchg in page_freeze_refs provides the smp_rmb */
	if (unlikely(PageDirty(page))) {
		/* ��ҳΪ��ҳ�����ܽ���remove_mapping������page->_count����Ϊ2 */
		page_unfreeze_refs(page, 2);
		goto cannot_free;
	}

	if (PageSwapCache(page)) {
		swp_entry_t swap = { .val = page_private(page) };
		mem_cgroup_swapout(page, swap);
		/* ��page��swapcache��ɾ�� */
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
		/* ���ļ�ҳ�������ļ���address_space�Ļ�����ɾ�� */
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
/* ��ҳ����lru�����У������������ǰ���Ǵ�ҳ���벻����lru������ */
void putback_lru_page(struct page *page)
{
	bool is_unevictable;
	/* ��ȡ��ҳ�ǲ���unevictable��ҳ */
	int was_unevictable = PageUnevictable(page);

	VM_BUG_ON_PAGE(PageLRU(page), page);

redo:
	/* �����ҳ��������unevictable��־�������Ѿ���ȡ�˴˱�־������������������¸��ж� */
	ClearPageUnevictable(page);

	/* �����evictable�ģ�ע�������жϲ�����ͨ��ҳ��������PageUnevictable��־�����жϣ������־�������Ѿ������
	 * ͨ����ҳ��Ӧ��address_space�ʹ�ҳ��PG_mlock�����ж�
	 */
	if (page_evictable(page)) {
		/*
		 * For evictable pages, we can use the cache.
		 * In event of a race, worst case is we end up with an
		 * unevictable page on [in]active list.
		 * We know how to handle that.
		 */
		is_unevictable = false;
		/* ��ҳ���뵽lru_add���lru�����У���������е�ҳ����ԭ������lru�ϣ�׼�����뵽lru������
		 * page->_count++
		 */
		lru_cache_add(page);
	} else {
		/* ��unevictable�ģ��Ὣ��ҳ����LRU_UNEVICTABLE������������ϵ�ҳ���ܱ����� */
		/*
		 * Put unevictable pages directly on zone's unevictable
		 * list.
		 */
		is_unevictable = true;
		/* ����ҳ���뵽LRU_UNEVICTABLE */
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
	/* �����Ǽ��һ���������ҳ��������뵽���ɻ���ҳ��lru����ʱ����ҳ��״̬�����˸ı䣬��Ϊ�ɻ���ҳ�� */
	if (is_unevictable && page_evictable(page)) {
		/* ����ҳ��lru���ó���page->_count++ */
		if (!isolate_lru_page(page)) {
			/* page->_count--����isolate_lru_page()�л�����һ�Σ������ͷ�һ�� */
			put_page(page);
			/* Ȼ���ٴ����½�������lru */
			goto redo;
		}
		/* This means someone else dropped this page from LRU
		 * So, it will be freed or putback to LRU again. There is
		 * nothing to do here.
		 */
	}

	/* ͳ�� */
	if (was_unevictable && !is_unevictable)
		count_vm_event(UNEVICTABLE_PGRESCUED);
	else if (!was_unevictable && is_unevictable)
		count_vm_event(UNEVICTABLE_PGCULLED);
	/* ���ٴ�ҳ�����ü�����page->_count++ */
	put_page(page);		/* drop ref from isolate */
}

enum page_references {
	PAGEREF_RECLAIM,
	PAGEREF_RECLAIM_CLEAN,
	PAGEREF_KEEP,
	PAGEREF_ACTIVATE,
};

/* ����ҳ�ܷ���л��� */
static enum page_references page_check_references(struct page *page,
						  struct scan_control *sc)
{
	int referenced_ptes, referenced_page;
	unsigned long vm_flags;

	/* ���ش�ҳ��������ٸ����̷��ʹ���ͨ��ӳ���˴�ҳ��ҳ�����е�Accessed������жϣ���Ҫ����ӳ��
	 * ����ӳ��ʱ�����ӳ���˴�ҳ��ҳ�����Accessed��־
	 */
	referenced_ptes = page_referenced(page, 1, sc->target_mem_cgroup,
					  &vm_flags);
	/* ��ȡ��ҳ��PG_referenced������˱�־���˱�־���ڱ�־��ҳ����Ƿ񱻷��ʹ� */
	referenced_page = TestClearPageReferenced(page);

	/*
	 * Mlock lost the isolation race with us.  Let try_to_unmap()
	 * move the page to the unevictable list.
	 */
	/* vma��vm_flags����VM_LOCKED���򷵻�PAGEREF_RECLAIM��֮���Ѵ�ҳ�ƶ���lru_unevictable_page���� */
	if (vm_flags & VM_LOCKED)
		return PAGEREF_RECLAIM;

	/*
	 * ���������ҳ��ֻҪ�����ҳ�����̷��ʹ����򽫴�ҳ�ƶ����lru�����������
	 * �����ӳ���ִ���ļ����ļ�ҳ��ֻҪ��������̷��ʹ����ͷŵ��lru�����������
	 * ������������ļ�ҳ����������������̷��ʹ����ƶ����lru�������ֻ��1�����̷��ʹ�������PG_referenced��λ�ˣ�Ҳ����lru���������������
	 */

	/* ��ҳ��������̷��ʹ���ͨ��ӳ���˴�ҳ��ҳ�����е�Accessed������жϣ���Ҫ����ӳ�� */
	if (referenced_ptes) {
		/* ��ҳ��������ҳ����������ʹ������ƶ����lru���� */
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
		/* �����Ǵ�ҳ���ļ�ҳ */
		
		/* ���ô��ļ�ҳPG_referenced��־����Ϊ��ҳ��������̷��ʹ� */
		SetPageReferenced(page);

		/* 
		 * ��ҳ֮ǰ��������PG_referenced�����߷��ʹ���ҳ�Ľ��̶���1�� 
		 * �Ѵ��ļ�ҳ�ŵ��lru������
		 */
		if (referenced_page || referenced_ptes > 1)
			return PAGEREF_ACTIVATE;

		/*
		 * Activate file-backed executable pages after first usage.
		 */
		/* ��ҳ��ӳ���˿�ִ���ļ���ҳ��ҳ���뵽�lru������ */
		if (vm_flags & VM_EXEC)
			return PAGEREF_ACTIVATE;

		/* ������ԭ�����ڵ�lru�����У������Ƿǻlru����
		 * �����ڷǻlru�����ҳ������Щ�ļ�ҳ��������������ʹ�������ֻ�����ʹ�һ�ε�ҳ
		 * �ļ�ҳ֮ǰPG_referenced����λ���ٱ�����ʱ�������鵽PG_referenced�Ѿ�����λ�����ƶ�����ļ�ҳlru�������򲻶�
		 */
		return PAGEREF_KEEP;
	}

	/* Reclaim if clean, defer dirty pages to writeback */
	/* �����ҳ���ļ�ҳ�����û�����̷��ʹ�������ҳ��PG_referenced����λ���Ǿͻ���(ӳ���ִ���ļ���ҳҳ�����ڴ˻���) */
	if (referenced_page && !PageSwapBacked(page))
		return PAGEREF_RECLAIM_CLEAN;

	/* ��ҳ���л��� */
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
	/* ���ҳ�����ļ�ҳ */
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
	/* ����ļ������ļ�ϵͳ���ض�is_dirty_writeback��������ִ���ļ�ϵͳ�ض���is_dirty_writeback���� */
	if (mapping && mapping->a_ops->is_dirty_writeback)
		mapping->a_ops->is_dirty_writeback(page, dirty, writeback);
}

/*
 * shrink_page_list() returns the number of reclaimed pages
 */
/* ��page_list�е�ҳ���Ƿǻlru����ģ����Ҷ���ͬһ���͵�ҳ(ANON/FILE)
 * ע��page_list�е�ҳ��û�б���ע���л��յı�־(PG_reclaim)���������Ϊ��ҳ��ҳ(PG_dirty������)����ôֻ����kswapd���õ��˻����writeback(��д������)����
 * ��������֮ǰ������pagevec�е�ҳ���Ż���lru������
 * force_reclaim: ��ʾ�Ƿ�ǿ�ƽ��л��գ�ǿ�ƽ��л����򲻻��жϴ�ҳ�Ƿ�Ӧ�û��գ�ǿ�ƻ��յ���˼�Ǽ�ʹҳ��������ʹ��ˣ�Ҳ���л��գ�����ҳ��mlock���ڴ��У�����unmapʧ��
 * ret_nr_dirty: ��ҳ����(�������ڻ�д��û�л�д����ҳ)
 * ret_nr_unqueued_dirty: ����ҳ��û�н��л�д��ҳ
 * ret_nr_congested: ���ڽ��л�д�������豸��æ
 * ret_nr_writeback: ���ڽ��л�д�������ڻ��յ�ҳ������
 * ret_nr_immediate: ���ڽ��л�д�Ļ���ҳ������
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
	/* ��ʼ����������ͷ */
	LIST_HEAD(ret_pages);
	/* ��������汾�λ��վͿ������������ͷŵ�ҳ */
	LIST_HEAD(free_pages);
	int pgactivate = 0;
	unsigned long nr_unqueued_dirty = 0;
	unsigned long nr_dirty = 0;
	unsigned long nr_congested = 0;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_writeback = 0;
	unsigned long nr_immediate = 0;

	/* ����Ƿ���Ҫ���ȣ���Ҫ����� */
	cond_resched();

	/* ��page_list�е�ҳһ��һ���ͷ� */
	while (!list_empty(page_list)) {
		struct address_space *mapping;
		struct page *page;
		int may_enter_fs;
		enum page_references references = PAGEREF_RECLAIM_CLEAN;
		bool dirty, writeback;

		/* ����Ƿ���Ҫ���ȣ���Ҫ����� */
		cond_resched();

		/* ��page_listĩβ�ó�һ��ҳ */
		page = lru_to_page(page_list);
		/* ����ҳ��page_list��ɾ�� */
		list_del(&page->lru);

		/* ���ԶԴ�ҳ����������޷�������˵����ҳ���ڱ�����·�����ƣ���ת��keep 
		 * ��ҳ���������з��ʴ�ҳ�Ľ��̶�����뵽zone->wait_table[hash_ptr(page, zone->wait_table_bits)]
		 */
		if (!trylock_page(page))
			goto keep;

		/* ��page_list��ҳһ�����Ƿǻ�� */
		VM_BUG_ON_PAGE(PageActive(page), page);
		/* ҳ������zoneҲҪ�봫���zoneһ�� */
		VM_BUG_ON_PAGE(page_zone(page) != zone, page);

		/* ɨ���ҳ����++ */
		sc->nr_scanned++;

		/* �����ҳ�������ڴ��У�����ת��cull_mlocked */	
		if (unlikely(!page_evictable(page)))
			goto cull_mlocked;

		/* ���ɨ����ƽṹ�б�ʶ���������unmap���������Ҵ�ҳ�б�ӳ�䵽ҳ���У���ת��keep_locked */
		if (!sc->may_unmap && page_mapped(page))
			goto keep_locked;

		/* Double the slab pressure for mapped and swapcache pages */
		/* ���ڴ���swapcache�л����н���ӳ���˵�ҳ����sc->nr_scanned�ٽ���һ��++
		 * swapcache������ҳ������swapʱ��ҳ�����ܵ�swapcache�У�����ҳ��ȫд��swap��������û�н��̶Դ�ҳ���з���ʱ��swapcache�Ż��ͷŵ���ҳ 
		 * ��������Ϊ����sc->nr_scanned���ӵø���?
		 */
		if (page_mapped(page) || PageSwapCache(page))
			sc->nr_scanned++;

		/* ���λ����Ƿ�����ִ��IO���� */
		may_enter_fs = (sc->gfp_mask & __GFP_FS) ||
			(PageSwapCache(page) && (sc->gfp_mask & __GFP_IO));

		/*
		 * The number of dirty pages determines if a zone is marked
		 * reclaim_congested which affects wait_iff_congested. kswapd
		 * will stall and start writing pages if the tail of the LRU
		 * is all dirty unqueued pages.
		 */
		/* ����Ƿ�����ҳ���д�ҳ�Ƿ����ڻ�д������ 
		 * ��������Ҫ�ж�ҳ��������PG_dirty��PG_writeback������־
		 * ����ҳ������swapcache�󣬾ͻᱻ���PG_dirty
		 * ����ļ������ļ�ϵͳ���ض�is_dirty_writeback��������ִ���ļ�ϵͳ�ض���is_dirty_writeback����
		 */
		page_check_dirty_writeback(page, &dirty, &writeback);
		/* �������ҳ�������ڻ�д��ҳ����ҳ����++ */
		if (dirty || writeback)
			nr_dirty++;

		/* ����ҳ����û�����ڻ�д��������û�н��л�д����ҳ���� */
		if (dirty && !writeback)
			nr_unqueued_dirty++;

		/*
		 * Treat this page as congested if the underlying BDI is or if
		 * pages are cycling through the LRU so quickly that the
		 * pages marked for immediate reclaim are making it to the
		 * end of the LRU a second time.
		 */
		/* ��ȡ��ҳ��Ӧ��address_space�������ҳ������ҳ����ΪNULL */
		mapping = page_mapping(page);
		/* �����ҳӳ����ļ����ڵĴ����豸�ȴ�������������(���ڽ���IO����)���ߴ�ҳ�Ѿ��ڽ��л�д���� */
		if ((mapping && bdi_write_congested(mapping->backing_dev_info)) ||
		    (writeback && PageReclaim(page)))
		    /* ���ܱȽ�����ܽ���������д��ҳ������ 
		 	 * ��Ϊ�����豸���ڷ�æ����������̫����Ҫд�������
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
		/* ��ҳ���ڽ��л�д�����̣��������ڻ�д�����̵�ҳ�����޷����л��յģ����ǵȴ���ҳ��д��� 
		 * ��ҳ���ڽ��л�д���������:
		 * 1.��ҳ�������Ľ��л�д(��̫����)
		 * 2.��ҳ�Ǹղ���ǰ�����ڴ����ʱ�����´�ҳ���л�д��
		 */
		if (PageWriteback(page)) {
			/* Case 1 above */

			/* ������ж϶��ǻ��ڴ�ҳ���ڽ��л�д������Ϊǰ�� */

			/* ��ǰ����kswapd�ں˽��̣����Ҵ�ҳ���ڽ��л���(�����ڵȴ�IO)��Ȼ��zoneҲ�����˺ܶ�ҳ���ڽ��л�д 
			 * ˵����ҳ���Ѿ��ڻ�д�����̣�����Ҳ���ڽ��л��յģ����λ��ղ���Ҫ�Դ�ҳ���л���
			 */
			if (current_is_kswapd() &&
			    PageReclaim(page) &&
			    test_bit(ZONE_WRITEBACK, &zone->flags)) {
			    /* ����nr_immediate�������˼���˵����ҳ׼���Ϳ��Ի����� */
				nr_immediate++;
				/* ��ת��keep_locked */
				goto keep_locked;

			/* Case 2 above */
			/* ��ҳ���ڽ��������Ļ�д(������ΪҪ���մ�ҳ�Ž��еĻ�д)
			 * ����������������:
			 * 1.�������������zone�����ڴ���յ�
			 * 2.���λ��ղ��������IO����
			 * ��ô�ͱ�����ҳҪ���գ����λ��ղ��Դ�ҳ���л��գ�����ҳ��д��ɺ󣬻��ж����PG_reclaim��ǣ������λ�ˣ��Ѵ�ҳ�ŵ��ǻlru����ĩβ
			 * ���ٻ��ջ�����������
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
				/* ���ô�ҳ���ڽ��л��գ���Ϊ��ҳ���ڽ��л�д�������ó�Ϊ���л��պ󣬻�д��ɺ��ҳ�ᱻ�ŵ��ǻlru����ĩβ */
				SetPageReclaim(page);
				/* ������Ҫ��д������ */
				nr_writeback++;

				goto keep_locked;

			/* Case 3 above */
			} else {
				/* �ȴ���ҳ��д��ɣ���д��ɺ󣬳��ԶԴ�ҳ���л��գ�Ӧ��ֻ�����ĳ��memcg���л���ʱ�Ż������ */
				wait_on_page_writeback(page);
			}
		}

		/*
		 * �˴λ���ʱ��ǿ�ƽ��л��գ���Ҫ���жϴ�ҳ�費��Ҫ�ƶ����lru����
		 * ���������ҳ��ֻҪ�����ҳ�����̷��ʹ����򽫴�ҳ�ƶ����lru����ͷ�����������
		 * �����ӳ���ִ���ļ����ļ�ҳ��ֻҪ��������̷��ʹ����ͷŵ��lru�����������
		 * ������������ļ�ҳ����������������̷��ʹ����ƶ����lru�������ֻ��1�����̷��ʹ�������PG_referenced��λ�ˣ�Ҳ����lru���������������
		 */
		if (!force_reclaim)
			references = page_check_references(page, sc);

		/* ���˴λ���ʱ��ǿ�ƽ��л���ʱ */
		switch (references) {
		/* ��ҳ�ŵ��lru������ */
		case PAGEREF_ACTIVATE:
			goto activate_locked;
		/* ҳ���������ڷǻlru������ */
		case PAGEREF_KEEP:
			goto keep_locked;

		/* ������������Ĵ��붼�᳢�Ի��մ�ҳ 
		 * ע��ҳ������vma�����VM_LOCKEDʱҲ����PAGEREF_RECLAIM����Ϊ�����Ҫ�Ѵ�ҳ�ŵ�lru_unevictable_page����
		 */
		case PAGEREF_RECLAIM:
		case PAGEREF_RECLAIM_CLEAN:
			; /* try to reclaim the page below */
		}

		/*
		 * Anonymous process memory has backing store?
		 * Try to allocate it some swap space here.
		 */
		/* pageΪ����ҳ�������ֲ�����swapcache�У�����᳢�Խ�����뵽swapcache�У����swapcache��Ϊswap������ 
		 * ��ҳ����������ʱ�����ȼ��뵽swapcache������ȫ����������ȫ����ʱ���Ż��swapcache���Ƴ�
		 * ���˴�swapcache����һ��ҳ���л���ʱ��һ�����̷��ʴ�ҳ������ֱ�Ӵ�swapcache�л�ȡ��ҳ��ӳ�䣬Ȼ��swapcache��ֹ��ҳ�Ļ��������������Ͳ��õ�ҳҪ��ȫ�����������»�����
		 */
		if (PageAnon(page) && !PageSwapCache(page)) {
			/* ������λ��ս�ֹio����������ת��keep_locked���ô�����ҳ�����ڷǻlru������ */
			if (!(sc->gfp_mask & __GFP_IO))
				goto keep_locked;
			/* ��ҳpage���뵽swap_cache��Ȼ�����ҳ����Ϊ�ļ�ҳ����ʼ���ǽ�ҳ��������Ϣ���浽��swapҳ��ƫ����Ϊ�����Ľ��
 			 * ����ҳ��������private = swapҳ��ƫ�������ɵ�ҳ����swp_entry_t����Ϊ�������������ӳ���˴�ҳ��ҳ����Ϊ��swp_entry_t
 			 * ����ҳ��PG_swapcache��־��������ҳ��swapcache�У����ڱ�����
  			 * ���ҳpageΪ��ҳ(PG_dirty)������ͻᱻ����
 			 */
 			 /* ִ�гɹ���ҳ����swapcache�����Ҵ�ҳ��page->_count��++�������������ô�ҳ�Ľ���ҳ��û�����ã����̻��ǿ��������������ҳ */
			if (!add_to_swap(page, page_list))
				/* ʧ�ܣ�����ҳ���뵽�lru������ */
				goto activate_locked;
			/* ���ÿ��ܻ��õ��ļ�ϵͳ��صĲ��� */
			may_enter_fs = 1;

			/* Adding to swap updated mapping */
			/* ��ȡ������ҳ���ڵ�swapcache��address_space������Ǹ���page->private�б����swp_entry_t��� */
			mapping = page_mapping(page);
		}

		/*
		 * The page is mapped into the page tables of one or more
		 * processes. Try to unmap it here.
		 */
		/* ������Ҫ������ӳ���˴�page��ҳ���������
		 * ����ҳ��Ѷ�Ӧ��ҳ��������Ϊ֮ǰ��ȡ��swp_entry_t
		 */
		if (page_mapped(page) && mapping) {
			/* ������ӳ���˴�ҳ�Ľ��̵�ҳ����д�ҳ��unmap����
			 * ttu_flags��������TTU_UNMAP��־
			 * ���������ҳ����ôpage->private����һ������swapҳ��ƫ������swp_entry_t���˺����swp_entry_t����תΪҳ����
			 * ִ����˺�����ҳ��swapcache�У������������˴�ҳ�Ľ��̶��ԣ���ҳ�Ѿ���swap��
			 * ���ǵ�������ҳ��û����ȫд��swap��ʱ�������ʱ�н��̷��ʴ�ҳ���Ὣ��ҳӳ�䵽�˽���ҳ���У���ȡ����ҳ����swap�еĲ������Ż�����ҳ��lru����(��ȱҳ�ж������)
			 * �������ļ�ҳ��ֻ��Ҫ���ӳ���˴�ҳ�Ľ���ҳ���ҳ�������Ҫ�����µ�ҳ����
			 * ÿһ������unmap��ҳ����ҳ��page->_count--
			 * �������ӳ�������page->_count == 0�����ͷŴ�ҳ
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

		/* ���ҳΪ��ҳ��������ҳ
		 * һ���ǵ�����ҳ���뵽swapcache��ʱ���ͱ����Ϊ����ҳ
		 * һ��������ļ�ҳ
		 */
		if (PageDirty(page)) {
			/*
			 * Only kswapd can writeback filesystem pages to
			 * avoid risk of stack overflow but only writeback
			 * if many dirty pages have been encountered.
			 */
			/* ֻ��kswapd�ں��߳��ܹ������ļ�ҳ�Ļ�д����(kswapd�в������ջ���?)������ֻ�е�zone���кܶ���ҳʱ��kswapdҲ���ܽ������ļ�ҳ�Ļ�д
			 * �˱��˵��zone����ҳ�ܶ࣬�ڻ���ʱ���������ҳ����û�н��л�д����ҳʱ����
			 * Ҳ���Ǵ�zone��ҳ�����࣬kswapd���ý��л�д����
			 * ����ʱ���ڶ�ζԴ�zoneִ���ڴ���պ����ZONE_DIRTY�ͻᱻ���ã���������������: ���Ȼ�������ҳ�͸ɾ����ļ�ҳ��˵������������Щzone�п����ڴ���㹻�ˣ�����Ҫ�ٽ����ڴ������
			 * ����������ҳ�������Ƿ���kswapd�����Խ��л�д
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
				/* �������Ȼ���ҳ������ */
				inc_zone_page_state(page, NR_VMSCAN_IMMEDIATE);
				/* ���ô�ҳ��Ҫ���գ���������ҳ��д��ɺ󣬾ͻᱻ���뵽�ǻlru����β�� 
				 * ������ϧ����ֻ�ܵ�kswapd�ں��̶߳Դ�ҳ���л�д��Ҫô�͵�ϵͳ���ں��Զ�����ҳ���л�д����kswapd�̶߳����ܶ��ļ�ҳ���л�д
				 */
				SetPageReclaim(page);

				/* ��ҳ�ƶ����ǻlru����ͷ����������˵������д��ɺ�ҳ�ᱻ�ƶ����ǻlru����β�������ڴ�����Ǵӷǻlru����β����ҳ�������յ� */
				goto keep_locked;
			}

			/* ��zoneû�б��ZONE_DIRTYʱ��kswapd�ں��߳����ִ�е����� */
			/* ��page_check_references()��ȡҳ��״̬��PAGEREF_RECLAIM_CLEAN��������keep_locked
			 * ҳ���û�����̷��ʹ�������ҳ��PG_referenced����λ
			 */
			if (references == PAGEREF_RECLAIM_CLEAN)
				goto keep_locked;
			/* ���ղ�����ִ���ļ�ϵͳ��ز���������ҳ�ƶ����ǻlru����ͷ�� */
			if (!may_enter_fs)
				goto keep_locked;
			/* ���ղ�������л�д������ҳ�ƶ����ǻlru����ͷ�� */
			if (!sc->may_writepage)
				goto keep_locked;

			/* Page is dirty, try to write it out here */
			/* ��ҳ���л�д�����̣�����ֻ�ǽ�ҳ���뵽��㣬���ý��������Ǵ����ҳ�Ѿ���д���
			 * ��Ҫ����page->mapping->a_ops->writepage���л�д����������ҳ��Ҳ��swapcache��address_space->a_ops->writepage
			 * ҳ�����뵽����д���к󣬻���λҳ��PG_writeback����д��ɺ����PG_writebackλ��������ͬ��ģʽ��д�£�������PG_writebackλ��0�ģ����첽ģʽ�£�PG_writeback�ܿ���Ϊ1
			 * �˺����л����ҳ��PG_dirty��־
			 * ����ҳ��PG_reclaim
			 * �ɹ���ҳ���뵽����ҳ��PG_lockλ�����
			 * Ҳ������һ��ҳ�ɹ����뵽���յ��µĻ�д�����У�����PG_writeback��PG_reclaim��־����λ��������PG_dirty��PG_lock��־�����
			 * ����ҳ�ɹ���д������PG_writeback��PG_reclaimλ���ᱻ���
			 */
			switch (pageout(page, mapping, sc)) {
			case PAGE_KEEP:
				/* ҳ�ᱻ�ƶ����ǻlru����ͷ�� */
				goto keep_locked;
			case PAGE_ACTIVATE:
				/* ҳ�ᱻ�ƶ����lru���� */
				goto activate_locked;
			case PAGE_SUCCESS:
				/* �����ҳ�����Ѿ����ͷţ�Ҳ����PG_lock����� 
				 * ����ͬ����д(һЩ�����ļ�ϵͳֻ֧��ͬ����д)�������PG_writeback��PG_reclaim��PG_dirty��PG_lock��־������0��
				 * �����첽��д��PG_dirty��PG_lock��־����Ϊ0��PG_writeback��PG_reclaim����Ϊ1����Ϊ0(��д���Ϊ0������Ϊ1)
				 */

				/* ���PG_writeback����λ��˵����ҳ���ڽ��л�д������������첽�Żᷢ�� */
				if (PageWriteback(page))
					goto keep;
				
				/* ��ҳΪ��ҳ��������������ڴ�ҳ����ֱ�д���ˣ����䱣���ڷǻlru������ 
				 * ����һ���������������ҳ���뵽swapcacheǰ���Ѿ�û�н���ӳ�������ҳ�ˣ�������swapcacheʱ�����ж�
				 * ���ǵ��Դ�����ҳ���л�дʱ�����жϴ�ҳ����swapcacheǰ�Ƿ��н���ӳ���ˣ����û�У���ҳ����ֱ���ͷţ�����Ҫд�����
				 * �����ڴ�����ҳ��д�����У��ͻὫ��ҳ��swap������address_space�еĻ����ó�����Ȼ����Ϊ��ҳ��������ͻ�����ж���ҳ��֮����ͷŵ���ҳ
				 */
				if (PageDirty(page))
					goto keep;

				/*
				 * A synchronous write - probably a ramdisk.  Go
				 * ahead and try to reclaim the page.
				 */
				/* ������������Ϊ��pageout�л��ͷ�page��������Ҫ��PG_lock��־ */
				if (!trylock_page(page))
					goto keep;
				if (PageDirty(page) || PageWriteback(page))
					goto keep_locked;
				/* ��ȡpage->mapping */
				mapping = page_mapping(page);

			/* ���ҳ������ҳ������Ҫ��д���������ֻ�������ļ�ҳ������ҳ�����뵽swapcache��ʱ�ͱ�����Ϊ��ҳ */
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

		/* ��������ֻ��ҳ�Ѿ���ɻ�д��Żᵽ���������ͬ����дʱ(pageout��ҳ��д��ɺ�ŷ���)���첽��дʱ�������е���֮ǰ�Ѿ���ҳ��д������
		 * û����ɻ�д��ҳ���ᵽ�����pageout()�������keep��
		 */
		
		/* ͨ��ҳ��������PAGE_FLAGS_PRIVATE����ж��Ƿ���buffer_head�����ֻ���ļ�ҳ��
		 * ���ﲻ��ͨ��page->private�жϣ�ԭ���ǣ�������ҳ���뵽swapcacheʱ��Ҳ��ʹ��page->private����������PAGE_FLAGS_PRIVATE
		 * ֻ���ļ�ҳ��ʹ�����PAGE_FLAGS_PRIVATE��������˵�����ļ�ҳ��page->privateָ��struct buffer_head����ͷ
		 */
		if (page_has_private(page)) {
			/* ��Ϊҳ�Ѿ���д��ɻ����Ǹɾ�����Ҫ��д��ҳ���ͷ�page->privateָ��struct buffer_head�����ͷź�page->private = NULL 
			 * �ͷ�ʱ����Ҫ��֤��ҳ��PG_writebackλΪ0��Ҳ���Ǵ�ҳ�Ѿ���д����������
			 */
			if (!try_to_release_page(page, sc->gfp_mask))
				/* �ͷ�ʧ�ܣ��Ѵ�ҳ�ƶ����lru���� */
				goto activate_locked;

			/* һЩ�����ҳ��mappingΪ�գ�����һЩ��־�Ļ�������������Щҳ������ü���Ϊ1����д��� */
			if (!mapping && page_count(page) == 1) {
				/* �Դ�ҳ���������PG_lock */
				unlock_page(page);
				/* ��page->_count--�����ж��Ƿ�Ϊ0�����Ϊ0���ͷŵ���ҳ */
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

					/* ���ﲻ̫���ף������˼����Щҳ���Ͼͻ��������ط����ͷ��ˣ�������������ҳ */
					
					nr_reclaimed++;
					continue;
				}
			}
		}

		/* 
		 * ��������Ĳ��裬��û�н����ٶԴ�ҳ���з��ʵ�ǰ���£�page->_countӦ��Ϊ2
		 * ��ʾֻ�н���ҳ�����lru������ͼ���address_space�Ļ����жԴ�ҳ���������ã��Ѿ�û�������ط��Դ�ҳ�������ã�
		 * Ȼ�󽫴�ҳ��address_space�Ļ������Ƴ���Ȼ��page->_count - 2�����ҳ���ھ�ֻʣ�ȴ��ű��ͷŵ���
		 * ���������ҳ�����Ƕ�Ӧ��swapcache��address_space�Ļ���
		 * ������ļ�ҳ�����Ƕ�Ӧ�ļ���address_space�Ļ���
		 * ��page->_countΪ2ʱ���ŻὫ��ҳ��address_space�Ļ������Ƴ���Ȼ����page->_count - 2
		 * �෴�������page->_count��Ϊ2��˵��unmap�����н��̷����˴�ҳ���Ͳ��Դ�ҳ�����ͷ���
		 * ͬʱ�����������ҳҲ���ܹ������ͷţ�����һ�£����һ�����̷����˴�ҳ��д�����ݣ���unmap��ҳ����ô��ҳ��page->_countΪ2��ͬ��Ҳ�����ͷŵ�������д������ݾͶ�ʧ��
		 * �ɹ�����1��ʧ�ܷ���0
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
		/* �ͷ�page�� */
		__clear_page_locked(page);
free_it:
		/* page->_countΪ0�Żᵽ�� */
		
		/* ��ҳ�������ϻ��գ���������뵽free_pages����
		 * �������ҳ��������������ν���ͬ����д��ҳ���ɾ��Ĳ���Ҫ��д��ҳ��֮ǰ�첽����ʱ����첽��д��ҳ
		 * ֮ǰ���ս����첽��д��ҳ�����������ͷţ���Ϊ�ϴλ���ʱ������Щҳ���еĹ�����: 
		 * ����ҳ: ����swapcache������ӳ���޸���ӳ���˴�ҳ�Ľ���ҳ�����������ҳ��д�����̣�����ҳ���浽�ǻ����ҳlru����β��
		 * �ļ�ҳ: ����ӳ���޸���ӳ���˴�ҳ�Ľ���ҳ��������ļ�ҳ��д�����̣�����ҳ���浽�ǻ�ļ�ҳlru����β��
		 * Ҳ�����첽���������ҳ��û�н���ʵ�ʵĻ��գ�������Щҳ��д��ɺ��ٽ��л���ʱ��������ҳ�����̶��ᵽ������л���
		 * Ҳ���Ǳ����ܹ��������յ���ҳ��������֮ǰ���л���ʱ�Ѿ�����ò�ಢ��д��ɵ�ҳ
		 */
		
		/* ����ҳ����++ */
		nr_reclaimed++;

		/*
		 * Is there need to periodically free_page_list? It would
		 * appear not as the counts should be low
		 */
		/* ���뵽free_pages���� */
		list_add(&page->lru, &free_pages);
		/* ��������ҳ */
		continue;

cull_mlocked:
		/* ��ǰҳ��mlock�����ڴ��е���� */

		/* ��ҳΪ����ҳ�����Ѿ�������swapcache���� */
		if (PageSwapCache(page))
			/* ��swapcache���ͷű�ҳ�ڻ����Ľ�㣬��page->_count-- */
			try_to_free_swap(page);
		
		unlock_page(page);
		/* �Ѵ�ҳ�Żص�lru�����У���Ϊ��ҳ�Ѿ������������
		 * ����ɻ���lru�����page->_count++����ͬʱҲ���ͷŸ����page->_count--
		 * ����unevictablelru�������page->_count++
		 */
		putback_lru_page(page);
		continue;

activate_locked:
		/* Not a candidate for swapping, so reclaim swap space. */
		/* �����ǳ���ҳ��(PG_lock)��������Ҫ��ҳ�ƶ����lru�����е���� */

		/* �����ҳΪ����ҳ���ҷ�����swapcache�У�����swapʹ�����Ѿ�������50% */
		if (PageSwapCache(page) && vm_swap_full())
			/* ����ҳ��swapcache�Ļ������ó��� */
			try_to_free_swap(page);
		VM_BUG_ON_PAGE(PageActive(page), page)
		/* ���ô�ҳΪ�ҳ */;
		SetPageActive(page);
		/* ��Ҫ�Żص��lru�����ҳ���� */
		pgactivate++;
keep_locked:
		/* ϣ��ҳ������ԭ����lru�����У����ҳ���ҳ������� */

		/* �ͷ�ҳ��(PG_lock) */
		unlock_page(page);
keep:
		/* ϣ��ҳ������ԭ����lru�����е���� */

		/* ��ҳ���뵽ret_pages������ */
		list_add(&page->lru, &ret_pages);
		VM_BUG_ON_PAGE(PageLRU(page) || PageUnevictable(page), page);
	}

	mem_cgroup_uncharge_list(&free_pages);
	/* ��free_pages�е�ҳ�ͷ� */
	free_hot_cold_page_list(&free_pages, true);

	/* ��ret_pages������뵽page_list�� */
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
/* ��page��lru���ó���������������������������������PageLRU��־����û��ʵ�ʶ�����lru���ó���ҳ 
 * ����0: ��ʾ��ҳ�ɹ���lru�������ó���
 * ���򷵻ش�����Ϣ
 */
int __isolate_lru_page(struct page *page, isolate_mode_t mode)
{
	int ret = -EINVAL;

	/* Only take pages on the LRU. */
	/* ��ҳ������lru�� */
	if (!PageLRU(page))
		return ret;

	/* Compaction should not handle unevictable pages but CMA can do so */
	/* ��ǰmode��ʾ�����������ڴ��е�ҳ�����Ҵ�ҳ�������ڴ��� */
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
		/* ���ҳ���ڻ�д���򲻴���ֱ�ӷ��� */
		if (PageWriteback(page))
			return ret;

		/* ��ҳΪ��ҳ��������ҳ�����뵽swapcacheʱ�ͻᱻ���Ϊ��ҳ */
		if (PageDirty(page)) {
			struct address_space *mapping;

			/* ISOLATE_CLEAN means only clean pages */
			/* mode��Ҫ��ֻ����ɾ���ҳ��ֱ�ӷ��� */
			if (mode & ISOLATE_CLEAN)
				return ret;

			/*
			 * Only pages without mappings or that have a
			 * ->migratepage callback are possible to migrate
			 * without blocking
			 */
			/* ��ȡ��ҳ��Ӧ��address_space�ṹ���ṹָ��ṹ���migratepage��������
			 * �������ҳ��swap cache�migratepage����Ϊswap_aops->migrate_page
			 */
			mapping = page_mapping(page);
			if (mapping && !mapping->a_ops->migratepage)
				return ret;
		}
	}

	/* Ҫ�����û�б�ӳ���ҳ������ҳ�Ѿ���ӳ��(page->_mapcount >= 0)���򷵻ش��� */
	if ((mode & ISOLATE_UNMAPPED) && page_mapped(page))
		return ret;

	/* ����page->_countΪ0������page->_count++ */
	if (likely(get_page_unless_zero(page))) {
		/*
		 * Be careful not to clear PageLRU until after we're
		 * sure the page is not being freed elsewhere -- the
		 * page release code relies on it.
		 */
		/* �����ҳ��lru�ı�־����Ϊ��ҳ�����Ѿ���lru�������ó����� */
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
/* ��lruvec�е�lru���͵�lru�����ȡҳ����lru����β��ʼ�ã�Ȼ�����dst������
 * ���ô˺���ǰ�����lruvec����
 */
static unsigned long isolate_lru_pages(unsigned long nr_to_scan,
		struct lruvec *lruvec, struct list_head *dst,
		unsigned long *nr_scanned, struct scan_control *sc,
		isolate_mode_t mode, enum lru_list lru)
{
	/* ��ȡlruvec��lru���͵�����ͷ */
	struct list_head *src = &lruvec->lists[lru];
	/* ��ȡ����ҳ������ */
	unsigned long nr_taken = 0;
	unsigned long scan;

	/* ɨ��nr_to_scan�Σ�Ĭ����32 */
	for (scan = 0; scan < nr_to_scan && !list_empty(src); scan++) {
		struct page *page;
		int nr_pages;

		/* ��ȡlru�����е����һҳ(src->prev)������û�д�lru��ɾ����page */
		page = lru_to_page(src);
		prefetchw_prev_lru_page(page, src, flags);

		/* ��ҳ������lru�� */
		VM_BUG_ON_PAGE(!PageLRU(page), page);

		/* ��page��lru���ó�����__isolate_lru_page�������page�������������޸Ĺ�����������ҳ�Ѳ���lru�У���û��ʵ�ʴ�lru���ó�����ʵ���ó����ں����list_move
		 * ���������ҳ��page->_count++
		 */
		switch (__isolate_lru_page(page, mode)) {
		case 0:
			/* �����͸����ҳ��ֻ��ͷpage�ᱻ���뵽lru���������͸����ҳ���˶��ٸ�page������ǳ���ҳ��Ϊ1 */
			nr_pages = hpage_nr_pages(page);
			/* ����memcg��lru�����е�ҳ������(ֻ�п�����memcg�Ż���memcg�и���) */
			mem_cgroup_update_lru_size(lruvec, lru, -nr_pages);
			/* �ӵ�ǰlru������ɾ�������뵽dst������ */
			list_move(&page->lru, dst);
			/* ���»�ȡ����ҳ������ */
			nr_taken += nr_pages;
			break;

		case -EBUSY:
			/* else it is being freed elsewhere */
			/* �Ż�src���lru������ */
			list_move(&page->lru, src);
			continue;

		default:
			BUG();
		}
	}

	/* �ܹ�ɨ���ҳ���� */
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
/* ��page��lru���ó��� */
int isolate_lru_page(struct page *page)
{
	int ret = -EBUSY;

	/* ��ҳ�����ü����������0 */
	VM_BUG_ON_PAGE(!page_count(page), page);

	if (PageLRU(page)) {
		/* ҳ���ڵĹ����� */
		struct zone *zone = page_zone(page);
		struct lruvec *lruvec;

		spin_lock_irq(&zone->lru_lock);
		/* ���ݹ�������ȡ��������lru���� */
		lruvec = mem_cgroup_page_lruvec(page, zone);
		if (PageLRU(page)) {
			/* ��ȡ��ҳӦ�÷��õ�lru��������� */
			int lru = page_lru(page);
			/* ���Ӵ�ҳ�����ü��� */
			get_page(page);
			/* �����ҳ��lru�ı�־ */
			ClearPageLRU(page);
			/* ����ҳ��lru�ó��� */
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
/* ��������ҳ�������ڷǻ��ҳ���������Ǹ���̫��ҳ�� */
static int too_many_isolated(struct zone *zone, int file,
		struct scan_control *sc)
{
	unsigned long inactive, isolated;

	/* �������kswapd�ں��߳��е��õ��ˣ���ֱ�ӷ���0 */
	if (current_is_kswapd())
		return 0;

	/* ��������������zone���������ĳ��memcg�ģ�Ҳ���� */
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
	/* ���gfp_mask�б����GFP_NOIO/GFP_NOFS����������������������ȴ������������IO���������������������ҳ */
	if ((sc->gfp_mask & GFP_IOFS) == GFP_IOFS)
		inactive >>= 3;

	/* ��������ҳ�������ڷǻ��ҳ���������Ǹ���̫��ҳ�� */
	return isolated > inactive;
}

/* ��page_list�е�ҳ�Żص���Ӧ���͵ķǻlru������ */
static noinline_for_stack void
putback_inactive_pages(struct lruvec *lruvec, struct list_head *page_list)
{
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	/* lruvec��Ӧ��zone */
	struct zone *zone = lruvec_zone(lruvec);
	/* ��ʼ��һ������pages_to_free������ͷ */
	LIST_HEAD(pages_to_free);

	/*
	 * Put back any unfreeable pages.
	 */
	/* ���page_list����Ϊ�� */
	while (!list_empty(page_list)) {
		/* ��page_list����β���л�ȡһ��ҳ */
		struct page *page = lru_to_page(page_list);
		int lru;

		/* ҳ��Ӧ�ô���lru�� */
		VM_BUG_ON_PAGE(PageLRU(page), page);
		/* ����ҳ��page_list��ɾ�� */
		list_del(&page->lru);
		/* �����ҳ����Ҫ�̶����ڴ��е� */
		if (unlikely(!page_evictable(page))) {
			spin_unlock_irq(&zone->lru_lock);
			/* �����ͨ��PageUnevictable(page)�жϳ���ҳ��unevictable�ģ�����ҳ�Ż�unevictable���͵�lru������ 
			 * ��page->_count--
			 */
			putback_lru_page(page);
			spin_lock_irq(&zone->lru_lock);
			continue;
		}

		lruvec = mem_cgroup_page_lruvec(page, zone);

		SetPageLRU(page);
		/* ��ȡҳ�����ͣ�anon����file */
		lru = page_lru(page);
		/* ��ҳ���뵽��Ӧ���͵�lru����ͷ�� */
		add_page_to_lru_list(page, lruvec, lru);

		/* �����ҳ�ǻҳ�������п��ܵģ������ҳ������CPU����ȹ����б������� */
		if (is_active_lru(lru)) {
			/* ��ȡ��ҳ�����ͣ��ļ�ҳ��������ҳ */
			int file = is_file_lru(lru);
			/* ��ҳ�����ҳ��������ҳ��������Ƕ��ٸ���ͨҳ����ͨҳ��ʱ��Ϊ1 */
			int numpages = hpage_nr_pages(page);
			/* ͳ�Ƶ�lruvec��recent_rotated�� */
			reclaim_stat->recent_rotated[file] += numpages;
		}
		
		/* ��page->_count--�����ж��Ƿ�Ϊ0�����Ϊ0��˵����ҳû�б��κν������� */
		if (put_page_testzero(page)) {
			/* �����ҳ��PG_lru��־��˵����ҳ����lru�� */
			__ClearPageLRU(page);
			/* �����ҳ��PG_active��־��˵����ҳ���ǻ�� */
			__ClearPageActive(page);
			/* ����ҳ��lru������ɾ�� */
			del_page_from_lru_list(page, lruvec, lru);

			/* ��ҳ��hugetlbfs�еĴ�ҳ */
			if (unlikely(PageCompound(page))) {
				spin_unlock_irq(&zone->lru_lock);
				mem_cgroup_uncharge(page);
				/* ���ô�ҳ���������� */
				(*get_compound_page_dtor(page))(page);
				spin_lock_irq(&zone->lru_lock);
			} else
				/* ���뵽pages_to_free����׼���ͷŴ�ҳ */
				list_add(&page->lru, &pages_to_free);
		}
	}

	/*
	 * To save our caller's stack, now use input list for pages to free.
	 */
	/* ��pages_to_free�е�ҳ�����뵽page_list�� */
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
/* ��lruvec���lru�����������е�lru���͵�lru��������ڴ���գ����lru����һ����LRU_INACTIVE_ANON����LRU_INACTIVE_FILE����
 * nr_to_scan: ���ɨ����ٸ�ҳ��
 * lruvec: lru������������������5��lru����
 * sc: ɨ����ƽṹ
 * lru: ��Ҫɨ���lru����
 * ���ر��λ��յ�ҳ������
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
	/* �˷ǻlru�Ƿ�Ϊ�ǻ�ļ�ҳlru */
	int file = is_file_lru(lru);
	/* lru������zone */
	struct zone *zone = lruvec_zone(lruvec);
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;

	/* ��������ҳ�������ڷǻ��ҳ���������Ǹ���̫��ҳ�ˣ����˲²������ǿ��Ʋ���
	 * ��zone��NR_INACTIVE_FILE/ANON < NR_ISOLATED_ANONʱ����һ�����������CPUҲ�ڶԴ�zone�����ڴ���գ�����NR_ISOLATED_ANON�Ƚϸ�
	 */
	while (unlikely(too_many_isolated(zone, file, sc))) {
		/* ��������ߵȴ�100ms������ǲ��������ڴ���գ���һ��CPU����Ҳ��ִ���ڴ���� */
		congestion_wait(BLK_RW_ASYNC, HZ/10);

		/* We are about to die and free our memory. Return now. */
		/* ��ǰ���̱���������kill�ˣ�������ܵ���kill�ź� */
		if (fatal_signal_pending(current))
			return SWAP_CLUSTER_MAX;
	}

	/* ����ǰcpu��pagevec�е�ҳ���뵽lru������ 
	 * ������CPU��pagevec�е�ҳ�򲻻�Żص�lru������
	 * �������ƺ�����ΪЧ������
	 */
	lru_add_drain();

	if (!sc->may_unmap)
		isolate_mode |= ISOLATE_UNMAPPED;
	if (!sc->may_writepage)
		isolate_mode |= ISOLATE_CLEAN;

	/* ��lru�������� */
	spin_lock_irq(&zone->lru_lock);

	/* ��lruvec���lru������������lru���͵�lru�����и������nr_to_scan��ҳ����������ʱ�Ǵ�lru����β����ʼ�ã�Ȼ��ŵ�page_list 
	 * ���ظ����˶��ٸ��˷ǻlru�����ҳ��
	 */
	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &page_list,
				     &nr_scanned, sc, isolate_mode, lru);

	/* ����zone�ж�Ӧlru��ҳ������ */
	__mod_zone_page_state(zone, NR_LRU_BASE + lru, -nr_taken);
	/* ��zone��Ӧ�����ANON/FILEҳ������ */
	__mod_zone_page_state(zone, NR_ISOLATED_ANON + file, nr_taken);

	/* ������������zone���ڴ���գ�������ĳ��memcg���ڴ���յ���� */
	if (global_reclaim(sc)) {
		/* ͳ��zone��ɨ���ҳ������ */
		__mod_zone_page_state(zone, NR_PAGES_SCANNED, nr_scanned);
		/* �������kswapd�ں��߳��е��õ��˵ģ���ɨ���ҳ������ͳ�Ƶ�zone��PGSCAN_KSWAPD */
		if (current_is_kswapd())
			__count_zone_vm_events(PGSCAN_KSWAPD, zone, nr_scanned);
		else
			/* ����ɨ�������ͳ�Ƶ�zone��PGSCAN_DIRECT */
			__count_zone_vm_events(PGSCAN_DIRECT, zone, nr_scanned);
	}
	/* �ͷ�lru�� */
	spin_unlock_irq(&zone->lru_lock);

	/* ���������ҳ����Ϊ0 */
	if (nr_taken == 0)
		return 0;

	/* ����Ĵ����Ѿ����ǻlru�����е�һЩҳ�ó����ŵ�page_list���ˣ������Ƕ�page_list�е�ҳ�����ڴ���� 
	 * �˺����Ĳ���:
	 * 1.��ҳ�Ƿ��ڽ��л�д(��������ᵼ�»�д��֮ǰ�����ڴ����ʱ���´�ҳ�����˻�д����ҳΪ��ҳ��ϵͳ�Զ������д)���������ͬ�����պ��첽�����в�ͬ�Ĵ���
	 * 2.�˴λ���ʱ��ǿ�ƽ��л��գ���Ҫ���жϴ�ҳ�ܲ��ܽ��л���
	 * 		���������ҳ��ֻҪ�����ҳ�����̷��ʹ����򽫴�ҳ�ƶ����lru����ͷ�����������
	 * 		�����ӳ���ִ���ļ����ļ�ҳ��ֻҪ��������̷��ʹ����ͷŵ��lru�����������
	 * 		������������ļ�ҳ����������������̷��ʹ����ƶ����lru�������ֻ��1�����̷��ʹ�������PG_referenced��λ�ˣ�Ҳ����lru���������������
	 * 3.�����������pageΪ����ҳ�������ֲ�����swapcache�У�����᳢�Խ�����뵽swapcache�в���ҳ���Ϊ��ҳ�����swapcache��Ϊswap����������һ��address_space
	 * 4.������ӳ���˴�ҳ�Ľ��̵�ҳ����д�ҳ��unmap����
	 * 5.���ҳΪ��ҳ������л�д����ͬ�����첽��ͬ������ǻ�д��ɲŷ��أ��첽����Ǽ������д����У����ҳ��PG_writeback��ʾ���ڻ�д�ͷ��أ���ҳ���ᱻ�ŵ��ǻlru����ͷ��
	 * 6.���ҳ��PG_writeback��־������˱�־λ0����˵����ҳ�Ļ�д���(�������: 1.ͬ������ 2.֮ǰ�첽���նԴ�ҳ���еĻ�д�����)����Ӵ�ҳ��Ӧ��address_space�еĻ����Ƴ���ҳ�Ľ�㣬���뵽free_pages����
	 *		����PG_writeback��־λ1�ģ��������¼��뵽page_list�����������֮��Ὣ�����ҳ�Żص��ǻlru����ĩβ���´ν��л���ʱ�����ҳ��д����˾ͻᱻ�ͷ�
	 * 7.��free_pages�����ҳ�ͷ�
	 *
	 * page_list�з���ʱ�п��ܻ���ҳ����Щҳ��Ҫ�ŵ��ǻlru����ĩβ��ҳ������Щҳ���У���Щҳ�����ڽ��л��յĻ�д������Щ��д��ɺ�ϵͳ�ٴν����ڴ����ʱ����Щҳ�ͻᱻ�ͷ�
	 *		����һЩҳ�ǲ�������������ҳ
	 * nr_dirty: page_list����ҳ������
	 * nr_unqueued_dirty: page_list����ҳ����û�����ڻ�д��ҳ������
	 * nr_congested: page_list�����ڽ��л�д�����豸��æ��ҳ������(��Щҳ���ܻ�д����)
	 * nr_writeback: page_list�����ڽ��л�д�������ڻ��յ�ҳ������
	 * nr_immediate: page_list�����ڽ��л�д�Ļ���ҳ������
	 * ���ر��λ��յ�ҳ������
	 */
	nr_reclaimed = shrink_page_list(&page_list, zone, sc, TTU_UNMAP,
				&nr_dirty, &nr_unqueued_dirty, &nr_congested,
				&nr_writeback, &nr_immediate,
				false);

	/* ��lru���� */
	spin_lock_irq(&zone->lru_lock);

	/* ����reclaim_stat�е�recent_scanned */
	reclaim_stat->recent_scanned[file] += nr_taken;

	/* ������������zone��������ĳ��memcg����� */
	if (global_reclaim(sc)) {
		/* �������kswakpd�ں��߳��� */
		if (current_is_kswapd())
			/* ���µ�zone��PGSTEAL_KSWAPD */
			__count_zone_vm_events(PGSTEAL_KSWAPD, zone,
					       nr_reclaimed);
		else
			/* ������kswapd�ں��߳��У����µ�PGSTEAL_DIRECT */
			__count_zone_vm_events(PGSTEAL_DIRECT, zone,
					       nr_reclaimed);
	}

	/* 
	 * ��page_list��ʣ���ҳ�Ż�����Ӧ��lru�����У������ҳ���������:
	 * 1.����������ˣ��ŵ��lru����ͷ��
	 * 2.��ҳ��Ҫ�����ڴ��У����뵽unevictablelru����
	 * 3.��ҳΪ�ǻҳ���ƶ����ǻlru����ͷ��
	 * ��ҳ���ڽ��л�д���գ�����д��ɺ�ͨ���ж�ҳ��PG_reclaim��֪��ҳ���ڻ��գ����ҳ�ƶ����ǻlru����ĩβ�������end_page_writeback()����
	 * ����lru��ҳpage->_count--
	 * ��Ϊ�������ʱpage->_count++������lru���ǲ���Ҫ��page->_count++��
	 */
	putback_inactive_pages(lruvec, &page_list);

	/* ���´�zone��Ӧ�����ANON/FILEҳ�����������������nr_taken����˺���֮ǰ���Ӧ */
	__mod_zone_page_state(zone, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&zone->lru_lock);

	mem_cgroup_uncharge_list(&page_list);
	/* �ͷ�page_list��ʣ���ҳ�����ϵͳ�е�ÿCPUҳ���ٻ����У�����ҳ���� 
	 * ����ʣ��ľ���page->_count == 0��ҳ
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
	/* ���������ҳ���ڽ��л�д(�����ǻ�����ɵĻ�д) */
	if (nr_writeback && nr_writeback == nr_taken)
		/* ���ZONE��ZONE_WRITEBACK����Ǵ�zone���ҳ�ڻ�д */
		set_bit(ZONE_WRITEBACK, &zone->flags);

	/*
	 * memcg will stall in page writeback so only consider forcibly
	 * stalling for global reclaim
	 */
	/* �����ڴ�������������zone�ģ���������Ҫ��zone��flags��һЩ��� */
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
		/* ��һЩҳ����Ϊ���յ��������ڻ�д����ȴ�һ���豸 */
		if (nr_immediate && current_may_throttle())
			congestion_wait(BLK_RW_ASYNC, HZ/10);
	}

	/*
	 * Stall direct reclaim for IO completions if underlying BDIs or zone
	 * is congested. Allow kswapd to continue until it starts encountering
	 * unqueued dirty pages or cycling through the LRU too quickly.
	 */
	/* ��kswapd������£���������豸��дѹ���ϴ� */
	if (!sc->hibernation_mode && !current_is_kswapd() &&
	    current_may_throttle())
	    /* �ȴ�һ���豸 */
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

/* ��list�����е�ҳ���뵽lruvec->lists[lru]�����У�����Ҫ�����ҳ�ŵ�pages_to_free������ */
static void move_active_pages_to_lru(struct lruvec *lruvec,
				     struct list_head *list,
				     struct list_head *pages_to_free,
				     enum lru_list lru)
{
	/* ����lruvec��ȡ��Ӧ��zone������ */
	struct zone *zone = lruvec_zone(lruvec);
	unsigned long pgmoved = 0;
	struct page *page;
	int nr_pages;

	/* ����list��ÿһ��ҳ������ */
	while (!list_empty(list)) {
		/* ��listĩβ��ȡһ��ҳ������ */
		page = lru_to_page(list);
		/* ��ȡ��Ӧ��lruvec���Ƿ����������������ȡ��lruvec�봫���lruvec��һ��?һ�������һ�µ� */
		lruvec = mem_cgroup_page_lruvec(page, zone);

		/* ���page��LRU�����ϣ�����ʾһ��BUG����ʱpageӦ����list�ϣ���list��Ӧ����lru�е�һ������ */
		VM_BUG_ON_PAGE(PageLRU(page), page);
		/* ����page��־����lru�� */
		SetPageLRU(page);

		/* ���ҳ��������������һ����ҳ����ȡ���Ӧ�Ķ��ٸ�����ҳ������2M��ҳ��������ҳ����512�� */
		nr_pages = hpage_nr_pages(page);
		/* ����������lruvec->lists[lru]�еļ��� */
		mem_cgroup_update_lru_size(lruvec, lru, nr_pages);
		/* ��ҳ�������ƶ���lruvec->lists[lru]�� */
		list_move(&page->lru, &lruvec->lists[lru]);
		/* ������ */
		pgmoved += nr_pages;

		/* �����ҳ�����ô��� page->_count--��Ȼ���ж��Ƿ�Ϊ0
		 * �����ҳ�����ô��� page->_count--�����0��˵��ֻ�и����ʱ�����page->_count������++��Ҳ����˵��ҳ�Ѿ�û���������̻�ģ��������
		 * �����������ҳ�ŵ�page_to_free�У�֮���׼���ͷţ���Ϊ��ҳ��lru�У��������ô���Ϊ1˵��û��ҳ�������˴�ҳ
		 * ���ڵ��ô˺���ǰ����ҳ�������ȱ����뵽һ��������ģ��������ʱ���Դ�page->_count++���������óɶ�
		 */
		if (put_page_testzero(page)) {
			/* �����lru�еı�־ */
			__ClearPageLRU(page);
			/* �����ҳ�ǻҳ�ı�־ */
			__ClearPageActive(page);
			/* �����lru���Ƴ����������ͳ�� */
			del_page_from_lru_list(page, lruvec, lru);

			/* ����Ǵ�ҳ */
			if (unlikely(PageCompound(page))) {
				spin_unlock_irq(&zone->lru_lock);
				mem_cgroup_uncharge(page);
				(*get_compound_page_dtor(page))(page);
				spin_lock_irq(&zone->lru_lock);
			} else
				/* ���Ǵ�ҳ����������뵽pages_to_free������ */
				list_add(&page->lru, pages_to_free);
		}
	}
	/* ͳ�ƣ�����ע�⣬��һЩҳ�ִ�lru���Ƴ���ʱ�򣬲�û�м���pgmoved��������Ϊ����del_page_from_lru_listʱ�Ѿ��ȼ������Ƴ���ҳ */
	__mod_zone_page_state(zone, NR_LRU_BASE + lru, pgmoved);
	/* ���Ŀ��lru������activate��lru������ҲҪͳ�� */
	if (!is_active_lru(lru))
		__count_vm_events(PGDEACTIVATE, pgmoved);
}

/*
 * ��lruvec�е�lru���͵������л�ȡһЩҳ�����ƶ����ǻlru����ͷ����ע��˺�������lru����Ϊ���ͣ�����lru����ΪLRU_ACTIVE_ANON����ֻ�ᴦ��ANON���͵�ҳ�����ᴦ��FILE���͵�ҳ
 * ֻ�д���ε�ҳ����������ˣ��Ὣ����뵽�lru����ͷ��������ҳ��ʹ����������ˣ�Ҳ�ƶ����ǻlru����
 * ��lruvec�е�lru���͵��������ó�һЩҳ֮�󣬻��ж���Щҳ��ȥ����Ȼ��page->_count = 1��ҳ�����ͷţ���Ϊ˵����ҳֻ�и����ʱ�����page->_count������++���Ѿ�û�н��̻�ģ�����ô�ҳ
 * �����ͷŵ����ϵͳ��ÿCPU���ٻ�����
 * nr_to_scan: Ĭ����32��ɨ����������ɨ���ȫ����ͨҳ�������ɨ��32��ҳ�����ȫ�Ǵ�ҳ�����ɨ��(��ҳ/��ͨҳ)*32��ҳ
 * lruvec: ��Ҫɨ���lru����(�������һ��zone���������͵�lru����)
 * sc: ɨ����ƽṹ
 * lru: ��Ҫɨ������ͣ���active_file����active_anon��lru����
 */
static void shrink_active_list(unsigned long nr_to_scan,
			       struct lruvec *lruvec,
			       struct scan_control *sc,
			       enum lru_list lru)
{
	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long vm_flags;
	/* ��lru�л�ȡ����ҳ������⣬����������滹��ʣ���ҳ�Ļ����Ͱ������ͷŻػ��ϵͳ */
	LIST_HEAD(l_hold);	/* The pages which were snipped off */
	/* �ƶ����lru����ͷ����ҳ������ */
	LIST_HEAD(l_active);
	/* ��Ҫ�ƶ����ǻlru�����ҳ������ */
	LIST_HEAD(l_inactive);
	struct page *page;
	/* lruvec��ͳ�ƽṹ */
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	unsigned long nr_rotated = 0;
	isolate_mode_t isolate_mode = 0;
	/* lru�Ƿ�����LRU_INACTIVE_FILE����LRU_ACTIVE_FILE */
	int file = is_file_lru(lru);
	/* lruvec������zone */
	struct zone *zone = lruvec_zone(lruvec);

	/* ����ǰCPU�Ķ��pagevec�е�ҳ������lru������ */
	lru_add_drain();

	/* ��kswapd���ù���������£�sc->may_unmapΪ1
	 * ֱ���ڴ���յ������sc->may_unmapΪ1
	 * �����ڴ���յ������sc->may_unmap��zone_reclaim_mode�й�
	 */
	if (!sc->may_unmap)
		isolate_mode |= ISOLATE_UNMAPPED;

	
	/* ��kswapd���ù���������£�sc->may_writepage��latptop_mode�й�
	 * ֱ���ڴ���յ������sc->may_writepage��latptop_mode�й�
	 * �����ڴ���յ������sc->may_writepage��zone_reclaim_mode�й�
	 */
	if (!sc->may_writepage)
		isolate_mode |= ISOLATE_CLEAN;

	/* ��zone��lru_lock���� */
	spin_lock_irq(&zone->lru_lock);

	/* ��lruvec��lru���������β���ó�һЩҳ������������뵽l_hold�У�lru����һ����LRU_ACTIVE_ANON��LRU_ACTIVE_FILE
	 * Ҳ���Ǵӻ��lru�����и����һЩҳ���ӻlru�����β�������ó�
	 * ��sc->may_unmapΪ0ʱ���򲻻Ὣ�н���ӳ���ҳ�������
	 * ��sc->may_writepageΪ0ʱ���򲻻Ὣ��ҳ�����ڻ�д��ҳ�������
	 * ���������ҳ��page->_count++
	 * nr_taken�����ó���ҳ������
	 */
	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &l_hold,
				     &nr_scanned, sc, isolate_mode, lru);
	if (global_reclaim(sc))
		__mod_zone_page_state(zone, NR_PAGES_SCANNED, nr_scanned);

	reclaim_stat->recent_scanned[file] += nr_taken;

	/* ��ͳ�� */
	__count_zone_vm_events(PGREFILL, zone, nr_scanned);
	__mod_zone_page_state(zone, NR_LRU_BASE + lru, -nr_taken);
	__mod_zone_page_state(zone, NR_ISOLATED_ANON + file, nr_taken);
	/* �ͷ�lru������ */
	spin_unlock_irq(&zone->lru_lock);

	/* ��l_hold�е�ҳһ��һ������ */
	while (!list_empty(&l_hold)) {
		/* �Ƿ���Ҫ���ȣ���Ҫ����� */
		cond_resched();
		/* ��ҳ��l_hold���ó��� */
		page = lru_to_page(&l_hold);
		list_del(&page->lru);

		/* ���ҳ��unevictable(���ɻ���)�ģ���Żص�LRU_UNEVICTABLE���lru�����У����lru�����е�ҳ���ܱ�������ȥ */
		if (unlikely(!page_evictable(page))) {
			/* �Żص�page��Ӧ�����ڵ�lru������ 
			 * ������ʵ�����ǽ�ҳ�ŵ�zone��LRU_UNEVICTABLE������
			 */
			putback_lru_page(page);
			continue;
		}

		/* buffer_heads�����������˽����������ֵ����� */
		if (unlikely(buffer_heads_over_limit)) {
			/* �ļ�ҳ���е�page����PAGE_FLAGS_PRIVATE��־ */
			if (page_has_private(page) && trylock_page(page)) {
				if (page_has_private(page))
					/* �ͷŴ��ļ�ҳ��ӵ�е�buffer_head�����е�buffer_head������page->_count-- */
					try_to_release_page(page, 0);
				unlock_page(page);
			}
		}

		/* ����ҳ������Ƿ��б����ʹ���ͨ��ӳ���˴�ҳ��ҳ�����Accessed���м�飬���һ����ҳ�����Accessed��־
		 * �����ҳ��������ʹ��������if
		 */
		if (page_referenced(page, 0, sc->target_mem_cgroup,
				    &vm_flags)) {
			/* ����Ǵ�ҳ�����¼һ�����ٸ�ҳ���������ͨҳ������1 */
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
			/* �����ҳӳ����Ǵ���Σ�����ŵ�l_active�����У�������֮����ҳ����ҳ��Ӧ�Ļlru������
			 * ���Կ������ڴ���ε�ҳ�����ǱȽ������ڽ����Ƿŵ���ļ�ҳlru�����
			 * �������û�����ʹ�ʱ��Ҳ���п��ܻ����ǻ�ļ�ҳlru�����
			 */
			if ((vm_flags & VM_EXEC) && page_is_file_cache(page)) {
				list_add(&page->lru, &l_active);
				continue;
			}
		}
		/* ��ҳ�ŵ�l_inactive������
		 * ֻ��������ʹ��Ĵ���ε�ҳ���ᱻ���룬������ʹ�����ʹ��ˣ�Ҳ�ᱻ����l_inactive
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
	/* ��¼��������б����ʹ���ҳ��������֮����Щҳ�����ص�active���� */
	reclaim_stat->recent_rotated[file] += nr_rotated;

	/* ��l_active�����е�ҳ�ƶ���lruvec->lists[lru]�У������ǽ�active��ҳ�ƶ���active��lru����ͷ�� */
	move_active_pages_to_lru(lruvec, &l_active, &l_hold, lru);
	/* ��l_inactive�����е�ҳ�ƶ���lruvec->lists[lru - LRU_ACITVE]�У������ǽ�active��ҳ�ƶ���inactive��lruͷ�� */
	move_active_pages_to_lru(lruvec, &l_inactive, &l_hold, lru - LRU_ACTIVE);
	__mod_zone_page_state(zone, NR_ISOLATED_ANON + file, -nr_taken);
	spin_unlock_irq(&zone->lru_lock);

	mem_cgroup_uncharge_list(&l_hold);
	/* ʣ�µ�ҳ�Ĵ���ʣ�µĶ���page->_countΪ0��ҳ����Ϊ��ҳ�Żص����ϵͳ��ÿCPU��ҳ����ٻ����� */
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
/* �жϷǻ����ҳ�Ƿ���lowˮƽ */
static int inactive_anon_is_low(struct lruvec *lruvec)
{
	/*
	 * If we don't have swap space, anonymous page deactivation
	 * is pointless.
	 */
	/* ���û��swap��������total_swap_pagesΪ0����������ǲ���������ҳ�� */
	if (!total_swap_pages)
		return 0;

	/* ����inactive������ҳ�����Ƿ��������zone������ҳ������25% */
	/* ʹ��memcg����� */
	if (!mem_cgroup_disabled())
		return mem_cgroup_inactive_anon_is_low(lruvec);

	/* û��ʹ��memcg����� */
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
/* �ǻ�ļ�ҳ�����Ƿ�̫�� */
static int inactive_file_is_low(struct lruvec *lruvec)
{
	unsigned long inactive;
	unsigned long active;

	/* �ǻ�ļ�ҳ���� */
	inactive = get_lru_size(lruvec, LRU_INACTIVE_FILE);
	/* ��ļ�ҳ���� */
	active = get_lru_size(lruvec, LRU_ACTIVE_FILE);

	/* ��ļ�ҳ�������ڷǻ�ļ�ҳ�������Ǿ�˵���ǻ�ļ�ҳ����̫�� */
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
 * ��lru������д���
 * lru: lru���������
 * nr_to_scan: ��Ҫɨ���ҳ����������ֵ <= 32���������Ȳ���32ʱ����Ϊ������
 * lruvec: lru��������������lru������Ͼ͵ó��������lru����
 * sc: ɨ����ƽṹ
 */
static unsigned long shrink_list(enum lru_list lru, unsigned long nr_to_scan,
				 struct lruvec *lruvec, struct scan_control *sc)
{
	/* ���lru�����ǻlru(���������ҳlru�ͻ�ļ�ҳlru) */
	if (is_active_lru(lru)) {
		/* ����˻lru��Ӧ�ķǻlru������ά����ҳ������̫�٣����ӻlru�������ƶ�һЩ����Ӧ�ǻlru������ 
		 * ������Ҫע�⣬�ļ�ҳ������ҳ�ķǻlru�������Ƿ��ټ��㷽ʽ�ǲ�ͬ��
		 * ����ҳ�Ļ�����һ������ֵ��ʾ��Ŷ�������ҳ���浽�ǻ����ҳlru����
		 * �ļ�ҳ�Ļ�����ŷǻ�ļ�ҳ����Ҫ���ڻ�ļ�ҳ
		 * ���������page->_count == 0��ҳ����Ὣ�����ͷŵ�ÿCPUҳ����ٻ�����
		 */
		if (inactive_list_is_low(lruvec, lru))
			/* �ӻlru���ƶ�һЩҳ�򵽷ǻlru�У��ƶ�nr_to_scan����nr_to_scan <= 32���ӻlru����ĩβ�ó�ҳ���ƶ����ǻlru����ͷ 
			 * ֻ�д���ε�ҳ����������ˣ��Ὣ����뵽�lru����ͷ��������ҳ��ʹ����������ˣ�Ҳ�ƶ����ǻlru����
			 */
			shrink_active_list(nr_to_scan, lruvec, sc, lru);
		return 0;
	}

	/* ���lru�����Ƿǻlru����ô��Դ�lru���͵�lru�����е�ҳ����л��� */
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

/* �����lru�����������е�ÿ��lru�����������Ǳ���ɨ��Ӧ��ɨ���ҳ������
 * ������nr��
 */
static void get_scan_count(struct lruvec *lruvec, int swappiness,
			   struct scan_control *sc, unsigned long *nr)
{
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	u64 fraction[2];
	u64 denominator = 0;	/* gcc */
	/* ��ȡlruvec���ڵ�zone */
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
	/* �����ǰ��kswapd�ں˽��̣����Ҵ�zone���ܹ������ڴ���� */
	if (current_is_kswapd() && !zone_reclaimable(zone))
		/* ����ǿ�ƽ���ɨ�� */
		force_scan = true;
	/* ��������������zone�����ڴ���� */
	if (!global_reclaim(sc))
		/* ����ǿ�ƽ���ɨ�� */
		force_scan = true;

	/* If we have no swap space, do not bother scanning anon pages. */
	/* ���ɨ����ƽṹ�����˲�����swap��������û�п��е�swap�ռ� */
	if (!sc->may_swap || (get_nr_swap_pages() <= 0)) {
		/* ���ֻɨ���ļ�ҳlru */
		scan_balance = SCAN_FILE;
		/* ��ת��out */
		goto out;
	}

	/*
	 * Global reclaim will swap to prevent OOM even with no
	 * swappiness, but memcg users want to use this knob to
	 * disable swapping for individual groups completely when
	 * using the memory controller's swap limit feature would be
	 * too expensive.
	 */
	/* ���ɨ����ƽṹ�����ĳ��memcg���л��գ�����swappiness����0 */
	if (!global_reclaim(sc) && !swappiness) {
		/* ���ֻɨ���ļ�ҳ */
		scan_balance = SCAN_FILE;
		/* ��ת��out */
		goto out;
	}

	/*
	 * Do not apply any pressure balancing cleverness when the
	 * system is close to OOM, scan both anon and file equally
	 * (unless the swappiness setting disagrees with swapping).
	 */
	/* ���sc->priority == 0������swappiness��Ϊ0 
	 * sc->priority����һ��ɨ��(��ҳ�� >> sc->priority)��ҳ�������ҳ�������һ��memcg��һ��zone���ܹ���ҳ������Ҳ������һ��zone��ҳ������Ҳ������һ��lru�����ȣ�����������ô��
	 */
	if (!sc->priority && swappiness) {
		/* �ļ�ҳ����ҳ��ɨ�� */
		scan_balance = SCAN_EQUAL;
		/* ��ת��out */
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
	/* ���zone����ȫ�ֻ��յ���� */
	if (global_reclaim(sc)) {
		unsigned long zonefile;
		unsigned long zonefree;

		/* zone�п���ҳ������ */
		zonefree = zone_page_state(zone, NR_FREE_PAGES);
		/* zone�����е��ļ�ҳ���� */
		zonefile = zone_page_state(zone, NR_ACTIVE_FILE) +
			   zone_page_state(zone, NR_INACTIVE_FILE);

		/* ��������ļ�ҳ���Ͽ���ҳ��������С��zone�ĸ߷�ֵ 
		 * ˵�������ļ�ҳ���ͷ��˶����ܴﵽ�߷�ֵ��ҳ��Ҫ������ҳ����ɨ��
		 */
		if (unlikely(zonefile + zonefree <= high_wmark_pages(zone))) {
			/* ���ö�����ҳ����ɨ�� */
			scan_balance = SCAN_ANON;
			/* ��ת��out */
			goto out;
		}
	}

	/*
	 * There is enough inactive page cache, do not reclaim
	 * anything from the anonymous working set right now.
	 */
	/* �ǻ�ļ�ҳlru�����ڻ�ļ�ҳlru���� */
	if (!inactive_file_is_low(lruvec)) {
		/* ��ֻɨ���ļ�ҳ */
		scan_balance = SCAN_FILE;
		goto out;
	}

	/* ���������û��ִ�е�����ʹ�ù�ʽȥ���㱾��ɨ���lru���������ҳ���ļ�ҳ������ */
	scan_balance = SCAN_FRACT;

	/*
	 * With swappiness at 100, anonymous and file have the same priority.
	 * This scanning priority is essentially the inverse of IO cost.
	 */
	/* ��swappinessΪ100ʱ��ɨ������ҳ�����ȼ���ɨ���ļ�ҳ�����ȼ���� */
	/* ɨ������ҳ�����ȼ� */
	anon_prio = swappiness;
	/* ɨ���ļ�ҳ�����ȼ����� 200 - ɨ������ҳ���ȼ� */
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

	/* ����ҳ���� */
	anon  = get_lru_size(lruvec, LRU_ACTIVE_ANON) +
		get_lru_size(lruvec, LRU_INACTIVE_ANON);
	/* �ļ�ҳ���� */
	file  = get_lru_size(lruvec, LRU_ACTIVE_FILE) +
		get_lru_size(lruvec, LRU_INACTIVE_FILE);

	spin_lock_irq(&zone->lru_lock);
	/* �����lru���������������ɨ���������ҳ����������lru����������ҳ���������ķ�֮һ */
	if (unlikely(reclaim_stat->recent_scanned[0] > anon / 4)) {
		/* ͳ�����ɨ���������ҳ�������� */
		reclaim_stat->recent_scanned[0] /= 2;
		/* ͳ�������������ҳ����������ҳ�������� */
		reclaim_stat->recent_rotated[0] /= 2;
	}
	
	/* �����lru���������������ɨ���������ҳ����������lru����������ҳ���������ķ�֮һ */
	if (unlikely(reclaim_stat->recent_scanned[1] > file / 4)) {
		/* ͳ�����ɨ������ļ�ҳ�������� */
		reclaim_stat->recent_scanned[1] /= 2;
		/* ͳ����������ļ�ҳ�������ļ�ҳ�������� */
		reclaim_stat->recent_rotated[1] /= 2;
	}

	/*
	 * The amount of pressure on anon vs file pages is inversely
	 * proportional to the fraction of recently scanned pages on
	 * each list that were recently referenced and in active use.
	 */
	/* ����Ӱ��ɨ������ҳ���ȵ����� */
	ap = anon_prio * (reclaim_stat->recent_scanned[0] + 1);
	ap /= reclaim_stat->recent_rotated[0] + 1;
	/* ����Ӱ��ɨ���ļ�ҳ���ȵ����� */
	fp = file_prio * (reclaim_stat->recent_scanned[1] + 1);
	fp /= reclaim_stat->recent_rotated[1] + 1;
	spin_unlock_irq(&zone->lru_lock);

	/* �������ӱ������� */
	fraction[0] = ap;
	fraction[1] = fp;
	denominator = ap + fp + 1;
out:
	some_scanned = false;
	/* Only use force_scan on second pass. */
	/* �����ѭ������
	 * ��һ��ѭ����������е�lru�����ɨ�賤�ȶ�Ϊ0������еڶ���ɨ�裬�ڶ���ɨ�������һ����С��ɨ�賤�ȣ�Ҫô��lru������Ҫô����SWAP_CLUSTER_MAX(32)
	 */
	for (pass = 0; !some_scanned && pass < 2; pass++) {
		/* �����˳�����LRU��LRU_INACTIVE_ANON��LRU_ACTIVE_ANON��LRU_INACTIVE_FILE��LRU_ACTIVE_FILE */
		for_each_evictable_lru(lru) {
			/* �Ƿ�Ϊ�ļ�ҳ��lru */
			int file = is_file_lru(lru);
			unsigned long size;
			unsigned long scan;

			/* ��ȡ��lru���� */
			size = get_lru_size(lruvec, lru);
			/* ����Դ�lru��ɨ�賤�ȣ���ɨ����ƽṹ�е����ȼ��йأ����ȼ�ԽС��ɨ���Խ�� */
			scan = size >> sc->priority;

			/* ����Դ�lru��ɨ�賤����0����ô�ڵڶ��ֵ�ʱ���������һ����С��ɨ�賤�� */
			if (!scan && pass && force_scan)
				/* ��С��ɨ�賤��Ҫô�Ǵ�lru�����ȣ�Ҫô��SWAP_CLUSTER_MAX(32) */
				scan = min(size, SWAP_CLUSTER_MAX);

			switch (scan_balance) {
			/* ���sc->priority == 0����swappiness��Ϊ0ʱ�����������������lru����������ҳ������һ��ɨ�� */
			case SCAN_EQUAL:
				/* Scan lists relative to size */
				break;
			/* ��������������������ô���� */
			case SCAN_FRACT:
				/*
				 * Scan types proportional to swappiness and
				 * their relative recent reclaim efficiency.
				 */
				/* �������lruӦ��ɨ���ҳ������ */
				scan = div64_u64(scan * fraction[file],
							denominator);
				break;
				
			/* ���ɨ����ƽṹ�����˲�����swap��������û�п��е�swap�ռ� */
			/* ���ɨ����ƽṹ�����ĳ��memcg���л��գ�����swappiness����0 */
			/* �ǻ�ļ�ҳlru�����ڻ�ļ�ҳlru���� */
			/* �������������ֻ���ļ�ҳ����ɨ�� */
			case SCAN_FILE:
			/* ���������zone�����ڴ����ʱ����zone�������ļ�ҳ���ͷ��˶����ܴﵽ�߷�ֵ���Ǿ�ֻ������ҳ����ɨ��
		 	 */
			case SCAN_ANON:
				/* Scan one type exclusively */
				/* �����SCAN_FILE˵��ֻɨ���ļ�ҳ����SCAN_ANONΪֻɨ������ҳ 
				 */
				if ((scan_balance == SCAN_FILE) != file)
					scan = 0;
				break;
			default:
				/* Look ma, no brain */
				BUG();
			}
			/* �����lruӦ��ɨ���ҳ������ */
			nr[lru] = scan;
			/*
			 * Skip the second pass and don't force_scan,
			 * if we found something to scan.
			 */
			/* �����ж�����lru�����������е�����lru����������Ƿ��ܵ�ɨ����������0 */
			some_scanned |= !!scan;
		}
	}
}

/*
 * This is a basic per-zone page freer.  Used by both kswapd and direct reclaim.
 */
/* ��lru����������lruvec�е�lru��������ڴ���գ���lruvec�п�������һ��memcg��Ҳ����������һ��zone 
 * lruvec: lru������������������5��lru�����/�ǻ����ҳlru�����/�ǻ�ļ�ҳlru������ֹ����ҳ����
 * swappiness: ɨ������ҳ���׺�������ֵԽ�ͣ���ɨ��Խ�ٵ�����ҳ����Ϊ0ʱ����������ɨ������ҳlru���������������zone�����ڴ����ʱ����zone�������ļ�ҳ���ͷ��˶����ܴﵽ�߷�ֵ���Ǿ�ֻ������ҳ����ɨ��
 * sc: ɨ����ƽṹ
 */
static void shrink_lruvec(struct lruvec *lruvec, int swappiness,
			  struct scan_control *sc)
{
	unsigned long nr[NR_LRU_LISTS];
	unsigned long targets[NR_LRU_LISTS];
	unsigned long nr_to_scan;
	enum lru_list lru;
	unsigned long nr_reclaimed = 0;
	/* ��Ҫ���յ�ҳ������ */
	unsigned long nr_to_reclaim = sc->nr_to_reclaim;
	struct blk_plug plug;
	bool scan_adjusted;

	/* �����lru�����������е�ÿ��lru�����������Ǳ���ɨ��Ӧ��ɨ���ҳ������ 
	 * ����õ�ÿ��lru������Ҫɨ���ҳ������������nr��
	 * ÿ��lru������Ҫɨ�������sc->priority�йأ�sc->priorityԽС����ôɨ���Խ��
	 */
	get_scan_count(lruvec, swappiness, sc, nr);

	/* Record the original scan target for proportional adjustments later */
	/* ��nr�����ݸ��Ƶ�targets�� */
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
	/* �Ƿ�nr[]�е�����ҳ����ɨ�����ֹͣ
	 * ������������zone����ɨ�裬���Ҳ�����kswapd�ں��߳��е��õģ����ȼ�ΪĬ�����ȼ����ͻ�������Ҫ���յ�ҳ��������ֻ�н�nr[]�е�����ҳ����ɨ�����ֹͣ
	 * ���ٻ��ղ���������(���ٻ��յ����ȼ�����DEF_PRIORITY)
	 */
	scan_adjusted = (global_reclaim(sc) && !current_is_kswapd() &&
			 sc->priority == DEF_PRIORITY);

	/* ��ʼ�����struct blk_plug
	 * ��Ҫ��ʼ��list��mq_list��cb_list����������ͷ
	 * Ȼ��current->plug = plug
	 */
	blk_start_plug(&plug);
	/* ���LRU_INACTIVE_ANON��LRU_ACTIVE_FILE��LRU_INACTIVE_FILE����������һ����Ҫɨ���ҳ����û��ɨ���꣬��ɨ��ͻ���� 
	 * ע�����ﲻ���ж�LRU_ACTIVE_ANON��Ҫɨ���ҳ�����Ƿ�ɨ���꣬����ԭ��������Ϊϵͳ��̫ϣ��������ҳlru�����е�ҳ����
	 */
	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
					nr[LRU_INACTIVE_FILE]) {
		unsigned long nr_anon, nr_file, percentage;
		unsigned long nr_scanned;

		/* ��LRU_INACTIVE_ANON��LRU_INACTIVE_ANON��LRU_INACTIVE_FILE��LRU_ACTIVE_FILE���˳�����lru���� 
		 * Ȼ��Ա�������lru�������ɨ�裬һ�����32��ҳ��
		 */
		for_each_evictable_lru(lru) {
			/* nr[lru����]�����ҳ����Ҫɨ�� */
			if (nr[lru]) {
				/* ��ȡ������Ҫɨ���ҳ��������nr[lru]��SWAP_CLUSTER_MAX����Сֵ 
				 * Ҳ����ÿһ�����ֻɨ��SWAP_CLUSTER_MAX(32)��ҳ��
				 */
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				/* nr[lru����]����������Ҫɨ���ҳ������ */
				nr[lru] -= nr_to_scan;

				/* �Դ�lru���͵�lru��������ڴ���� 
				 * һ��ɨ���ҳ������nr[lru]��SWAP_CLUSTER_MAX����Сֵ��Ҳ�������ȫ���ܻ��գ�һ��Ҳ��ֻ�ܻ���SWAP_CLUSTER_MAX(32)��ҳ��
				 * ���Ǵ�lru����ĩβ��ǰɨ��
				 * ���λ��յ�ҳ����������nr_reclaimed��
				 */
				nr_reclaimed += shrink_list(lru, nr_to_scan,
							    lruvec, sc);
			}
		}

		/* û�л��յ��㹻ҳ�򣬻�����Ҫ������Ҫ���յ�ҳ�������������ܶ�Ļ���ҳ����������л���
		 * ��scan_adjustedΪ��ʱ��ɨ�赽nr[��������]�����е�����Ϊ0Ϊֹ��������Ƿ���յ��㹻ҳ�򣬼�ʹ���յ��㹻ҳ��Ҳ��������ɨ��
		 * Ҳ���Ǿ����ܵĻ���ҳ��Խ��Խ�ã�alloc_pages()�����������
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

		/* kswapd�����ĳ��memcg���л��յ�����л���õ��ˣ��Ѿ����յ����㹻������ҳ�򣬵��õ����������ж��Ƿ�Ҫ����ɨ�裬��Ϊ�Ѿ����յ����㹻ҳ���� */

		/* ɨ��һ���ʣ����Ҫɨ����ļ�ҳ����������ҳ���� */
		nr_file = nr[LRU_INACTIVE_FILE] + nr[LRU_ACTIVE_FILE];
		nr_anon = nr[LRU_INACTIVE_ANON] + nr[LRU_ACTIVE_ANON];

		/*
		 * It's just vindictive to attack the larger once the smaller
		 * has gone to zero.  And given the way we stop scanning the
		 * smaller below, this makes sure that we only make one nudge
		 * towards proportionality once we've got nr_to_reclaim.
		 */

		/* �Ѿ�ɨ������ˣ��˳�ѭ�� */
		if (!nr_file || !nr_anon)
			break;

		/* ������Ǽ�����ɨ�����ҳ�򣬻��nr[]�е���������Ӧ�ļ��� 
		 * ���õ�����϶���kswapd���̻������memcg��ҳ����գ������Ѿ����յ����㹻��ҳ����
		 * ���nr[]�л�ʣ��ܶ�������ҳ��û��ɨ�裬�����ͨ�����㣬����һЩnr[]��ɨ�������
		 * ����scan_adjusted��֮���nr[]��ʣ�������ɨ�����
		 */

		if (nr_file > nr_anon) {
			/* ʣ����Ҫɨ����ļ�ҳ����ʣ����Ҫɨ�������ҳʱ */

			/* ԭʼ����Ҫɨ������ҳ���� */
			unsigned long scan_target = targets[LRU_INACTIVE_ANON] +
						targets[LRU_ACTIVE_ANON] + 1;
			lru = LRU_BASE;
			/* ����ʣ�����Ҫɨ�������ҳ����ռ */
			percentage = nr_anon * 100 / scan_target;
		} else {
			/* ʣ����Ҫɨ����ļ�ҳ����ʣ����Ҫɨ�������ҳʱ */
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
	/* �ܹ����յ�ҳ������ */
	sc->nr_reclaimed += nr_reclaimed;

	/*
	 * Even if we did not try to evict anon pages at all, we want to
	 * rebalance the anon lru active/inactive ratio.
	 */
	/* �ǻ����ҳlru������ҳ����̫�� */
	if (inactive_anon_is_low(lruvec))
		/* �ӻ����ҳlru�������ƶ�һЩҳȥ�ǻ����ҳlru�������32�� */
		shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
				   sc, LRU_ACTIVE_ANON);

	/* ���̫����ҳ���л�д�ˣ������˯��100ms */
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
/* �ж��Ƿ������zone�����ڴ���գ���Ҫ�Ǽ�����ҳ�������ܲ��ܽ����ڴ�ѹ��
 * nr_reclaimed: ���λ��յ�����
 * nr_scanned: ����ɨ�������
 */
static inline bool should_continue_reclaim(struct zone *zone,
					unsigned long nr_reclaimed,
					unsigned long nr_scanned,
					struct scan_control *sc)
{
	unsigned long pages_for_compaction;
	unsigned long inactive_lru_pages;

	/* If not in reclaim/compaction mode, stop */
	/* ��������ڽ����ڴ���ջ����ڴ�ѹ�����򷵻� */
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
	/* �����Ǳ����Ŀ��order��һ����order�����ҳ������ */
	pages_for_compaction = (2UL << sc->order);
	/* �ǻҳ���� = �ǻ�ļ�ҳ���� */
	inactive_lru_pages = zone_page_state(zone, NR_INACTIVE_FILE);
	/* ������п���swap�ռ� */
	if (get_nr_swap_pages() > 0)
		/* �ǻҳ���� += �ǻ����ҳ���� */
		inactive_lru_pages += zone_page_state(zone, NR_INACTIVE_ANON);
	/* ������յ�ҳ��û�дﵽҪ����յ�ҳ��orderֵ�ٴ�һ����order�����ҳ���������ҷǻҳ�����㹻�����ٴ�һ����order�����ҳ���������ô�zone�������� */
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

/* ��zone�����ڴ���� 
 * �����Ƿ���յ���ҳ�򣬶�����ʮ�ֻ��յ���sc��ָ��������ҳ��
 * ��ʹû���յ�sc��ָ��������ҳ��ֻҪ���յ���ҳ�򣬾ͷ�����
 */
static bool shrink_zone(struct zone *zone, struct scan_control *sc)
{
	unsigned long nr_reclaimed, nr_scanned;
	bool reclaimable = false;

	do {
		/* ���ڴ�������������zoneʱ��sc->target_mem_cgroupΪNULL */
		struct mem_cgroup *root = sc->target_mem_cgroup;
		struct mem_cgroup_reclaim_cookie reclaim = {
			.zone = zone,
			.priority = sc->priority,
		};
		struct mem_cgroup *memcg;

		/* ���ο�ʼǰ���յ���ҳ������ 
		 * ��һ��ʱ��0
		 */
		nr_reclaimed = sc->nr_reclaimed;
		/* ���ο�ʼǰɨ�����ҳ������
		 * ��һ��ʱ��0
		 */
		nr_scanned = sc->nr_scanned;

		/* ��ȡ���ϲ��memcg
		 * ���û��ָ����ʼ��root����Ĭ����root_mem_cgroup
		 * root_mem_cgroup�����ÿ��zone��lru�������ÿ��zone������lru����
 		 */
		memcg = mem_cgroup_iter(root, NULL, &reclaim);
		do {
			struct lruvec *lruvec;
			int swappiness;

			/* ��ȡ��memcg�ڴ�zone��lru���� 
			 * ����ں�û�п���memcg����ô����zone->lruvec
			 */
			lruvec = mem_cgroup_zone_lruvec(zone, memcg);
			/* ��memcg�л�ȡswapiness����ֵ�����˽���swap��Ƶ�ʣ���ֵ�ϵ�ʱ����ô�͸���Ľ����ļ�ҳ�Ļ��գ���ֵ�ϸ�ʱ��������������ҳ�Ļ��� */
			swappiness = mem_cgroup_swappiness(memcg);

			/* �Դ�memcg��lru������л��չ��� 
			 * ��lru�����е�����ҳ�������ڴ�zone��
			 * ÿ��memcg�ж���Ϊÿ��zoneά��һ��lru����
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
			/* ����Ƕ�������zone���л��գ���ô���������memcg��������memcg�д�zone��lru������л��� 
			 * �����ֻ�����ĳ��memcg���л��գ�������յ����㹻�ڴ��򷵻أ����û���յ��㹻�ڴ棬��Դ�memcg�����memcg���л���
			 */
			if (!global_reclaim(sc) &&
					sc->nr_reclaimed >= sc->nr_to_reclaim) {
				mem_cgroup_iter_break(root, memcg);
				break;
			}
			/* ��һ��memcg����������zone���л��պͶ�ĳ��memcg���л��յ�������������ʱ��ִ�е��� */
			memcg = mem_cgroup_iter(root, memcg, &reclaim);
		} while (memcg);
		
		/* �����memcg���ڴ�ѹ�������浽memcg->vmpressure */
		vmpressure(sc->gfp_mask, sc->target_mem_cgroup,
			   sc->nr_scanned - nr_scanned,
			   sc->nr_reclaimed - nr_reclaimed);

		if (sc->nr_reclaimed - nr_reclaimed)
			reclaimable = true;

	/* �ж��Ƿ��ٴδ�zone�����ڴ���� 
	 * �����Դ�zone�����ڴ�������������:
	 * 1. û�л��յ���Ŀ��orderֵ��һ��������ҳ�򣬲��ҷǻlru�����е�ҳ������ > Ŀ��order��һ����ҳ
	 * 2. ��zone�������ڴ�ѹ����������������Դ�zone�����ڴ����
	 * ���������ڴ������ȫû�л��յ�ҳ��ʱ�򷵻أ���������˼��������ձ�order�����ҳ��
	 */
	} while (should_continue_reclaim(zone, sc->nr_reclaimed - nr_reclaimed,
					 sc->nr_scanned - nr_scanned, sc));

	return reclaimable;
}

/*
 * Returns true if compaction should go ahead for a high-order request, or
 * the high-order allocation would succeed without compaction.
 */
/* �жϴ�zone�Ƿ���Ҫ�����ڴ�ѹ�� */
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
	/* ��һ�ε���˼����
	 * ��zone�Ŀ����ڴ���ڴ�zone�ĸ߷�ֵ + balance_gap + 2^orderҳ����
	 * ��zone�кܶ�����ڴ�
	 */
	balance_gap = min(low_wmark_pages(zone), DIV_ROUND_UP(
			zone->managed_pages, KSWAPD_ZONE_BALANCE_GAP_RATIO));
	watermark = high_wmark_pages(zone) + balance_gap + (2UL << order);
	watermark_ok = zone_watermark_ok_safe(zone, 0, watermark, 0, 0);

	/*
	 * If compaction is deferred, reclaim up to a point where
	 * compaction will have a chance of success when re-enabled
	 */

	/* �Դ�zone����һ���ڴ�ѹ���Ƴ�
	 * �������watermark_ok��true����ô����ͻ᷵��true
	 */
	if (compaction_deferred(zone, order))
		return watermark_ok;

	/*
	 * If compaction is not ready to start and allocation is not likely
	 * to succeed without it, then keep reclaiming.
	 */
	/* ����zone�ܷ�����ڴ�ѹ�� */
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
	/* �ڴ���տ��ƽṹ���ڴ���յ���ؽ������ز������������� */
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
	/* ���buffer_head����������ϵͳ���Ƶ�ֵ��������__GFP_HIGHMEM */
	if (buffer_heads_over_limit)
		sc->gfp_mask |= __GFP_HIGHMEM;

	nodes_clear(shrink.nodes_to_scan);


	/* ����zonelist�е�ÿ��zone */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
					gfp_zone(sc->gfp_mask), sc->nodemask) {
					
		/* ����zone�Ƿ������ҳ�����û�У������� */
		if (!populated_zone(zone))
			continue;
		/*
		 * Take care memory controller reclaiming has small influence
		 * to global LRU.
		 */
		/* ���sc�е�target_mem_cgroup�Ƿ��Ƕ�����zone�����ڴ���գ����Ƕ�cgroup�е�ĳ���飬����Ƕ�����zone��������ж� */
		if (global_reclaim(sc)) {
			/* ��cpuset�й� */
			if (!cpuset_zone_allowed_hardwall(zone, GFP_KERNEL))
				continue;

			/* ����zone�ܹ����յ��ڴ�ҳ��������Ҳ����û�������ڴ��е�����ҳ���ļ�ҳ֮�� */
			lru_pages += zone_reclaimable_pages(zone);
			/* �����ڴ���տ��ƽṹ������յ�node�м����zone���ڵ�node */
			node_set(zone_to_nid(zone), shrink.nodes_to_scan);

			/* ���ɨ����ƽṹ�����ȼ��Ƿ���Ĭ�����ȼ�(DEF_PRIORITY)���������Ĭ�����ȼ��������zone�ܷ�����ڴ����
			 * �ж�zone�Ƿ��ܹ������ڴ���գ��жϵı�׼�� ɨ���ҳ�� < (���пɻ���ҳ������� * 6)��Ҳ�����Ѿ��Դ�zone�Ѿ�ɨ���6���������пɻ���ҳ���� 
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
			/* �����zone�Ѿ����㹻�Ŀ����ڴ��ˣ����п����Ǵ�zone��Ƭ̫�࣬�������Ƿ���Ҫ�����ڴ�ѹ�� */
			if (IS_ENABLED(CONFIG_COMPACTION) &&
			    sc->order > PAGE_ALLOC_COSTLY_ORDER &&
			    zonelist_zone_idx(z) <= requested_highidx &&
			    compaction_ready(zone, sc->order)) {
			    /* ��Ҫ�����ڴ�ѹ��������ɨ����ƽṹ�п��Խ����ڴ�ѹ����־ 
				 * Ȼ����һ��zone��Ҳ���Ǵ�zone�����ڴ��㹻������Ҫ���գ�ֻ��Ҫ�ڴ�ѹ���������zone�Ͳ�����������ߣ�ȥ���ڴ������
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
			 * ��������գ�������ո�cgroup��memory��ϵͳ�е�soft_limit_in_bytes�ļ��й�
			 * �˲�������˼������memory��Ľ���ʹ�õ��ڴ���Գ���soft_limit_in_bytes���������ڴ治��ʱ�����Ȼ��ճ�������
			 * ��������Ȼ��ճ����ⲿ��
			 * ��Ҫע�⣬cgroup��memory������ǽ��̣��������������zone��Ҳ����˵������ʱ�ǻ��ս����ڴ�zone��ʹ�õĿɻ����ڴ�
			 */
			nr_soft_reclaimed = mem_cgroup_soft_limit_reclaim(zone,
						sc->order, sc->gfp_mask,
						&nr_soft_scanned);
			/* �ܵĻ����������¼��ϱ�������յ����� */
			sc->nr_reclaimed += nr_soft_reclaimed;
			/* �ܹ�ɨ����������ϱ����������ɨ���ҳ������ */
			sc->nr_scanned += nr_soft_scanned;
			/* �Դ�zone������ջ��յ���ҳ������reclaimableΪtrue��reclaimable�����жϱ��ζ�zonelist���е��ڴ�����Ƿ���յ�ҳ�� */
			if (nr_soft_reclaimed)
				reclaimable = true;
			/* need some check for avoid more shrink_zone() */
		}

		/* ��zone�����ڴ���� */
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
		/* �������32��ҳ�� */
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.gfp_mask = (gfp_mask = memalloc_noio_flags(gfp_mask)),
		/* �����ڴ�����orderֵ */
		.order = order,
		/* ������л��յ�node���� */
		.nodemask = nodemask,
		/* ���ȼ�ΪĬ�ϵ�12 */
		.priority = DEF_PRIORITY,
		/* ��/proc/sys/vm/laptop_mode�ļ��й�
		 * laptop_modeΪ0����������л�д��������ʹ�����д��ֱ���ڴ����Ҳ���ܶ����ļ�ҳ���л�д
		 * ���������дʱ�����ԶԷ��ļ�ҳ���л�д
		 */
		.may_writepage = !laptop_mode,
		/* �������unmap���� */
		.may_unmap = 1,
		/* ������з��ļ�ҳ�Ĳ��� */
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

/* ��active_anon���lru�����е�ҳ�ó�һЩ�ŵ�inactive_anon���lru����ͷ����������һ���ö��ٷŶ��٣�����ҪһЩ�ж� */
static void age_active_anon(struct zone *zone, struct scan_control *sc)
{
	struct mem_cgroup *memcg;

	if (!total_swap_pages)
		return;

	/* ������ȡroot��memcg */
	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		/* ��ȡzone��lruvec���� 
		 * ������memcgʱ������������memcg->nodeinfo[nodeID]->zoneinfo[zoneID]
		 * û������memcgʱ��������zone->lruvec
		 */
		struct lruvec *lruvec = mem_cgroup_zone_lruvec(zone, memcg);

		/* �жϷǻ����ҳ�Ƿ���lowˮƽ���жϱ�׼��inactive������ҳ�����Ƿ��������zone������ҳ������25%
		 * ����ǻ����ҳ����low��ֵ����Ҫ��һЩactive�е�����ҳ�ƶ���inactive��
		 */
		if (inactive_anon_is_low(lruvec))
			shrink_active_list(SWAP_CLUSTER_MAX, lruvec,
					   sc, LRU_ACTIVE_ANON);

		/* ��һ��memcg */
		memcg = mem_cgroup_iter(NULL, memcg, NULL);
	} while (memcg);
}

/* �ж�zone�Ƿ�ƽ�� 
 * ���zone�Ŀ���ҳ���������ڸ߾���λ���������zone��ƽ���
 * ���ж��Ƿ���Ҫ�����ڴ�ѹ���������Ҫ���Ǵ�zoneҲ���ǲ�ƽ���zone
 */
static bool zone_balanced(struct zone *zone, int order,
			  unsigned long balance_gap, int classzone_idx)
{
	/* ���zone�Ŀ���ҳ���������ڸ߾���λ���������zone��ƽ��� */
	if (!zone_watermark_ok_safe(zone, order, high_wmark_pages(zone) +
				    balance_gap, classzone_idx, 0))
		return false;

	/* ���ж��Ƿ���Ҫ�����ڴ�ѹ���������Ҫ���Ǵ�zoneҲ���ǲ�ƽ���zone */
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
/* ���ڼ��node�Ƿ�ƽ��
 * ���orderΪ0��ֻҪ����һ��zone��ƽ���򷵻�false
 * ���order��Ϊ0��balanced_pagesС��node�������ҳ���1/4���᷵��false 
 */
static bool pgdat_balanced(pg_data_t *pgdat, int order, int classzone_idx)
{
	/* ����node��classzone_idx�е�zone�������ȫ��ҳ������ */
	unsigned long managed_pages = 0;
	/* ���ƽ���ҳ����������һ��zoneƽ��ʱ��������zone��ҳ��Ϊƽ��ҳ�� */
	unsigned long balanced_pages = 0;
	int i;

	/* Check the watermark levels */
	for (i = 0; i <= classzone_idx; i++) {
		struct zone *zone = pgdat->node_zones + i;

		if (!populated_zone(zone))
			continue;

		/* managed_pages����node�����е�ҳ���� */
		managed_pages += zone->managed_pages;

		/*
		 * A special case here:
		 *
		 * balance_pgdat() skips over all_unreclaimable after
		 * DEF_PRIORITY. Effectively, it considers them balanced so
		 * they must be considered balanced here as well!
		 */
		/* ��zone�Ƿ��ܹ������ڴ���գ�������ܹ�����ֱ�ӵ�����ƽ���zone���жϱ�׼��zone��NR_PAGES_SCANNED�Ƿ�С�����пɻ���ҳ���1/6 */
		if (!zone_reclaimable(zone)) {
			balanced_pages += zone->managed_pages;
			continue;
		}

		/* �ж�zone�Ƿ�ƽ�⣬��Ҫ�ж��Ƿ���ڸ߷�ֵ���Ƿ���Ҫ�����ڴ�ѹ���������ƽ�⣬��ֱ�ӷ���false */
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
/* �������nodeƽ���򷵻�true�����򷵻�false */
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
	/* �鿴pgdat->pfmemalloc_wait�Ƿ��еȴ��Ľ��̣����������ȫ������ */
	if (waitqueue_active(&pgdat->pfmemalloc_wait))
		wake_up_all(&pgdat->pfmemalloc_wait);

	/* ��������node�Ƿ�ƽ��
	 * ���orderΪ0��ֻҪ����һ��zone��ƽ���򷵻�false
 	 * ���order��Ϊ0��balanced_pagesС��node�������ҳ���1/4���᷵��false 
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
	/* �����������Ҫ���յ�ҳ����������Ϊ���zone�ĸ߷�ֵ��˵��ϣ�������ܵĻ���ҳ�� */
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
	/* �ж��Ƿ�Ҫ�Դ�zone�����ڴ����
	 * ���ڵͶ��ڴ棬ֻҪ�����ڴ���ڸ߷�ֵ�����Ҳ���Ҫ�����ڴ�ѹ������
	 * ���ڸ߶��ڴ棬���buffer_head������ϵͳ�޶�ֵ����Ҫ���л���
	 */
	lowmem_pressure = (buffer_heads_over_limit && is_highmem(zone));
	if (!lowmem_pressure && zone_balanced(zone, testorder,
						balance_gap, classzone_idx))
		return true;

	/* �Դ�zone���л��� */
	shrink_zone(zone, sc);
	/* ����Ҫɨ���node������ */
	nodes_clear(shrink.nodes_to_scan);
	/* ����zone����node��㸳ֵ��ȥ */
	node_set(zone_to_nid(zone), shrink.nodes_to_scan);

	reclaim_state->reclaimed_slab = 0;
	/* ����slab */
	shrink_slab(&shrink, sc->nr_scanned, lru_pages);
	sc->nr_reclaimed += reclaim_state->reclaimed_slab;

	/* Account for the number of pages attempted to reclaim */
	*nr_attempted += sc->nr_to_reclaim;
	/* ���zone��ZONE_WRITEBACK��־ */
	clear_bit(ZONE_WRITEBACK, &zone->flags);

	/*
	 * If a zone reaches its high watermark, consider it to be no longer
	 * congested. It's possible there are dirty pages backed by congested
	 * BDIs but as pressure is relieved, speculatively avoid congestion
	 * waits.
	 */
	/* ���zoneƽ����(����ҳ�� - 2^testorder�󻹴ﵽ�˸߷�ֵ)�������ZONE_CONGESTED��ZONE_DIRTY��־ */
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
/* ��node�е�classzone_idx��zone�����ڴ�ƽ���������node��������zone�Ŀ���ҳ����ߵ�high�ķ�ֵ�������ܹ����յ�ҳ������
 * ͬʱҲ���ж��Ƿ���Ҫ�����ڴ�ѹ��
 */
static unsigned long balance_pgdat(pg_data_t *pgdat, int order,
							int *classzone_idx)
{
	int i;
	int end_zone = 0;	/* Inclusive.  0 = ZONE_DMA */
	unsigned long nr_soft_reclaimed;
	unsigned long nr_soft_scanned;
	/* ɨ����ƽṹ */
	struct scan_control sc = {
		/* (__GFP_WAIT | __GFP_IO | __GFP_FS)
		 * �˴��ڴ�����������IO���ļ�ϵͳ�������п�������
		 */
		.gfp_mask = GFP_KERNEL,
		/* ��Ҫ���յ�ҳ�� */
		.order = order,
		/* ������ȼ�������һ��ɨ����ٶ��� */
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
	};
	count_vm_event(PAGEOUTRUN);

	do {
		unsigned long lru_pages = 0;
		unsigned long nr_attempted = 0;
		/* �Ƿ����������ȼ���Ĭ�Ͽ��� */
		bool raise_priority = true;
		/* �Ƿ���Ҫ�����ڴ�ѹ�������order>0����Ҫ */
		bool pgdat_needs_compaction = (order > 0);

		sc.nr_reclaimed = 0;

		/*
		 * Scan in the highmem->dma direction for the highest
		 * zone which needs scanning
		 */
		/* ����node��������е�zone���ҵ���һ����ƽ��Ĺ�����(�����ڴ���߷�ֵ�Ƚ�)����highmem��dma�ң��ҵ��˵�һ����ƽ���zone���˳����ѭ�� */
		for (i = pgdat->nr_zones - 1; i >= 0; i--) {
			/* ��ȡ�˽ڵ�ĵ�i��zone������ */
			struct zone *zone = pgdat->node_zones + i;

			/* ����zone�Ƿ������ҳ��(�����ڴ�С��ʱ���û��ZONE_HIGHMEM��������ZONE_HIGHMEM������)��Ҳ���Ǽ��zone->present_zone */
			if (!populated_zone(zone))
				continue;

			/* ����zone�Ƿ�ɽ���ҳ����գ��ɻ���ҳ������ = NR_ACTIVE_FILE + NR_INACTIVE_FILE + NR_ACTIVE_ANON + NR_INACTIVE_ANON */		
			/* NR_ACTIVE_FILE��NR_INACTIVE_FILE�����᷵�ص�swap�У����ǻ�ֱ�ӽ���ҳд�뵽�ļ��У�ֻ��NR_ACTIVE_ANON��NR_INACTIVE_ANON��д�뵽swap�� */
			if (sc.priority != DEF_PRIORITY &&
			    !zone_reclaimable(zone))
				continue;

			/*
			 * Do some background aging of the anon list, to give
			 * pages a chance to be referenced before reclaiming.
			 */
			/* ���·ǻ����ҳlru��������ҳ��Ҫ�ǽ��̵ĶѺ�ջ��˽������mmap��
			 * ������Ҫ�жϷǻ����ҳlru������ҳ�����Ƿ���٣����ٵ��������ӻ����ҳlru�����ó�һЩҳ����ǻ����ҳlru����ͷ��
			 */
			age_active_anon(zone, &sc);

			/*
			 * If the number of buffer_heads in the machine
			 * exceeds the maximum allowed level and this node
			 * has a highmem zone, force kswapd to reclaim from
			 * it to relieve lowmem pressure.
			 */
			/* ���buffer_heads�����������˽����������ֵ�����ұ�������zoneΪhighmem�������ǽ���zoneΪ���highmem�߶��ڴ�����֮���ǿ��kswapd������Щbuffer_heads���ͷ��ڴ��ѹ�� */
			if (buffer_heads_over_limit && is_highmem_idx(i)) {
				end_zone = i;
				break;
			}

			/* ����zone�Ƿ���ƽ��ģ���ʵ����zone�п����ڴ��ȥ2��order�η�����ҳ���ҳ�����������ڸ߷�ֵ */
			if (!zone_balanced(zone, order, 0, 0)) {
				/* ��ƽ�⣬��¼��end_zone���˳����ѭ�� */
				end_zone = i;
				break;
			} else {
				/*
				 * If balanced, clear the dirty and congested
				 * flags
				 */
				/* ƽ������������ZONE_CONGESTED��ZONE_DIRTY��־ */
				clear_bit(ZONE_CONGESTED, &zone->flags);
				clear_bit(ZONE_DIRTY, &zone->flags);
			}
		}

		/* node�����й���������ƽ��ģ��˳� */
		if (i < 0)
			goto out;

		/* �в�ƽ��Ĺ���������dma���ϱ��������� */
		for (i = 0; i <= end_zone; i++) {
			/* ��ȡ�������Ĺ����������� */
			struct zone *zone = pgdat->node_zones + i;
			
			/* ����zone�Ƿ������ҳ��(�����ڴ�С��ʱ���û��ZONE_HIGHMEM��������ZONE_HIGHMEM������)��Ҳ���Ǽ��zone->present_zone */
			if (!populated_zone(zone))
				continue;

			/* ��ȡ�˹������ɻ��յ�ҳ����������Ҳ����NR_ACTIVE_FILE + NR_INACTIVE_FILE + NR_ACTIVE_ANON + NR_INACTIVE_ANON */
			lru_pages += zone_reclaimable_pages(zone);

			/*
			 * If any zone is currently balanced then kswapd will
			 * not call compaction as it is expected that the
			 * necessary pages are already available.
			 */
			/* ���order > 0����pgdat_needs_compaction = true��������κ�һ����������ȥ2��order�η�������ҳ���ҳ�����������ڵͷ�ֵ����pgdat_needs_compaction����Ϊfalse
			 * pgdat_needs_compaction�����Ƿ���Ҫ�ڴ�ѹ��
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
		/* �ٴδ�dma�����ϱ��� */
		for (i = 0; i <= end_zone; i++) {
			/* zone������ */
			struct zone *zone = pgdat->node_zones + i;

			/* ����zone�Ƿ������ҳ��(�����ڴ�С��ʱ���û��ZONE_HIGHMEM��������ZONE_HIGHMEM������)��Ҳ���Ǽ��zone->present_zone */
			if (!populated_zone(zone))
				continue;

			if (sc.priority != DEF_PRIORITY &&
			    !zone_reclaimable(zone))
				continue;

			/* ��ǰzoneɨ���ҳ������ʼ��Ϊ0 */
			sc.nr_scanned = 0;

			/* �����ܹ�ɨ���ҳ���� */
			nr_soft_scanned = 0;
			/*
			 * Call soft limit reclaim before calling shrink_zone.
			 */
			/* ���ػ��յ����� */
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
			/* ����Ҳ�����zone�Ƿ���ƽ��ģ���ʵ����zone�п����ڴ��ȥ2��order�η�����ҳ���ҳ�����������ڸ߷�ֵ 
			 * �����ƽ���zone�����ڴ����
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
		/* �ж�node�Ƿ�����ڴ�ѹ�����ڴ���մﵽ����ֵ�����ѹ�� 
		 * �жϱ�׼:
		 * ������κ�һ����������ȥ2��order�η�������ҳ���ҳ������С��low��ֵ�������ѹ��
		 * ���յ�ҳ����sc.nr_reclaimed > nr_attempted
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

/* �˺�������м������node�Ƿ�ƽ�⣬���ƽ�⣬��˯�ߣ������ƽ�⣬�򷵻� */
static void kswapd_try_to_sleep(pg_data_t *pgdat, int order, int classzone_idx)
{
	long remaining = 0;
	DEFINE_WAIT(wait);

	if (freezing(current) || kthread_should_stop())
		return;
	
	/* ���뵽pgdat->kswapd_wait�ȴ������У�����û�н���˯�ߣ�������״̬������Ϊ��TASK_INTERRUPTIBLE */
	prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);

	/* Try to sleep for a short interval */
	/* ��prepare_kswapd_sleep()�л����Ƿ���Ҫ˯�ߣ��жϱ�׼������node����Ƿ���Ҫ�����ڴ���գ�����Ҫ�����ڴ�����򷵻�true */
	if (prepare_kswapd_sleep(pgdat, order, remaining, classzone_idx)) {
		/* remaining������ǻ�û��ʱ�ͱ�����ʱ��ʣ��ĳ�ʱʱ�� */
		remaining = schedule_timeout(HZ/10);
		/* ��pgdat->kswapd_wait�ȴ��������Ƴ� */
		finish_wait(&pgdat->kswapd_wait, &wait);
		/* �����¼��뵽pgdat->kswapd_wait�ȴ������У�����û�н���˯�ߣ�������״̬������Ϊ��TASK_INTERRUPTIBLE */
		prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);
	}

	/*
	 * After a short sleep, check if it was a premature sleep. If not, then
	 * go fully to sleep until explicitly woken up.
	 */
	/* �����ж��Ƿ���Ҫ�����ڴ���գ���������remaining��ʣ�࣬˵���Ǳ��������̻��ѵģ���������Σ�������˯��
	 * ��λ��ٴμ������node�Ƿ�ƽ�⣬���ƽ�������һ����ʱ���˯�ߣ���Ϊ����ѽ���״̬����Ϊ��TASK_INTERRUPTIBLE����������������schedule()����û���������̻��Ѵ�kswapdʱ����һֱ˯��
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
		/* �������pageblock������ɨ���־ */
		reset_isolation_suitable(pgdat);

		/* ˯�� */
		if (!kthread_should_stop())
			schedule();
		
		/* ������ */
		set_pgdat_percpu_threshold(pgdat, calculate_pressure_threshold);
	} else {
		if (remaining)
			count_vm_event(KSWAPD_LOW_WMARK_HIT_QUICKLY);
		else
			count_vm_event(KSWAPD_HIGH_WMARK_HIT_QUICKLY);
	}
	/* ����kswapd��״̬ΪTASK_RUNNING������pgdat->kswapd_wait����ȴ�������ɾ�� */
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
/* ҳ������߳�ʹ�õĺ���
 * ����ҳ��ȱҳʱ�ᱻ����
 */
static int kswapd(void *p)
{
	unsigned long order, new_order;
	unsigned balanced_order;
	int classzone_idx, new_classzone_idx;
	int balanced_classzone_idx;
	pg_data_t *pgdat = (pg_data_t*)p;
	struct task_struct *tsk = current;

	/* ���汾��ҳ�����״̬ */
	struct reclaim_state reclaim_state = {
		.reclaimed_slab = 0,
	};
	/* node�����������cpu������ */
	const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);

	lockdep_set_current_reclaim_state(GFP_KERNEL);

	/* ���cpumask��Ϊ�գ�Ҳ����node��������CPU */
	if (!cpumask_empty(cpumask))
		/* �����ô�kswapd������������ЩCPU������ */
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
	/* ���õ�ǰkswapd�ǿ��䶳�ģ�һ���ں��߳��ǲ����䶳�ģ��䶳�Ƿ�ֹ����ʱ�ƻ��ļ�ϵͳ */
	set_freezable();

	order = new_order = 0;
	balanced_order = 0;
	/* classzone_idx��new_classzone_idx��ʼ����node��������һ����������node_zones[]������±� */
	classzone_idx = new_classzone_idx = pgdat->nr_zones - 1;
	/* node�����һ���� */
	balanced_classzone_idx = classzone_idx;
	/* ��Ҫѭ����������kswapd��99%����ʱ�䶼���������棬�����ѭ���л�ִ�� ����->����->�����ڴ�->���� ����һ��ѭ�� */
	for ( ; ; ) {
		bool ret;

		/*
		 * If the last balance_pgdat was unsuccessful it's unlikely a
		 * new request of a similar or harder type will succeed soon
		 * so consider going to sleep on the basis we reclaimed at
		 */
		if (balanced_classzone_idx >= new_classzone_idx &&
					balanced_order == new_order) {
			/* ��ȡ��Ҫ���յ�ҳ��������orderֵ�����pgdat->kswapd_max_order����wakeup_kswapd()�����ã��Ǵ����յ�ҳ������orderֵ */
			new_order = pgdat->kswapd_max_order;
			/* ��ȡ��Ҫ����ҳ���zone����id */
			new_classzone_idx = pgdat->classzone_idx;
			/* ��������node��kswapd_max_order = 0��classzone_idx = ���һ��zone */
			pgdat->kswapd_max_order =  0;
			pgdat->classzone_idx = pgdat->nr_zones - 1;
		}

		/* ��һ��ѭ������������if 
		 * ������������������Ҫ2^new_order��ҳ����Ϊorder���������һ�ֽ��л��յ�orderֵ��new_order��������ֱ�д�뵽pgdat->kswapd_max_order���ֵ
		 * Ҳ������swap�����ڴ�Ĺ����У��ں�����������ҳ��
		 */
		if (order < new_order || classzone_idx > new_classzone_idx) {
			/*
			 * Don't sleep if someone wants a larger 'order'
			 * allocation or has tigher zone constraints
			 */
			order = new_order;
			classzone_idx = new_classzone_idx;
		} else {
			/* �˺�������м������node��zone�Ƿ�ƽ�⣬���ƽ�⣬��˯�ߣ������ƽ�⣬�򷵻�
			 * �����Ϊ�ڴ治�������wakeup_kswapd()�����ˣ���wakeup_kswapd()������pgdat->kswapd_max_order��pgdat->classzone_idx
			 * �����Ƿ�ƽ����Կ�calculate_normal_threshold()������
			 */
			kswapd_try_to_sleep(pgdat, balanced_order,
						balanced_classzone_idx);
			/* order���汾����Ҫ���յ�ҳ���order������ֵ����wakeup_kswapd()������ */
			order = pgdat->kswapd_max_order;
			/* classzone_idx������ԵĹ���������ֵ����wakeup_kswapd()������ */
			classzone_idx = pgdat->classzone_idx;
			new_order = order;
			new_classzone_idx = classzone_idx;
			/* ����kswapd_max_orderΪ0 */
			pgdat->kswapd_max_order = 0;
			/* pgdat->classzone_idxΪ����node��zone */
			pgdat->classzone_idx = pgdat->nr_zones - 1;
		}

		/* ����ܷ�����䶳����ϵͳΪsuspended״̬�£��䶳�Ľ��̻ᱻ�������� */
		ret = try_to_freeze();
		if (kthread_should_stop())
			break;

		/*
		 * We can speed up thawing tasks if we don't call balance_pgdat
		 * after returning from the refrigerator
		 */
		/* ȷ��kswapd�ܹ������䶳״̬�����ܽ���ҳ����գ���ֹ������ϵͳ��suspended����kswapd�ƻ��ļ�ϵͳ */
		if (!ret) {
			trace_mm_vmscan_kswapd_wake(pgdat->node_id, order);
			balanced_classzone_idx = classzone_idx;
			/* nodeƽ����ں���������kswapd������Ҫ�ĵط�
			 * pgdata: ���
			 * order: Ҫ���յ�ҳ��orderֵ�����ֵ����wakeup_kswapd()������
			 * balanced_classzone_idx: ��ԵĹ������б����ֵ����wakeup_kswapd()������
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
/* ����kswapd�ں��̣߳�ֻ����zone�п���ҳ����������zone�ĸ߾���λ�Żỽ�� */
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
	/* �Ѵ��ڻ��Ѷ��У����ڵȴ������� */
	if (!waitqueue_active(&pgdat->kswapd_wait))
		return;
	/* ����Ƿ�ƽ�⣬���zone�Ŀ���ҳ���������ڸ߾���λ���������zone��ƽ��� */
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

/* ����zoneδ����ӳ����ļ�ҳ���� */
static inline unsigned long zone_unmapped_file_pages(struct zone *zone)
{
	/* zone���Ѿ�ӳ���˵��ļ�ҳ */
	unsigned long file_mapped = zone_page_state(zone, NR_FILE_MAPPED);
	/* zone�����ļ�ҳlru�����е��ļ�ҳ���� */
	unsigned long file_lru = zone_page_state(zone, NR_INACTIVE_FILE) +
		zone_page_state(zone, NR_ACTIVE_FILE);

	/*
	 * It's possible for there to be more file mapped pages than
	 * accounted for by the pages on the file LRU lists because
	 * tmpfs pages accounted for as ANON can also be FILE_MAPPED
	 */
	/* ����zoneδ����ӳ����ļ�ҳ���� */
	return (file_lru > file_mapped) ? (file_lru - file_mapped) : 0;
}

/* Work out how many page cache pages we can reclaim in this reclaim_mode */
/* �����zone���Ի��յ��ļ�ҳ���� */
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
		/* ����zone�м��뵽page cache�е�ҳ������������ҳ���뵽swapcache��Ҳ���������� */
		nr_pagecache_reclaimable = zone_page_state(zone, NR_FILE_PAGES);
	else
		/* zone����ģʽ�н�ֹ�˻�������ҳ������
	 	 * ����zoneδ����ӳ����ļ�ҳ���������ļ�ҳlru�����Ȼ�ȡ�ļ�ҳ������������NR_FILE_PAGES
	 	 */
		nr_pagecache_reclaimable = zone_unmapped_file_pages(zone);

	/* If we can't clean pages, remove dirty pages from consideration */
	if (!(zone_reclaim_mode & RECLAIM_WRITE))
		/* �������ģʽ��ֹ����ҳ��д����ô��zone���п��Ի��յ�ҳҪ�޳���zone����ҳ */
		delta += zone_page_state(zone, NR_FILE_DIRTY);

	/* Watch for any possible underflows due to delta */
	/* ��������ǣ����пɻ��յ�ҳ������ҳ������ͽ�delta = nr_pagecache_reclaimable
	 * ���������Ϊ0��Ҳ���������ģʽ��ֹ����ҳ��д����ô��zone�ɻ���ҳ����������0
	 */
	if (unlikely(delta > nr_pagecache_reclaimable))
		delta = nr_pagecache_reclaimable;

	/* ���ش�zone���Ի��յ�ҳ���� */
	return nr_pagecache_reclaimable - delta;
}

/*
 * Try to free up some pages from this zone through reclaim.
 */
/* ��get_page_from_freelist()�������·���ӵ��õ��Ļ����ڴ溯�� 
 * ����ɨ�赽�ķǻ����ҳlru�����е�ҳ: ���ܽ��л�д��Ҳ���ܽ���unmap
 * ����ɨ�赽�ķǻ�ļ�ҳlru�����е�ҳ: ������л�д�����ܽ���unmap
 * ֻ����page->_countΪ0��ҳ��Ҳ���ǻ����Ͽ���ֱ�ӻ��յ�ҳ(��Щҳ�Ѿ����й�unmap�����й����ջ�д)
 * ���յ���ҳ�������ﵽ 1<< orderֵ���ͷ���true�����򷵻�false
 */
static int __zone_reclaim(struct zone *zone, gfp_t gfp_mask, unsigned int order)
{
	/* Minimum pages needed in order to stay on node */
	/* Ŀ����յ�ҳ������ */
	const unsigned long nr_pages = 1 << order;
	struct task_struct *p = current;
	struct reclaim_state reclaim_state;
	/*
	 * �����Ƿ��䵼�µĻ��գ�����ͽ������ٻ��գ����ｫ����page->_countΪ0��ҳ�����л���
	 * ����һ��ҳ���л���ʱ����Դ�ҳ����unmap������Ȼ�󽫴�ҳ��д�������У������ڴ�����ڴ���յ�����£���д���첽�ģ�Ҳ���Ǳ����ڴ���նԴ�ҳ�ύһ����д���룬Ȼ��ͷ�����
	 * ֮���д��ɺ󣬿���ͨ����ҳ��PG_reclaim�жϵ���ҳ����ΪҪ�������ԲŻ�д�ģ��ͰѴ�ҳ�ŵ��ǻlru����ĩβ
	 * ����ҳ��д��ɺ��´�ִ���ڴ����ʱ���Ϳ��Է��ִ�ҳ��page->_countΪ0��ֱ�ӻ��մ�ҳ
	 * Ҳ���ǵ�ҳΪ��ҳʱ�������ϱ��λ��ն����������Щҳ��ֻ����Щҳ��д��ɺ����´��ڴ���ս��л���
	 * ���ٻ��վ��ǻ��յ�����Щ�Ѿ�������Ҫ���գ������Ѿ���д��ɵ�ҳ��������ǰ��ĳ���ڴ���մ���õ�ҳ
	 */
	struct scan_control sc = {
		/* ����һ�λ���SWAP_CLUSTER_MAX�����һ�λ���1 << order����Ӧ����1024�� */
		.nr_to_reclaim = max(nr_pages, SWAP_CLUSTER_MAX),
		/* ��ǰ������ȷ��ֹ�����ڴ��IO����(��ֹ__GFP_IO��__GFP_FS��־)����ô�����__GFP_IO��__GFP_FS��־����ʾ������IO���� */
		.gfp_mask = (gfp_mask = memalloc_noio_flags(gfp_mask)),
		.order = order,
		/* ���ȼ�Ϊ4��Ĭ����12�����12һ��ɨ�����lru�����е�ҳ�򣬶���ɨ�����������ȼ�Ϊ12���٣�����������չ����л��յ����㹻ҳ�򣬾ͻ᷵�� */
		.priority = ZONE_RECLAIM_PRIORITY,
		/* ͨ��/proc/sys/vm/zone_reclaim_mode�ļ������Ƿ�������ҳ��д�����̣���ʹ���������ڴ����ҳ���ܶ����ļ�ҳ���л�д����
		 * ��zone_reclaim_modeΪ0ʱ���������ǲ�����ҳ���д��
		 */
		.may_writepage = !!(zone_reclaim_mode & RECLAIM_WRITE),
		/* ͨ��/proc/sys/vm/zone_reclaim_mode�ļ������Ƿ���������ҳ��д��swap���� 
		 * ��zone_reclaim_modeΪ0ʱ���������ǲ���������ҳ��д��
		 */
		.may_unmap = !!(zone_reclaim_mode & RECLAIM_SWAP),
		/* ���������ҳlru������� */
		.may_swap = 1,
		/* ���ṹ����һ��
		 * .target_mem_cgroup ��ʾ�����ĳ��memcg�������������zone�����ڴ���յģ�����Ϊ�գ�Ҳ����˵�������������zone�����ڴ���յ�
		 */
	};
	struct shrink_control shrink = {
		.gfp_mask = sc.gfp_mask,
	};
	unsigned long nr_slab_pages0, nr_slab_pages1;

	/* ����Ƿ���Ҫ���ȣ���Ҫ����� */
	cond_resched();
	/*
	 * We need to be able to allocate from the reserves for RECLAIM_SWAP
	 * and we also need to be able to write out pages for RECLAIM_WRITE
	 * and RECLAIM_SWAP.
	 */
	/* ���õ�ǰ���������д����ҳ */
	p->flags |= PF_MEMALLOC | PF_SWAPWRITE;
	lockdep_set_current_reclaim_state(gfp_mask);
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;

	/* ��zone�ɻ���ҳ��������min_unmapped_pagesʱ���ŶԴ�zone���л��� */
	if (zone_pagecache_reclaimable(zone) > zone->min_unmapped_pages) {
		/*
		 * Free memory by calling shrink zone with increasing
		 * priorities until we have enough memory freed.
		 */
		do {
			/* �Դ�zone�����ڴ���գ��ڴ���յ���Ҫ���� */
			shrink_zone(zone, &sc);
			/* û�л��յ��㹻ҳ�򣬲���ѭ������û�ﵽ���ȼ����������� */
		} while (sc.nr_reclaimed < nr_pages && --sc.priority >= 0);
	}

	/* ��zone�е�ǰ�ɻ���slab��ҳ������ */
	nr_slab_pages0 = zone_page_state(zone, NR_SLAB_RECLAIMABLE);
	/* ��zone�е�ǰ�ɻ���slabʹ�õ�ҳ����������zone�������Сslabʹ�õ�ҳ������ 
	 * �ڴ����ͬʱ���zone��slab����ʹ�õ�ҳ������ѹ�ͣ�Ҳ�᳢�Ի���nr_pages��ҳ��
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
			/* ��ȡzone�ܹ����յ��ڴ�ҳ��������Ҳ����û�������ڴ��е�����ҳ���ļ�ҳ֮�� */
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
		/* ��slab�л��յ���һ��ҳ�򣬼��뵽�ܻ��յ���ҳ�������� */
		if (nr_slab_pages1 < nr_slab_pages0)
			sc.nr_reclaimed += nr_slab_pages0 - nr_slab_pages1;
	}

	p->reclaim_state = NULL;
	current->flags &= ~(PF_MEMALLOC | PF_SWAPWRITE);
	lockdep_clear_current_reclaim_state();
	return sc.nr_reclaimed >= nr_pages;
}

/* ��zone�����ڴ����
 * zone: �����ڴ���յ�zone
 * gfp_mask: �ڴ�����־
 * order: ��Ҫ����ҳ��������orderֵ
 * ���յ���2^order������ҳ��ʱ���Ż᷵���棬��ʹ�����ˣ�û�ﵽ���������Ҳ���ؼ�
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
	/* zone�Ŀɻ����ڴ���������Ҫ����zone��min_unmapped_pages 
	 * Ҳ�������пɻ����ڴ�ҳ����unmap��������Щunmap��Ŀɻ����ڴ�ҳ�������ﲻ��min_unmapped_pages
	 * �ɻ���slabҳ������СҲҪ����min_slab_pages���ܽ��л���
	 */
	if (zone_pagecache_reclaimable(zone) <= zone->min_unmapped_pages &&
	    zone_page_state(zone, NR_SLAB_RECLAIMABLE) <= zone->min_slab_pages)
		return ZONE_RECLAIM_FULL;

	/* �����zone���ɨ���ҳ�������Ѿ�������zone�ɻ���ҳ��������6����
	 * ��û�б�Ҫ�ٶԽ��д�zone����ɨ����
	 */
	if (!zone_reclaimable(zone))
		return ZONE_RECLAIM_FULL;

	/*
	 * Do not scan if the allocation should not be delayed.
	 */
	/* �����־�б�ʾ��ֹ�ȴ������н��̱�־����PF_MEMALLOC��������򷵻� */
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

	/* ���ô�zone���ڽ����ڴ���յ�������Ҫ����zone->flags��ZONE_RECLAIM_LOCKED��־ */
	if (test_and_set_bit(ZONE_RECLAIM_LOCKED, &zone->flags))
		return ZONE_RECLAIM_NOSCAN;

	/* ���п����ڴ���� 
	 * ���յ���2^order������ҳ��ʱ���Ż᷵���棬��ʹ�����ˣ�û�ﵽ���������Ҳ���ؼ�
	 */
	ret = __zone_reclaim(zone, gfp_mask, order);
	/* �ͷŴ�zone���ڽ����ڴ���յ����������zone��ZONE_RECLAIM_LOCKED��־����ʾ��zone�Ѿ�������� */
	clear_bit(ZONE_RECLAIM_LOCKED, &zone->flags);

	if (!ret)
		/* �ڴ����ʧ�ܼ����� */
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
