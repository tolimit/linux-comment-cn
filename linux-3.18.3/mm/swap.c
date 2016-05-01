/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the operation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * Documentation/sysctl/vm.txt.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/mm_inline.h>
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/backing-dev.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/uio.h>

#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/pagemap.h>

/* How many pages do we try to swap or page in/out together? */
int page_cluster;

/* 这部分的lru缓存是用于那些原来不属于lru链表的，新加入进来的页 */
static DEFINE_PER_CPU(struct pagevec, lru_add_pvec);
/* 在这个lru_rotate_pvecs中的页都是非活动页并且在非活动lru链表中，将这些页移动到非活动lru链表的末尾 */
static DEFINE_PER_CPU(struct pagevec, lru_rotate_pvecs);
/* 在这个lru缓存的页原本应属于活动lru链表中的页，会强制清除PG_activate和PG_referenced，并加入到非活动页lru链表的链表表头中
 * 这些页一般从活动lru链表中的尾部拿出来的
 */
static DEFINE_PER_CPU(struct pagevec, lru_deactivate_pvecs);
#ifdef CONFIG_SMP
/* 将cpu的activate_page_pvecs中的页放到活动页lru链表头中，这些页原本属于非活动lru链表的页 */
static DEFINE_PER_CPU(struct pagevec, activate_page_pvecs);
#endif

/*
 * This path almost never happens for VM activity - pages are normally
 * freed via pagevecs.  But it gets used by networking.
 */
static void __page_cache_release(struct page *page)
{
	if (PageLRU(page)) {
		struct zone *zone = page_zone(page);
		struct lruvec *lruvec;
		unsigned long flags;

		spin_lock_irqsave(&zone->lru_lock, flags);
		lruvec = mem_cgroup_page_lruvec(page, zone);
		VM_BUG_ON_PAGE(!PageLRU(page), page);
		__ClearPageLRU(page);
		del_page_from_lru_list(page, lruvec, page_off_lru(page));
		spin_unlock_irqrestore(&zone->lru_lock, flags);
	}
	mem_cgroup_uncharge(page);
}

static void __put_single_page(struct page *page)
{
	__page_cache_release(page);
	free_hot_cold_page(page, false);
}

static void __put_compound_page(struct page *page)
{
	compound_page_dtor *dtor;

	__page_cache_release(page);
	dtor = get_compound_page_dtor(page);
	(*dtor)(page);
}

/**
 * Two special cases here: we could avoid taking compound_lock_irqsave
 * and could skip the tail refcounting(in _mapcount).
 *
 * 1. Hugetlbfs page:
 *
 *    PageHeadHuge will remain true until the compound page
 *    is released and enters the buddy allocator, and it could
 *    not be split by __split_huge_page_refcount().
 *
 *    So if we see PageHeadHuge set, and we have the tail page pin,
 *    then we could safely put head page.
 *
 * 2. Slab THP page:
 *
 *    PG_slab is cleared before the slab frees the head page, and
 *    tail pin cannot be the last reference left on the head page,
 *    because the slab code is free to reuse the compound page
 *    after a kfree/kmem_cache_free without having to check if
 *    there's any tail pin left.  In turn all tail pinsmust be always
 *    released while the head is still pinned by the slab code
 *    and so we know PG_slab will be still set too.
 *
 *    So if we see PageSlab set, and we have the tail page pin,
 *    then we could safely put head page.
 */
static __always_inline
void put_unrefcounted_compound_page(struct page *page_head, struct page *page)
{
	/*
	 * If @page is a THP tail, we must read the tail page
	 * flags after the head page flags. The
	 * __split_huge_page_refcount side enforces write memory barriers
	 * between clearing PageTail and before the head page
	 * can be freed and reallocated.
	 */
	smp_rmb();
	if (likely(PageTail(page))) {
		/*
		 * __split_huge_page_refcount cannot race
		 * here, see the comment above this function.
		 */
		VM_BUG_ON_PAGE(!PageHead(page_head), page_head);
		VM_BUG_ON_PAGE(page_mapcount(page) != 0, page);
		if (put_page_testzero(page_head)) {
			/*
			 * If this is the tail of a slab THP page,
			 * the tail pin must not be the last reference
			 * held on the page, because the PG_slab cannot
			 * be cleared before all tail pins (which skips
			 * the _mapcount tail refcounting) have been
			 * released.
			 *
			 * If this is the tail of a hugetlbfs page,
			 * the tail pin may be the last reference on
			 * the page instead, because PageHeadHuge will
			 * not go away until the compound page enters
			 * the buddy allocator.
			 */
			VM_BUG_ON_PAGE(PageSlab(page_head), page_head);
			__put_compound_page(page_head);
		}
	} else
		/*
		 * __split_huge_page_refcount run before us,
		 * @page was a THP tail. The split @page_head
		 * has been freed and reallocated as slab or
		 * hugetlbfs page of smaller order (only
		 * possible if reallocated as slab on x86).
		 */
		if (put_page_testzero(page))
			__put_single_page(page);
}

static __always_inline
void put_refcounted_compound_page(struct page *page_head, struct page *page)
{
	if (likely(page != page_head && get_page_unless_zero(page_head))) {
		unsigned long flags;

		/*
		 * @page_head wasn't a dangling pointer but it may not
		 * be a head page anymore by the time we obtain the
		 * lock. That is ok as long as it can't be freed from
		 * under us.
		 */
		flags = compound_lock_irqsave(page_head);
		if (unlikely(!PageTail(page))) {
			/* __split_huge_page_refcount run before us */
			compound_unlock_irqrestore(page_head, flags);
			if (put_page_testzero(page_head)) {
				/*
				 * The @page_head may have been freed
				 * and reallocated as a compound page
				 * of smaller order and then freed
				 * again.  All we know is that it
				 * cannot have become: a THP page, a
				 * compound page of higher order, a
				 * tail page.  That is because we
				 * still hold the refcount of the
				 * split THP tail and page_head was
				 * the THP head before the split.
				 */
				if (PageHead(page_head))
					__put_compound_page(page_head);
				else
					__put_single_page(page_head);
			}
out_put_single:
			if (put_page_testzero(page))
				__put_single_page(page);
			return;
		}
		VM_BUG_ON_PAGE(page_head != page->first_page, page);
		/*
		 * We can release the refcount taken by
		 * get_page_unless_zero() now that
		 * __split_huge_page_refcount() is blocked on the
		 * compound_lock.
		 */
		if (put_page_testzero(page_head))
			VM_BUG_ON_PAGE(1, page_head);
		/* __split_huge_page_refcount will wait now */
		VM_BUG_ON_PAGE(page_mapcount(page) <= 0, page);
		atomic_dec(&page->_mapcount);
		VM_BUG_ON_PAGE(atomic_read(&page_head->_count) <= 0, page_head);
		VM_BUG_ON_PAGE(atomic_read(&page->_count) != 0, page);
		compound_unlock_irqrestore(page_head, flags);

		if (put_page_testzero(page_head)) {
			if (PageHead(page_head))
				__put_compound_page(page_head);
			else
				__put_single_page(page_head);
		}
	} else {
		/* @page_head is a dangling pointer */
		VM_BUG_ON_PAGE(PageTail(page), page);
		goto out_put_single;
	}
}

static void put_compound_page(struct page *page)
{
	struct page *page_head;

	/*
	 * We see the PageCompound set and PageTail not set, so @page maybe:
	 *  1. hugetlbfs head page, or
	 *  2. THP head page.
	 */
	if (likely(!PageTail(page))) {
		if (put_page_testzero(page)) {
			/*
			 * By the time all refcounts have been released
			 * split_huge_page cannot run anymore from under us.
			 */
			if (PageHead(page))
				__put_compound_page(page);
			else
				__put_single_page(page);
		}
		return;
	}

	/*
	 * We see the PageCompound set and PageTail set, so @page maybe:
	 *  1. a tail hugetlbfs page, or
	 *  2. a tail THP page, or
	 *  3. a split THP page.
	 *
	 *  Case 3 is possible, as we may race with
	 *  __split_huge_page_refcount tearing down a THP page.
	 */
	page_head = compound_head_by_tail(page);
	if (!__compound_tail_refcounted(page_head))
		put_unrefcounted_compound_page(page_head, page);
	else
		put_refcounted_compound_page(page_head, page);
}

void put_page(struct page *page)
{
	if (unlikely(PageCompound(page)))
		put_compound_page(page);
	else if (put_page_testzero(page))
		__put_single_page(page);
}
EXPORT_SYMBOL(put_page);

/*
 * This function is exported but must not be called by anything other
 * than get_page(). It implements the slow path of get_page().
 */
bool __get_page_tail(struct page *page)
{
	/*
	 * This takes care of get_page() if run on a tail page
	 * returned by one of the get_user_pages/follow_page variants.
	 * get_user_pages/follow_page itself doesn't need the compound
	 * lock because it runs __get_page_tail_foll() under the
	 * proper PT lock that already serializes against
	 * split_huge_page().
	 */
	unsigned long flags;
	bool got;
	struct page *page_head = compound_head(page);

	/* Ref to put_compound_page() comment. */
	if (!__compound_tail_refcounted(page_head)) {
		smp_rmb();
		if (likely(PageTail(page))) {
			/*
			 * This is a hugetlbfs page or a slab
			 * page. __split_huge_page_refcount
			 * cannot race here.
			 */
			VM_BUG_ON_PAGE(!PageHead(page_head), page_head);
			__get_page_tail_foll(page, true);
			return true;
		} else {
			/*
			 * __split_huge_page_refcount run
			 * before us, "page" was a THP
			 * tail. The split page_head has been
			 * freed and reallocated as slab or
			 * hugetlbfs page of smaller order
			 * (only possible if reallocated as
			 * slab on x86).
			 */
			return false;
		}
	}

	got = false;
	if (likely(page != page_head && get_page_unless_zero(page_head))) {
		/*
		 * page_head wasn't a dangling pointer but it
		 * may not be a head page anymore by the time
		 * we obtain the lock. That is ok as long as it
		 * can't be freed from under us.
		 */
		flags = compound_lock_irqsave(page_head);
		/* here __split_huge_page_refcount won't run anymore */
		if (likely(PageTail(page))) {
			__get_page_tail_foll(page, false);
			got = true;
		}
		compound_unlock_irqrestore(page_head, flags);
		if (unlikely(!got))
			put_page(page_head);
	}
	return got;
}
EXPORT_SYMBOL(__get_page_tail);

/**
 * put_pages_list() - release a list of pages
 * @pages: list of pages threaded on page->lru
 *
 * Release a list of pages which are strung together on page.lru.  Currently
 * used by read_cache_pages() and related error recovery code.
 */
void put_pages_list(struct list_head *pages)
{
	while (!list_empty(pages)) {
		struct page *victim;

		victim = list_entry(pages->prev, struct page, lru);
		list_del(&victim->lru);
		page_cache_release(victim);
	}
}
EXPORT_SYMBOL(put_pages_list);

/*
 * get_kernel_pages() - pin kernel pages in memory
 * @kiov:	An array of struct kvec structures
 * @nr_segs:	number of segments to pin
 * @write:	pinning for read/write, currently ignored
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_segs long.
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with.
 */
int get_kernel_pages(const struct kvec *kiov, int nr_segs, int write,
		struct page **pages)
{
	int seg;

	for (seg = 0; seg < nr_segs; seg++) {
		if (WARN_ON(kiov[seg].iov_len != PAGE_SIZE))
			return seg;

		pages[seg] = kmap_to_page(kiov[seg].iov_base);
		page_cache_get(pages[seg]);
	}

	return seg;
}
EXPORT_SYMBOL_GPL(get_kernel_pages);

/*
 * get_kernel_page() - pin a kernel page in memory
 * @start:	starting kernel address
 * @write:	pinning for read/write, currently ignored
 * @pages:	array that receives pointer to the page pinned.
 *		Must be at least nr_segs long.
 *
 * Returns 1 if page is pinned. If the page was not pinned, returns
 * -errno. The page returned must be released with a put_page() call
 * when it is finished with.
 */
int get_kernel_page(unsigned long start, int write, struct page **pages)
{
	const struct kvec kiov = {
		.iov_base = (void *)start,
		.iov_len = PAGE_SIZE
	};

	return get_kernel_pages(&kiov, 1, write, pages);
}
EXPORT_SYMBOL_GPL(get_kernel_page);

/* 将缓存中的页做move_fn处理，然后对页进行page->_count--
 * 当所有页加入到lru缓存中时，都要page->_count++
 */
static void pagevec_lru_move_fn(struct pagevec *pvec,
	void (*move_fn)(struct page *page, struct lruvec *lruvec, void *arg),
	void *arg)
{
	int i;
	struct zone *zone = NULL;
	struct lruvec *lruvec;
	unsigned long flags = 0;

	/* 遍历pagevec中的所有页
	 * pagevec_count()返回lru缓存pvec中已经加入的页的数量
	 */
	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		/* 获取页所在的zone */
		struct zone *pagezone = page_zone(page);

		/* 由于不同页可能加入到的zone不同，这样就是判断是否是同一个zone，是的话就不需要上锁了
		 * 不是的话要先把之前上锁的zone解锁，再对此zone的lru_lock上锁
		 */
		if (pagezone != zone) {
			/* 对之前的zone进行解锁，如果是第一次循环则不需要 */
			if (zone)
				spin_unlock_irqrestore(&zone->lru_lock, flags);
			/* 设置上次访问的zone */
			zone = pagezone;
			/* 这里会上锁，因为当前zone没有上锁，后面加入lru的时候就不需要上锁 */
			spin_lock_irqsave(&zone->lru_lock, flags);
		}

		/* 获取zone的lru链表 */
		lruvec = mem_cgroup_page_lruvec(page, zone);
		/* 将page加入到zone的lru链表中 */
		(*move_fn)(page, lruvec, arg);
	}
	/* 遍历结束，对zone解锁 */
	if (zone)
		spin_unlock_irqrestore(&zone->lru_lock, flags);
	/* 对pagevec中所有页的page->_count-- */
	release_pages(pvec->pages, pvec->nr, pvec->cold);
	/* pvec->nr = 0 */
	pagevec_reinit(pvec);
}

/* 将lru缓存pvec中的页移动到非活动lru链表尾部操作的回调函数
 * 这些页原本就属于非活动lru链表
 */
static void pagevec_move_tail_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	int *pgmoved = arg;

	/* 页属于非活动页 */
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		/* 获取页应该放入匿名页lru链表还是文件页lru链表，通过页的PG_swapbacked标志判断 */
		enum lru_list lru = page_lru_base_type(page);
		/* 加入到对应的非活动lru链表尾部 */
		list_move_tail(&page->lru, &lruvec->lists[lru]);
		(*pgmoved)++;
	}
}

/*
 * pagevec_move_tail() must be called with IRQ disabled.
 * Otherwise this may cause nasty races.
 */
/* 将lru缓存pvec中的页移动到非活动lru链表尾部
 * 这些页原本就属于非活动lru链表
 */
static void pagevec_move_tail(struct pagevec *pvec)
{
	int pgmoved = 0;

	pagevec_lru_move_fn(pvec, pagevec_move_tail_fn, &pgmoved);
	__count_vm_events(PGROTATED, pgmoved);
}

/*
 * Writeback is about to end against a page which has been marked for immediate
 * reclaim.  If it still appears to be reclaimable, move it to the tail of the
 * inactive list.
 */
/* 将处于非活动lru链表中的页移动到非活动lru链表尾部 
 * 如果页是处于非活动匿名页lru链表，那么就加入到非活动匿名页lru链表尾部
 * 如果页是处于非活动文件页lru链表，那么就加入到非活动文件页lru链表尾部
 */
void rotate_reclaimable_page(struct page *page)
{

	/* 此页加入到非活动lru链表尾部的条件
	 * 页当前不能被上锁(并不是锁在内存，而是每个页自己的锁PG_locked)
	 * 页必须不能是脏页(这里应该也不会是脏页)
	 * 页必须非活动的(如果页是活动的，那页如果在lru链表中，那肯定是在活动lru链表)
	 * 页没有被锁在内存中
	 * 页处于lru链表中
	 */
	if (!PageLocked(page) && !PageDirty(page) && !PageActive(page) &&
	    !PageUnevictable(page) && PageLRU(page)) {
		struct pagevec *pvec;
		unsigned long flags;

		/* page->_count++，因为这里会加入到lru_rotate_pvecs这个lru缓存中 
		 * lru缓存中的页移动到lru时，会对移动的页page->_count--
		 */
		page_cache_get(page);
		/* 禁止中断 */
		local_irq_save(flags);
		/* 获取当前CPU的lru_rotate_pvecs缓存 */
		pvec = this_cpu_ptr(&lru_rotate_pvecs);
		if (!pagevec_add(pvec, page))
			/* lru_rotate_pvecs缓存已满，将当前缓存中的页加入到非活动lru链表尾部 */
			pagevec_move_tail(pvec);
		/* 重新开启中断 */
		local_irq_restore(flags);
	}
}

static void update_page_reclaim_stat(struct lruvec *lruvec,
				     int file, int rotated)
{
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;

	reclaim_stat->recent_scanned[file]++;
	if (rotated)
		reclaim_stat->recent_rotated[file]++;
}

/* 设置页为活动页，并加入到对应的活动页lru链表中 */
static void __activate_page(struct page *page, struct lruvec *lruvec,
			    void *arg)
{
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		/* 是否为文件页 */
		int file = page_is_file_cache(page);
		/* 获取lru类型 */
		int lru = page_lru_base_type(page);
		/* 将此页从lru链表中移除 */
		del_page_from_lru_list(page, lruvec, lru);
		/* 设置page的PG_active标志，此标志说明此页在活动页的lru链表中 */
		SetPageActive(page);
		/* 获取类型，lru在这里一般是lru_inactive_file或者lru_inactive_anon
		 * 加上LRU_ACTIVE就变成了lru_active_file或者lru_active_anon
		 */
		lru += LRU_ACTIVE;
		/* 将此页加入到活动页lru链表头 */
		add_page_to_lru_list(page, lruvec, lru);
		trace_mm_lru_activate(page);

		__count_vm_event(PGACTIVATE);
		/* 更新lruvec中zone_reclaim_stat->recent_scanned[file]++和zone_reclaim_stat->recent_rotated[file]++ */
		update_page_reclaim_stat(lruvec, file, 1);
	}
}

#ifdef CONFIG_SMP
static void activate_page_drain(int cpu)
{
	struct pagevec *pvec = &per_cpu(activate_page_pvecs, cpu);

	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, __activate_page, NULL);
}

static bool need_activate_page_drain(int cpu)
{
	return pagevec_count(&per_cpu(activate_page_pvecs, cpu)) != 0;
}

/* smp下使用，设置页为活动页，并加入到对应的活动页lru链表中 */
void activate_page(struct page *page)
{
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		struct pagevec *pvec = &get_cpu_var(activate_page_pvecs);

		page_cache_get(page);
		if (!pagevec_add(pvec, page))
			pagevec_lru_move_fn(pvec, __activate_page, NULL);
		put_cpu_var(activate_page_pvecs);
	}
}

#else
static inline void activate_page_drain(int cpu)
{
}

static bool need_activate_page_drain(int cpu)
{
	return false;
}

/* 设置页为活动页，并加入到对应的活动页lru链表中 */
void activate_page(struct page *page)
{
	struct zone *zone = page_zone(page);

	spin_lock_irq(&zone->lru_lock);
	__activate_page(page, mem_cgroup_page_lruvec(page, zone), NULL);
	spin_unlock_irq(&zone->lru_lock);
}
#endif

/* 将page加入到此CPU对应的lru_add_pvec这个lru缓存中 */
static void __lru_cache_activate_page(struct page *page)
{
	struct pagevec *pvec = &get_cpu_var(lru_add_pvec);
	int i;

	/*
	 * Search backwards on the optimistic assumption that the page being
	 * activated has just been added to this pagevec. Note that only
	 * the local pagevec is examined as a !PageLRU page could be in the
	 * process of being released, reclaimed, migrated or on a remote
	 * pagevec that is currently being drained. Furthermore, marking
	 * a remote pagevec's page PageActive potentially hits a race where
	 * a page is marked PageActive just after it is added to the inactive
	 * list causing accounting errors and BUG_ON checks to trigger.
	 */
	for (i = pagevec_count(pvec) - 1; i >= 0; i--) {
		struct page *pagevec_page = pvec->pages[i];

		if (pagevec_page == page) {
			SetPageActive(page);
			break;
		}
	}

	put_cpu_var(lru_add_pvec);
}

/*
 * Mark a page as having seen activity.
 *
 * inactive,unreferenced	->	inactive,referenced
 * inactive,referenced		->	active,unreferenced
 * active,unreferenced		->	active,referenced
 *
 * When a newly allocated page is not yet visible, so safe for non-atomic ops,
 * __SetPageReferenced(page) may be substituted for mark_page_accessed(page).
 */
/* 标记此页最近被访问过，如果此页为非活动页或者已经被访问过的新页(不在lru中)，并且最近有被访问过(PG_referenced已经被置位)，则将此页移动到活动页lru链表中
 * 如果一个新页，第一次被访问时，设置PG_referenced标志，第二次访问时，加入活动lru链表
 * 注意: 只有在页的PG_referenced置位了，这里面才会将页放到活动页lru链表，因为第一次访问此页时，会设置PG_referenced标志，表明此页最近被访问过，
 * 但是这个页仍留在非活动lru链表中，第二次访问时发现此页的PG_referenced已经被置位，才将此页移动到活动页lru链表中
 * 此函数调用位置:
 * 1.当此页被作为进程的一个匿名页时(do_anonymous_page())
 * 2.当此页被用于映射文件时(filemap_nopage())
 * 3.当此页被作为共享内存区的一个页时(shmem_nopage())
 * 4.当从文件读取数据到此页时(do_generic_file_read())
 * 5.当此页被swap换入的数据填充时(do_swap_page())
 * 6.当在page cache中搜索此页并访问到时(__find_get_block())
 */
void mark_page_accessed(struct page *page)
{
	/* 此页为非活动页，或者不在lru中(一个新页)，并且没有锁在内存中，并且PG_referenced被置位 */
	if (!PageActive(page) && !PageUnevictable(page) &&
			PageReferenced(page)) {

		/*
		 * If the page is on the LRU, queue it for activation via
		 * activate_page_pvecs. Otherwise, assume the page is on a
		 * pagevec, mark it active and it'll be moved to the active
		 * LRU on the next drain.
		 */
		/* 如果此页在lru链表中，将其移动到活动页lru链表头部 */
		if (PageLRU(page))
			activate_page(page);
		else
			/* 此页不在lru链表中，则判断此页在不在lru_add_pvec这个lru缓存中，在则设置此页的PG_active标志 */
			__lru_cache_activate_page(page);
		/* 清除PG_referenced，这里已经将其放入到活动页lru链表中 */
		ClearPageReferenced(page);
		/* 页是文件页 */
		if (page_is_file_cache(page))
			/* zone->inactive_age++ */
			workingset_activation(page);
	} else if (!PageReferenced(page)) {
		/* PG_referenced没有被设置过，这里设置此页最近被访问过，不在lru中的新页这里第一次被访问，第二次访问时就加入到活动lru链表中 */
		SetPageReferenced(page);
	}
}
EXPORT_SYMBOL(mark_page_accessed);

/* 加入到lru_add_pvec缓存中 */
static void __lru_cache_add(struct page *page)
{
	/* 获取此CPU的lru缓存， */
	struct pagevec *pvec = &get_cpu_var(lru_add_pvec);

	/* 当页加入到lru缓存中时，页的page->_count++ 
	 * 在页从lru缓存移动到lru链表时，这些页的page->_count会--
	 */
	page_cache_get(page);
	/* 检查LRU缓存是否已满，如果满则将此lru缓存中的页放到lru链表中 */
	if (!pagevec_space(pvec))
		__pagevec_lru_add(pvec);
	/* 将page加入到此cpu的lru缓存中，注意，加入pagevec实际上只是将pagevec中的pages数组中的某个指针指向此页，如果此页原本属于lru链表，那么现在实际还是在原来的lru链表中 */
	pagevec_add(pvec, page);
	put_cpu_var(lru_add_pvec);
}

/**
 * lru_cache_add: add a page to the page lists
 * @page: the page to add
 */
void lru_cache_add_anon(struct page *page)
{
	if (PageActive(page))
		ClearPageActive(page);
	__lru_cache_add(page);
}

void lru_cache_add_file(struct page *page)
{
	if (PageActive(page))
		ClearPageActive(page);
	__lru_cache_add(page);
}
EXPORT_SYMBOL(lru_cache_add_file);

/**
 * lru_cache_add - add a page to a page list
 * @page: the page to be added to the LRU.
 *
 * Queue the page for addition to the LRU via pagevec. The decision on whether
 * to add the page to the [in]active [file|anon] list is deferred until the
 * pagevec is drained. This gives a chance for the caller of lru_cache_add()
 * have the page added to the active list using mark_page_accessed().
 */
void lru_cache_add(struct page *page)
{
	VM_BUG_ON_PAGE(PageActive(page) && PageUnevictable(page), page);
	VM_BUG_ON_PAGE(PageLRU(page), page);
	__lru_cache_add(page);
}

/**
 * add_page_to_unevictable_list - add a page to the unevictable list
 * @page:  the page to be added to the unevictable list
 *
 * Add page directly to its zone's unevictable list.  To avoid races with
 * tasks that might be making the page evictable, through eg. munlock,
 * munmap or exit, while it's not on the lru, we want to add the page
 * while it's locked or otherwise "invisible" to other tasks.  This is
 * difficult to do when using the pagevec cache, so bypass that.
 */
/* 将页加入到不能换出的页lru链表 */
void add_page_to_unevictable_list(struct page *page)
{
	/* 获取页所在zone */
	struct zone *zone = page_zone(page);
	struct lruvec *lruvec;

	spin_lock_irq(&zone->lru_lock);
	/* 获取zone的lruvec */
	lruvec = mem_cgroup_page_lruvec(page, zone);
	ClearPageActive(page);
	SetPageUnevictable(page);
	SetPageLRU(page);
	add_page_to_lru_list(page, lruvec, LRU_UNEVICTABLE);
	spin_unlock_irq(&zone->lru_lock);
}

/**
 * lru_cache_add_active_or_unevictable
 * @page:  the page to be added to LRU
 * @vma:   vma in which page is mapped for determining reclaimability
 *
 * Place @page on the active or unevictable LRU list, depending on its
 * evictability.  Note that if the page is not evictable, it goes
 * directly back onto it's zone's unevictable list, it does NOT use a
 * per cpu pagevec.
 */
/* 通过判断，将页加入到活动lru缓存或者不能换出页的lru链表 */
void lru_cache_add_active_or_unevictable(struct page *page,
					 struct vm_area_struct *vma)
{
	VM_BUG_ON_PAGE(PageLRU(page), page);

	/* 如果此vma中的页不需要锁到内存中 */
	if (likely((vma->vm_flags & (VM_LOCKED | VM_SPECIAL)) != VM_LOCKED)) {
		/* 设置页属于活动lru链表 */
		SetPageActive(page);
		/* 加入到当前CPU的lru_add缓存中，page->_count++ */
		lru_cache_add(page);
		return;
	}

	if (!TestSetPageMlocked(page)) {
		/*
		 * We use the irq-unsafe __mod_zone_page_stat because this
		 * counter is not modified from interrupt context, and the pte
		 * lock is held(spinlock), which implies preemption disabled.
		 */
		/* 统计锁入内存中的页数量 */
		__mod_zone_page_state(page_zone(page), NR_MLOCK,
				    hpage_nr_pages(page));
		count_vm_event(UNEVICTABLE_PGMLOCKED);
	}
	/* 如果此vma是用于特殊页或者vma中的页需要锁在内存中，将页加入到不能换出的页链表 */
	add_page_to_unevictable_list(page);
}

/*
 * If the page can not be invalidated, it is moved to the
 * inactive list to speed up its reclaim.  It is moved to the
 * head of the list, rather than the tail, to give the flusher
 * threads some time to write it out, as this is much more
 * effective than the single-page writeout from reclaim.
 *
 * If the page isn't page_mapped and dirty/writeback, the page
 * could reclaim asap using PG_reclaim.
 *
 * 1. active, mapped page -> none
 * 2. active, dirty/writeback page -> inactive, head, PG_reclaim
 * 3. inactive, mapped page -> none
 * 4. inactive, dirty/writeback page -> inactive, head, PG_reclaim
 * 5. inactive, clean -> inactive, tail
 * 6. Others -> none
 *
 * In 4, why it moves inactive's head, the VM expects the page would
 * be write it out by flusher threads as this is much more effective
 * than the single-page writeout from reclaim.
 */
/* 将处于活动lru链表中的page移动到非活动lru链表中
 * 此页只有不被锁在内存中，并且没有进程映射了此页的情况下才会移动
 */
static void lru_deactivate_fn(struct page *page, struct lruvec *lruvec,
			      void *arg)
{
	int lru, file;
	bool active;

	/* 此页不在lru中，则不处理此页 */
	if (!PageLRU(page))
		return;

	/* 如果此页被锁在内存中禁止换出，则不处理此页 */
	if (PageUnevictable(page))
		return;

	/* Some processes are using the page */
	/* 有进程映射了此页，也不处理此页 */
	if (page_mapped(page))
		return;

	/* 获取页的活动标志，PG_active */
	active = PageActive(page);
	/* 根据页的PG_swapbacked判断此页是否需要依赖swap分区 */
	file = page_is_file_cache(page);
	/* 获取此页需要加入匿名页或者文件页lru链表，也是通过PG_swapbacked标志判断 */
	lru = page_lru_base_type(page);

	/* 从活动lru链表中删除 */
	del_page_from_lru_list(page, lruvec, lru + active);
	/* 清除PG_active和PG_referenced */
	ClearPageActive(page);
	ClearPageReferenced(page);
	/* 加到非活动页lru链表头部 */
	add_page_to_lru_list(page, lruvec, lru);

	/* 如果此页当前正在回写或者是脏页 */
	if (PageWriteback(page) || PageDirty(page)) {
		/*
		 * PG_reclaim could be raced with end_page_writeback
		 * It can make readahead confusing.  But race window
		 * is _really_ small and  it's non-critical problem.
		 */
		/* 则设置此页需要回收 */
		SetPageReclaim(page);
	} else {
		/*
		 * The page's writeback ends up during pagevec
		 * We moves tha page into tail of inactive.
		 */
		/* 如果此页是干净的，并且非活动的，则将此页移动到非活动lru链表尾部
		 * 因为此页回收起来更简单，不用回写
		 */
		list_move_tail(&page->lru, &lruvec->lists[lru]);
		__count_vm_event(PGROTATED);
	}

	/* 统计 */
	if (active)
		__count_vm_event(PGDEACTIVATE);
	update_page_reclaim_stat(lruvec, file, 0);
}

/*
 * Drain pages out of the cpu's pagevecs.
 * Either "cpu" is the current CPU, and preemption has already been
 * disabled; or "cpu" is being hot-unplugged, and is already dead.
 */
/* 将cpu的pagevec中的页放入到lru链表中 */
void lru_add_drain_cpu(int cpu)
{
	/* 每cpu的pagevec有四个pagevec
	 * lru_add_pvec、lru_rotate_pvecs、lru_deactivate_pvecs、activate_page_pvecs
	 */
	struct pagevec *pvec = &per_cpu(lru_add_pvec, cpu);

	/* 如果lru_add_pvec不为空，则将lru_add_pvec中的页放入lru链表中
	 * 在lru_add_pvec中的页都是新的页，这些页刚加入，并不在lru链表中
	 */
	if (pagevec_count(pvec))
		__pagevec_lru_add(pvec);

	/* 以下处理的页都是在lru中的 */

	/* lru_rotate_pvecs里的页会被放到zone的非活动页lru链表末尾 */
	pvec = &per_cpu(lru_rotate_pvecs, cpu);
	if (pagevec_count(pvec)) {
		unsigned long flags;

		/* No harm done if a racing interrupt already did this */
		local_irq_save(flags);
		/* 在这个lru_rotate_pvecs中的页都是非活动页，将这些页移动到非活动lru链表的末尾 */
		pagevec_move_tail(pvec);
		local_irq_restore(flags);
	}

	pvec = &per_cpu(lru_deactivate_pvecs, cpu);
	/* 将lru_deactivate_pvecs中的页放入zone的非活动lru链表的头，让他们能够优先被回收
	 * 这些页原本应属于活动lru链表中的页，会强制清除PG_activate和PG_referenced，并加入到非活动页lru链表的链表头中
	 */
	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, lru_deactivate_fn, NULL);

	/* 将cpu的activate_page_pvecs中的页放到活动页lru链表头中，这些页原本属于非活动lru链表的页 */
	activate_page_drain(cpu);
}

/**
 * deactivate_page - forcefully deactivate a page
 * @page: page to deactivate
 *
 * This function hints the VM that @page is a good reclaim candidate,
 * for example if its invalidation fails due to the page being dirty
 * or under writeback.
 */
/* 将页移动到非活动lru链表中
 * 此页应该属于活动lru链表中的页
 */
void deactivate_page(struct page *page)
{
	/*
	 * In a workload with many unevictable page such as mprotect, unevictable
	 * page deactivation for accelerating reclaim is pointless.
	 */
	/* 如果页被锁在内存中禁止换出，则跳出 */
	if (PageUnevictable(page))
		return;

	/* page->_count == 1才会进入if语句 
	 * 说明此页已经没有进程进行映射了
	 */
	if (likely(get_page_unless_zero(page))) {
		struct pagevec *pvec = &get_cpu_var(lru_deactivate_pvecs);

		if (!pagevec_add(pvec, page))
			pagevec_lru_move_fn(pvec, lru_deactivate_fn, NULL);
		put_cpu_var(lru_deactivate_pvecs);
	}
}

void lru_add_drain(void)
{
	lru_add_drain_cpu(get_cpu());
	put_cpu();
}

static void lru_add_drain_per_cpu(struct work_struct *dummy)
{
	lru_add_drain();
}

static DEFINE_PER_CPU(struct work_struct, lru_add_drain_work);

void lru_add_drain_all(void)
{
	static DEFINE_MUTEX(lock);
	static struct cpumask has_work;
	int cpu;

	mutex_lock(&lock);
	get_online_cpus();
	cpumask_clear(&has_work);

	for_each_online_cpu(cpu) {
		struct work_struct *work = &per_cpu(lru_add_drain_work, cpu);

		if (pagevec_count(&per_cpu(lru_add_pvec, cpu)) ||
		    pagevec_count(&per_cpu(lru_rotate_pvecs, cpu)) ||
		    pagevec_count(&per_cpu(lru_deactivate_pvecs, cpu)) ||
		    need_activate_page_drain(cpu)) {
			INIT_WORK(work, lru_add_drain_per_cpu);
			schedule_work_on(cpu, work);
			cpumask_set_cpu(cpu, &has_work);
		}
	}

	for_each_cpu(cpu, &has_work)
		flush_work(&per_cpu(lru_add_drain_work, cpu));

	put_online_cpus();
	mutex_unlock(&lock);
}

/**
 * release_pages - batched page_cache_release()
 * @pages: array of pages to release
 * @nr: number of pages
 * @cold: whether the pages are cache cold
 *
 * Decrement the reference count on all the pages in @pages.  If it
 * fell to zero, remove the page from the LRU and free it.
 */
void release_pages(struct page **pages, int nr, bool cold)
{
	int i;
	LIST_HEAD(pages_to_free);
	struct zone *zone = NULL;
	struct lruvec *lruvec;
	unsigned long uninitialized_var(flags);
	unsigned int uninitialized_var(lock_batch);

	for (i = 0; i < nr; i++) {
		struct page *page = pages[i];

		/* 大页的情况 */
		if (unlikely(PageCompound(page))) {
			if (zone) {
				spin_unlock_irqrestore(&zone->lru_lock, flags);
				zone = NULL;
			}
			put_compound_page(page);
			continue;
		}

		/*
		 * Make sure the IRQ-safe lock-holding time does not get
		 * excessive with a continuous string of pages from the
		 * same zone. The lock is held only if zone != NULL.
		 */
		if (zone && ++lock_batch == SWAP_CLUSTER_MAX) {
			spin_unlock_irqrestore(&zone->lru_lock, flags);
			zone = NULL;
		}


		/* 对页的page->_count-- */
		if (!put_page_testzero(page))
			continue;

		/* 如果页在lru中，并且page->_count == 0，这些页会被释放掉 */
		if (PageLRU(page)) {
			struct zone *pagezone = page_zone(page);

			if (pagezone != zone) {
				if (zone)
					spin_unlock_irqrestore(&zone->lru_lock,
									flags);
				lock_batch = 0;
				zone = pagezone;
				spin_lock_irqsave(&zone->lru_lock, flags);
			}

			lruvec = mem_cgroup_page_lruvec(page, zone);
			VM_BUG_ON_PAGE(!PageLRU(page), page);
			/* 从lru中拿出来 */
			__ClearPageLRU(page);
			del_page_from_lru_list(page, lruvec, page_off_lru(page));
		}

		/* Clear Active bit in case of parallel mark_page_accessed */
		__ClearPageActive(page);

		/* 加入需要释放的页的链表 */
		list_add(&page->lru, &pages_to_free);
	}
	if (zone)
		spin_unlock_irqrestore(&zone->lru_lock, flags);

	mem_cgroup_uncharge_list(&pages_to_free);
	free_hot_cold_page_list(&pages_to_free, cold);
}
EXPORT_SYMBOL(release_pages);

/*
 * The pages which we're about to release may be in the deferred lru-addition
 * queues.  That would prevent them from really being freed right now.  That's
 * OK from a correctness point of view but is inefficient - those pages may be
 * cache-warm and we want to give them back to the page allocator ASAP.
 *
 * So __pagevec_release() will drain those queues here.  __pagevec_lru_add()
 * and __pagevec_lru_add_active() call release_pages() directly to avoid
 * mutual recursion.
 */
void __pagevec_release(struct pagevec *pvec)
{
	lru_add_drain();
	release_pages(pvec->pages, pagevec_count(pvec), pvec->cold);
	pagevec_reinit(pvec);
}
EXPORT_SYMBOL(__pagevec_release);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/* used by __split_huge_page_refcount() */
void lru_add_page_tail(struct page *page, struct page *page_tail,
		       struct lruvec *lruvec, struct list_head *list)
{
	const int file = 0;

	VM_BUG_ON_PAGE(!PageHead(page), page);
	VM_BUG_ON_PAGE(PageCompound(page_tail), page);
	VM_BUG_ON_PAGE(PageLRU(page_tail), page);
	VM_BUG_ON(NR_CPUS != 1 &&
		  !spin_is_locked(&lruvec_zone(lruvec)->lru_lock));

	if (!list)
		SetPageLRU(page_tail);

	if (likely(PageLRU(page)))
		list_add_tail(&page_tail->lru, &page->lru);
	else if (list) {
		/* page reclaim is reclaiming a huge page */
		get_page(page_tail);
		list_add_tail(&page_tail->lru, list);
	} else {
		struct list_head *list_head;
		/*
		 * Head page has not yet been counted, as an hpage,
		 * so we must account for each subpage individually.
		 *
		 * Use the standard add function to put page_tail on the list,
		 * but then correct its position so they all end up in order.
		 */
		add_page_to_lru_list(page_tail, lruvec, page_lru(page_tail));
		list_head = page_tail->lru.prev;
		list_move_tail(&page_tail->lru, list_head);
	}

	if (!PageUnevictable(page))
		update_page_reclaim_stat(lruvec, file, PageActive(page_tail));
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

/* 将lru_add缓存中的页加入到lru链表中 */
static void __pagevec_lru_add_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	/* 判断此页是否是page cache页(映射文件的页) */
	int file = page_is_file_cache(page);
	/* 是否是活跃的页 
	 * 主要判断page的PG_active标志
	 * 如果此标志置位了，则将此页加入到活动lru链表中
	 * 如果没置位，则加入到非活动lru链表中
	 */
	int active = PageActive(page);
	/* 获取page所在的lru链表，里面会检测是映射页还是文件页，并且检查PG_active，最后能得出该page应该放到哪个lru链表中 
	 * 里面就可以判断出此页需要加入到哪个lru链表中
	 * 如果PG_active置位，则加入到活动lru链表，否则加入到非活动lru链表
	 * 如果PG_swapbacked置位，则加入到匿名页lru链表，否则加入到文件页lru链表
	 */
	enum lru_list lru = page_lru(page);

	VM_BUG_ON_PAGE(PageLRU(page), page);

	SetPageLRU(page);
	/* 将page加入到lru中 */
	add_page_to_lru_list(page, lruvec, lru);
	/* 更新lruvec中的reclaim_stat */
	update_page_reclaim_stat(lruvec, file, active);
	trace_mm_lru_insertion(page, lru);
}

/*
 * Add the passed pages to the LRU, then drop the caller's refcount
 * on them.  Reinitialises the caller's pagevec.
 */
/* 将pagevec中的页加入到lru链表中，并且会将pvec->nr设置为0 */
void __pagevec_lru_add(struct pagevec *pvec)
{
	/* __pagevec_lru_add_fn为回调函数 */
	pagevec_lru_move_fn(pvec, __pagevec_lru_add_fn, NULL);
}
EXPORT_SYMBOL(__pagevec_lru_add);

/**
 * pagevec_lookup_entries - gang pagecache lookup
 * @pvec:	Where the resulting entries are placed
 * @mapping:	The address_space to search
 * @start:	The starting entry index
 * @nr_entries:	The maximum number of entries
 * @indices:	The cache indices corresponding to the entries in @pvec
 *
 * pagevec_lookup_entries() will search for and return a group of up
 * to @nr_entries pages and shadow entries in the mapping.  All
 * entries are placed in @pvec.  pagevec_lookup_entries() takes a
 * reference against actual pages in @pvec.
 *
 * The search returns a group of mapping-contiguous entries with
 * ascending indexes.  There may be holes in the indices due to
 * not-present entries.
 *
 * pagevec_lookup_entries() returns the number of entries which were
 * found.
 */
unsigned pagevec_lookup_entries(struct pagevec *pvec,
				struct address_space *mapping,
				pgoff_t start, unsigned nr_pages,
				pgoff_t *indices)
{
	pvec->nr = find_get_entries(mapping, start, nr_pages,
				    pvec->pages, indices);
	return pagevec_count(pvec);
}

/**
 * pagevec_remove_exceptionals - pagevec exceptionals pruning
 * @pvec:	The pagevec to prune
 *
 * pagevec_lookup_entries() fills both pages and exceptional radix
 * tree entries into the pagevec.  This function prunes all
 * exceptionals from @pvec without leaving holes, so that it can be
 * passed on to page-only pagevec operations.
 */
void pagevec_remove_exceptionals(struct pagevec *pvec)
{
	int i, j;

	for (i = 0, j = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		if (!radix_tree_exceptional_entry(page))
			pvec->pages[j++] = page;
	}
	pvec->nr = j;
}

/**
 * pagevec_lookup - gang pagecache lookup
 * @pvec:	Where the resulting pages are placed
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @nr_pages:	The maximum number of pages
 *
 * pagevec_lookup() will search for and return a group of up to @nr_pages pages
 * in the mapping.  The pages are placed in @pvec.  pagevec_lookup() takes a
 * reference against the pages in @pvec.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 *
 * pagevec_lookup() returns the number of pages which were found.
 */
unsigned pagevec_lookup(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t start, unsigned nr_pages)
{
	pvec->nr = find_get_pages(mapping, start, nr_pages, pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup);

unsigned pagevec_lookup_tag(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t *index, int tag, unsigned nr_pages)
{
	pvec->nr = find_get_pages_tag(mapping, index, tag,
					nr_pages, pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup_tag);

/*
 * Perform any setup for the swap system
 */
void __init swap_setup(void)
{
	unsigned long megs = totalram_pages >> (20 - PAGE_SHIFT);
#ifdef CONFIG_SWAP
	int i;

	if (bdi_init(swapper_spaces[0].backing_dev_info))
		panic("Failed to init swap bdi");
	for (i = 0; i < MAX_SWAPFILES; i++) {
		spin_lock_init(&swapper_spaces[i].tree_lock);
		INIT_LIST_HEAD(&swapper_spaces[i].i_mmap_nonlinear);
	}
#endif

	/* Use a smaller cluster for small-memory machines */
	if (megs < 16)
		page_cluster = 2;
	else
		page_cluster = 3;
	/*
	 * Right now other parts of the system means that we
	 * _really_ don't want to cluster much more
	 */
}
