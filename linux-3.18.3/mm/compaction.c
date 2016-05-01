/*
 * linux/mm/compaction.c
 *
 * Memory compaction for the reduction of external fragmentation. Note that
 * this heavily depends upon page migration to do all the real heavy
 * lifting
 *
 * Copyright IBM Corp. 2007-2010 Mel Gorman <mel@csn.ul.ie>
 */
#include <linux/swap.h>
#include <linux/migrate.h>
#include <linux/compaction.h>
#include <linux/mm_inline.h>
#include <linux/backing-dev.h>
#include <linux/sysctl.h>
#include <linux/sysfs.h>
#include <linux/balloon_compaction.h>
#include <linux/page-isolation.h>
#include "internal.h"

#ifdef CONFIG_COMPACTION
static inline void count_compact_event(enum vm_event_item item)
{
	count_vm_event(item);
}

static inline void count_compact_events(enum vm_event_item item, long delta)
{
	count_vm_events(item, delta);
}
#else
#define count_compact_event(item) do { } while (0)
#define count_compact_events(item, delta) do { } while (0)
#endif

#if defined CONFIG_COMPACTION || defined CONFIG_CMA

#define CREATE_TRACE_POINTS
#include <trace/events/compaction.h>

static unsigned long release_freepages(struct list_head *freelist)
{
	struct page *page, *next;
	unsigned long count = 0;

	list_for_each_entry_safe(page, next, freelist, lru) {
		list_del(&page->lru);
		__free_page(page);
		count++;
	}

	return count;
}

static void map_pages(struct list_head *list)
{
	struct page *page;

	list_for_each_entry(page, list, lru) {
		arch_alloc_page(page, 0);
		kernel_map_pages(page, 1, 1);
	}
}

static inline bool migrate_async_suitable(int migratetype)
{
	/* 如果是MIGRATE_CMA类型或者MIGRATE_MOVABLE，则返回真 */
	return is_migrate_cma(migratetype) || migratetype == MIGRATE_MOVABLE;
}

/*
 * Check that the whole (or subset of) a pageblock given by the interval of
 * [start_pfn, end_pfn) is valid and within the same zone, before scanning it
 * with the migration of free compaction scanner. The scanners then need to
 * use only pfn_valid_within() check for arches that allow holes within
 * pageblocks.
 *
 * Return struct page pointer of start_pfn, or NULL if checks were not passed.
 *
 * It's possible on some configurations to have a setup like node0 node1 node0
 * i.e. it's possible that all pages within a zones range of pages do not
 * belong to a single zone. We assume that a border between node0 and node1
 * can occur within a single pageblock, but not a node0 node1 node0
 * interleaving within a single pageblock. It is therefore sufficient to check
 * the first and last page of a pageblock and avoid checking each individual
 * page in a pageblock.
 */
static struct page *pageblock_pfn_to_page(unsigned long start_pfn,
				unsigned long end_pfn, struct zone *zone)
{
	struct page *start_page;
	struct page *end_page;

	/* end_pfn is one past the range we are checking */
	end_pfn--;

	if (!pfn_valid(start_pfn) || !pfn_valid(end_pfn))
		return NULL;

	start_page = pfn_to_page(start_pfn);

	if (page_zone(start_page) != zone)
		return NULL;

	end_page = pfn_to_page(end_pfn);

	/* This gives a shorter code than deriving page_zone(end_page) */
	if (page_zone_id(start_page) != page_zone_id(end_page))
		return NULL;

	return start_page;
}

#ifdef CONFIG_COMPACTION
/* Returns true if the pageblock should be scanned for pages to isolate. */
static inline bool isolation_suitable(struct compact_control *cc,
					struct page *page)
{
	if (cc->ignore_skip_hint)
		return true;

	return !get_pageblock_skip(page);
}

/*
 * This function is called to clear all cached information on pageblocks that
 * should be skipped for page isolation when the migrate and free page scanner
 * meet.
 */
static void __reset_isolation_suitable(struct zone *zone)
{
	/* 管理区开始页框 */
	unsigned long start_pfn = zone->zone_start_pfn;
	/* 管理区结束页框 */
	unsigned long end_pfn = zone_end_pfn(zone);
	unsigned long pfn;

	/* 0中是用于异步，1中是用于同步，保存可移动页框扫描的起始位置，为管理区第一个页框 */
	zone->compact_cached_migrate_pfn[0] = start_pfn;
	zone->compact_cached_migrate_pfn[1] = start_pfn;
	/* 设置空闲页框扫描起始位置为管理区最后一个页框 */
	zone->compact_cached_free_pfn = end_pfn;
	zone->compact_blockskip_flush = false;

	/* Walk the zone and mark every pageblock as suitable for isolation */
	/* 遍历管理区所有页框，每次走1024个页框，也就是1024个页框为一个pageblock */
	for (pfn = start_pfn; pfn < end_pfn; pfn += pageblock_nr_pages) {
		struct page *page;
		/* 检查是否需要调度 */
		cond_resched();

		/* 是否为有效页框号 */
		if (!pfn_valid(pfn))
			continue;

		/* 页描述符 */
		page = pfn_to_page(pfn);
		/* 判断是否处于此管理区 */
		if (zone != page_zone(page))
			continue;
		/* 把此页框块的首页描述符中PB_migrate_skip置0，看起来是让所有页框都要进行压缩 */
		clear_pageblock_skip(page);
	}
}

void reset_isolation_suitable(pg_data_t *pgdat)
{
	int zoneid;

	for (zoneid = 0; zoneid < MAX_NR_ZONES; zoneid++) {
		struct zone *zone = &pgdat->node_zones[zoneid];
		if (!populated_zone(zone))
			continue;

		/* Only flush if a full compaction finished recently */
		if (zone->compact_blockskip_flush)
			__reset_isolation_suitable(zone);
	}
}

/*
 * If no pages were isolated then mark this pageblock to be skipped in the
 * future. The information is later cleared by __reset_isolation_suitable().
 */
static void update_pageblock_skip(struct compact_control *cc,
			struct page *page, unsigned long nr_isolated,
			bool migrate_scanner)
{
	struct zone *zone = cc->zone;
	unsigned long pfn;

	if (cc->ignore_skip_hint)
		return;

	if (!page)
		return;

	if (nr_isolated)
		return;

	set_pageblock_skip(page);

	pfn = page_to_pfn(page);

	/* Update where async and sync compaction should restart */
	if (migrate_scanner) {
		if (cc->finished_update_migrate)
			return;
		if (pfn > zone->compact_cached_migrate_pfn[0])
			zone->compact_cached_migrate_pfn[0] = pfn;
		if (cc->mode != MIGRATE_ASYNC &&
		    pfn > zone->compact_cached_migrate_pfn[1])
			zone->compact_cached_migrate_pfn[1] = pfn;
	} else {
		if (cc->finished_update_free)
			return;
		if (pfn < zone->compact_cached_free_pfn)
			zone->compact_cached_free_pfn = pfn;
	}
}
#else
static inline bool isolation_suitable(struct compact_control *cc,
					struct page *page)
{
	return true;
}

static void update_pageblock_skip(struct compact_control *cc,
			struct page *page, unsigned long nr_isolated,
			bool migrate_scanner)
{
}
#endif /* CONFIG_COMPACTION */

/*
 * Compaction requires the taking of some coarse locks that are potentially
 * very heavily contended. For async compaction, back out if the lock cannot
 * be taken immediately. For sync compaction, spin on the lock if needed.
 *
 * Returns true if the lock is held
 * Returns false if the lock is not held and compaction should abort
 */
static bool compact_trylock_irqsave(spinlock_t *lock, unsigned long *flags,
						struct compact_control *cc)
{
	if (cc->mode == MIGRATE_ASYNC) {
		if (!spin_trylock_irqsave(lock, *flags)) {
			cc->contended = COMPACT_CONTENDED_LOCK;
			return false;
		}
	} else {
		spin_lock_irqsave(lock, *flags);
	}

	return true;
}

/*
 * Compaction requires the taking of some coarse locks that are potentially
 * very heavily contended. The lock should be periodically unlocked to avoid
 * having disabled IRQs for a long time, even when there is nobody waiting on
 * the lock. It might also be that allowing the IRQs will result in
 * need_resched() becoming true. If scheduling is needed, async compaction
 * aborts. Sync compaction schedules.
 * Either compaction type will also abort if a fatal signal is pending.
 * In either case if the lock was locked, it is dropped and not regained.
 *
 * Returns true if compaction should abort due to fatal signal pending, or
 *		async compaction due to need_resched()
 * Returns false when compaction can continue (sync compaction might have
 *		scheduled)
 */
static bool compact_unlock_should_abort(spinlock_t *lock,
		unsigned long flags, bool *locked, struct compact_control *cc)
{
	if (*locked) {
		spin_unlock_irqrestore(lock, flags);
		*locked = false;
	}

	if (fatal_signal_pending(current)) {
		cc->contended = COMPACT_CONTENDED_SCHED;
		return true;
	}

	if (need_resched()) {
		if (cc->mode == MIGRATE_ASYNC) {
			cc->contended = COMPACT_CONTENDED_SCHED;
			return true;
		}
		cond_resched();
	}

	return false;
}

/*
 * Aside from avoiding lock contention, compaction also periodically checks
 * need_resched() and either schedules in sync compaction or aborts async
 * compaction. This is similar to what compact_unlock_should_abort() does, but
 * is used where no lock is concerned.
 *
 * Returns false when no scheduling was needed, or sync compaction scheduled.
 * Returns true when async compaction should abort.
 */
static inline bool compact_should_abort(struct compact_control *cc)
{
	/* async compaction aborts if contended */
	if (need_resched()) {
		if (cc->mode == MIGRATE_ASYNC) {
			cc->contended = COMPACT_CONTENDED_SCHED;
			return true;
		}

		cond_resched();
	}

	return false;
}

/* Returns true if the page is within a block suitable for migration to */
static bool suitable_migration_target(struct page *page)
{
	/* If the page is a large free page, then disallow migration */
	if (PageBuddy(page)) {
		/*
		 * We are checking page_order without zone->lock taken. But
		 * the only small danger is that we skip a potentially suitable
		 * pageblock, so it's not worth to check order for valid range.
		 */
		if (page_order_unsafe(page) >= pageblock_order)
			return false;
	}

	/* If the block is MIGRATE_MOVABLE or MIGRATE_CMA, allow migration */
	if (migrate_async_suitable(get_pageblock_migratetype(page)))
		return true;

	/* Otherwise skip the block */
	return false;
}

/*
 * Isolate free pages onto a private freelist. If @strict is true, will abort
 * returning 0 on any invalid PFNs or non-free pages inside of the pageblock
 * (even though it may still end up isolating some pages).
 */
/* 扫描从start_pfn到end_pfn的空闲页框，并把它们放入到freelist中，返回此pageblock中总共获得的空闲页框数量 */
static unsigned long isolate_freepages_block(struct compact_control *cc,
				unsigned long *start_pfn,
				unsigned long end_pfn,
				struct list_head *freelist,
				bool strict)
{
	int nr_scanned = 0, total_isolated = 0;
	struct page *cursor, *valid_page = NULL;
	unsigned long flags = 0;
	bool locked = false;
	unsigned long blockpfn = *start_pfn;

	cursor = pfn_to_page(blockpfn);

	/* Isolate free pages. */
	/* 从pageblock的start向end进行扫描 */
	for (; blockpfn < end_pfn; blockpfn++, cursor++) {
		int isolated, i;
		/* 当前页框 */
		struct page *page = cursor;

		/*
		 * Periodically drop the lock (if held) regardless of its
		 * contention, to give chance to IRQs. Abort if fatal signal
		 * pending or async compaction detects need_resched()
		 */
		if (!(blockpfn % SWAP_CLUSTER_MAX)
		    && compact_unlock_should_abort(&cc->zone->lock, flags,
								&locked, cc))
			break;

		nr_scanned++;
		/* 检查此页框号是否正确 */
		if (!pfn_valid_within(blockpfn))
			goto isolate_fail;

		/* valid_page是开始扫描的页框 */
		if (!valid_page)
			valid_page = page;
		/* 检查此页是否在伙伴系统中，不在说明是正在使用的页框，则跳过 */
		if (!PageBuddy(page))
			goto isolate_fail;

		/*
		 * If we already hold the lock, we can skip some rechecking.
		 * Note that if we hold the lock now, checked_pageblock was
		 * already set in some previous iteration (or strict is true),
		 * so it is correct to skip the suitable migration target
		 * recheck as well.
		 */
		/* 获取锁 */
		if (!locked) {
			/*
			 * The zone lock must be held to isolate freepages.
			 * Unfortunately this is a very coarse lock and can be
			 * heavily contended if there are parallel allocations
			 * or parallel compactions. For async compaction do not
			 * spin on the lock and we acquire the lock as late as
			 * possible.
			 */
			locked = compact_trylock_irqsave(&cc->zone->lock,
								&flags, cc);
			if (!locked)
				break;

			/* Recheck this is a buddy page under lock */
			if (!PageBuddy(page))
				goto isolate_fail;
		}

		/* Found a free page, break it into order-0 pages */
		/* 将page开始的连续空闲页框拆分为连续的单个页框，返回数量，order值会在page的页描述符中，这里有可能会设置pageblock的类型 */
		isolated = split_free_page(page);
		/* 更新总共获得的空闲页框 */
		total_isolated += isolated;
		/* 将isolated数量个单个页框放入freelist中 */
		for (i = 0; i < isolated; i++) {
			list_add(&page->lru, freelist);
			page++;
		}

		/* If a page was split, advance to the end of it */
		/* 跳过这段连续空闲页框，因为上面把这段空闲页框全部加入到了freelist中 */
		if (isolated) {
			blockpfn += isolated - 1;
			cursor += isolated - 1;
			continue;
		}

isolate_fail:
		if (strict)
			break;
		else
			continue;

	}

	/* Record how far we have got within the block */
	*start_pfn = blockpfn;

	trace_mm_compaction_isolate_freepages(nr_scanned, total_isolated);

	/*
	 * If strict isolation is requested by CMA then check that all the
	 * pages requested were isolated. If there were any failures, 0 is
	 * returned and CMA will fail.
	 */
	if (strict && blockpfn < end_pfn)
		total_isolated = 0;

	/* 如果占有锁则释放掉 */
	if (locked)
		spin_unlock_irqrestore(&cc->zone->lock, flags);

	/* Update the pageblock-skip if the whole pageblock was scanned */
	/* 扫描完了此pageblock，但是total_isolated为0的话，则标记此pageblock为跳过 */
	if (blockpfn == end_pfn)
		update_pageblock_skip(cc, valid_page, total_isolated, false);

	/* 统计 */
	count_compact_events(COMPACTFREE_SCANNED, nr_scanned);
	if (total_isolated)
		count_compact_events(COMPACTISOLATED, total_isolated);
	/* 返回总共获得的空闲页框 */
	return total_isolated;
}

/**
 * isolate_freepages_range() - isolate free pages.
 * @start_pfn: The first PFN to start isolating.
 * @end_pfn:   The one-past-last PFN.
 *
 * Non-free pages, invalid PFNs, or zone boundaries within the
 * [start_pfn, end_pfn) range are considered errors, cause function to
 * undo its actions and return zero.
 *
 * Otherwise, function returns one-past-the-last PFN of isolated page
 * (which may be greater then end_pfn if end fell in a middle of
 * a free page).
 */
unsigned long
isolate_freepages_range(struct compact_control *cc,
			unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long isolated, pfn, block_end_pfn;
	LIST_HEAD(freelist);

	pfn = start_pfn;
	block_end_pfn = ALIGN(pfn + 1, pageblock_nr_pages);

	for (; pfn < end_pfn; pfn += isolated,
				block_end_pfn += pageblock_nr_pages) {
		/* Protect pfn from changing by isolate_freepages_block */
		unsigned long isolate_start_pfn = pfn;

		block_end_pfn = min(block_end_pfn, end_pfn);

		/*
		 * pfn could pass the block_end_pfn if isolated freepage
		 * is more than pageblock order. In this case, we adjust
		 * scanning range to right one.
		 */
		if (pfn >= block_end_pfn) {
			block_end_pfn = ALIGN(pfn + 1, pageblock_nr_pages);
			block_end_pfn = min(block_end_pfn, end_pfn);
		}

		if (!pageblock_pfn_to_page(pfn, block_end_pfn, cc->zone))
			break;

		isolated = isolate_freepages_block(cc, &isolate_start_pfn,
						block_end_pfn, &freelist, true);

		/*
		 * In strict mode, isolate_freepages_block() returns 0 if
		 * there are any holes in the block (ie. invalid PFNs or
		 * non-free pages).
		 */
		if (!isolated)
			break;

		/*
		 * If we managed to isolate pages, it is always (1 << n) *
		 * pageblock_nr_pages for some non-negative n.  (Max order
		 * page may span two pageblocks).
		 */
	}

	/* split_free_page does not map the pages */
	map_pages(&freelist);

	if (pfn < end_pfn) {
		/* Loop terminated early, cleanup. */
		release_freepages(&freelist);
		return 0;
	}

	/* We don't use freelists for anything. */
	return pfn;
}

/* Update the number of anon and file isolated pages in the zone */
static void acct_isolated(struct zone *zone, struct compact_control *cc)
{
	struct page *page;
	unsigned int count[2] = { 0, };

	if (list_empty(&cc->migratepages))
		return;

	list_for_each_entry(page, &cc->migratepages, lru)
		count[!!page_is_file_cache(page)]++;

	mod_zone_page_state(zone, NR_ISOLATED_ANON, count[0]);
	mod_zone_page_state(zone, NR_ISOLATED_FILE, count[1]);
}

/* Similar to reclaim, but different enough that they don't share logic */
static bool too_many_isolated(struct zone *zone)
{
	unsigned long active, inactive, isolated;

	inactive = zone_page_state(zone, NR_INACTIVE_FILE) +
					zone_page_state(zone, NR_INACTIVE_ANON);
	active = zone_page_state(zone, NR_ACTIVE_FILE) +
					zone_page_state(zone, NR_ACTIVE_ANON);
	isolated = zone_page_state(zone, NR_ISOLATED_FILE) +
					zone_page_state(zone, NR_ISOLATED_ANON);

	return isolated > (inactive + active) / 2;
}

/**
 * isolate_migratepages_block() - isolate all migrate-able pages within
 *				  a single pageblock
 * @cc:		Compaction control structure.
 * @low_pfn:	The first PFN to isolate
 * @end_pfn:	The one-past-the-last PFN to isolate, within same pageblock
 * @isolate_mode: Isolation mode to be used.
 *
 * Isolate all pages that can be migrated from the range specified by
 * [low_pfn, end_pfn). The range is expected to be within same pageblock.
 * Returns zero if there is a fatal signal pending, otherwise PFN of the
 * first page that was not scanned (which may be both less, equal to or more
 * than end_pfn).
 *
 * The pages are isolated on cc->migratepages list (not required to be empty),
 * and cc->nr_migratepages is updated accordingly. The cc->migrate_pfn field
 * is neither read nor updated.
 */
/* 将一个pageblock中所有可以移动的页框隔离出来 */
static unsigned long
isolate_migratepages_block(struct compact_control *cc, unsigned long low_pfn,
			unsigned long end_pfn, isolate_mode_t isolate_mode)
{
	struct zone *zone = cc->zone;
	unsigned long nr_scanned = 0, nr_isolated = 0;
	/* 待移动的页框链表 */
	struct list_head *migratelist = &cc->migratepages;
	struct lruvec *lruvec;
	unsigned long flags = 0;
	bool locked = false;
	struct page *page = NULL, *valid_page = NULL;

	/*
	 * Ensure that there are not too many pages isolated from the LRU
	 * list by either parallel reclaimers or compaction. If there are,
	 * delay for some time until fewer pages are isolated
	 */
	/* 检查isolated是否小于LRU链表的(inactive + active) / 2，超过了则表示已经将许多页框隔离出来 */
	while (unlikely(too_many_isolated(zone))) {
		/* async migration should just abort */
		/* 如果是异步模式，隔离出来的页多于(inactive + active) / 2，则直接返回 */
		if (cc->mode == MIGRATE_ASYNC)
			return 0;

		/* 进行100ms的休眠，等待设备没那么繁忙 */
		congestion_wait(BLK_RW_ASYNC, HZ/10);

		if (fatal_signal_pending(current))
			return 0;
	}
	/* 如果是异步调用，并且当前进程需要调度的话，返回真 */
	if (compact_should_abort(cc))
		return 0;

	/* Time to isolate some pages for migration */
	/* 遍历每一个页框 */
	for (; low_pfn < end_pfn; low_pfn++) {
		/*
		 * Periodically drop the lock (if held) regardless of its
		 * contention, to give chance to IRQs. Abort async compaction
		 * if contended.
		 */
		/* 这里会释放掉zone->lru_lock这个锁 */
		if (!(low_pfn % SWAP_CLUSTER_MAX)
		    && compact_unlock_should_abort(&zone->lru_lock, flags,
								&locked, cc))
			break;

		if (!pfn_valid_within(low_pfn))
			continue;
		/* 扫描次数++ */
		nr_scanned++;

		/* 根据页框号获取页描述符 */
		page = pfn_to_page(low_pfn);

		/* 设置valid_page */
		if (!valid_page)
			valid_page = page;

		/*
		 * Skip if free. We read page order here without zone lock
		 * which is generally unsafe, but the race window is small and
		 * the worst thing that can happen is that we skip some
		 * potential isolation targets.
		 */
		/* 检查此页是否处于伙伴系统中，主要是通过page->_mapcount判断，如果在伙伴系统中，则跳过这块空闲内存 */
		if (PageBuddy(page)) {
			/* 获取这个页开始的order次方个页框为伙伴系统的一块内存 */
			unsigned long freepage_order = page_order_unsafe(page);

			/*
			 * Without lock, we cannot be sure that what we got is
			 * a valid page order. Consider only values in the
			 * valid order range to prevent low_pfn overflow.
			 */
			if (freepage_order > 0 && freepage_order < MAX_ORDER)
				low_pfn += (1UL << freepage_order) - 1;
			continue;
		}

		/*
		 * Check may be lockless but that's ok as we recheck later.
		 * It's possible to migrate LRU pages and balloon pages
		 * Skip any other type of page
		 */
		/* 以下处理此页不在伙伴系统中的情况，表明此页是在使用的页*/
		/* 如果页不处于lru中的处理，isolated的页是不处于lru中的，用于balloon的页也不处于lru中?
		 * 可移动的页都会在LRU中，不在LRU中的页都会被跳过，这里就把UNMOVABLE进行跳过
		 */
		if (!PageLRU(page)) {
			if (unlikely(balloon_page_movable(page))) {
				if (balloon_page_isolate(page)) {
					/* Successfully isolated */
					goto isolate_success;
				}
			}
			continue;
		}

		/*
		 * PageLRU is set. lru_lock normally excludes isolation
		 * splitting and collapsing (collapsing has already happened
		 * if PageLRU is set) but the lock is not necessarily taken
		 * here and it is wasteful to take it just to check transhuge.
		 * Check TransHuge without lock and skip the whole pageblock if
		 * it's either a transhuge or hugetlbfs page, as calling
		 * compound_order() without preventing THP from splitting the
		 * page underneath us may return surprising results.
		 */
		/* 如果此页是透明大页的处理，也是跳过。透明大页是在系统活动时可以实时配置，不需要重启生效 */
		if (PageTransHuge(page)) {
			if (!locked)
				low_pfn = ALIGN(low_pfn + 1,
						pageblock_nr_pages) - 1;
			else
				low_pfn += (1 << compound_order(page)) - 1;

			continue;
		}

		/*
		 * Migration will fail if an anonymous page is pinned in memory,
		 * so avoid taking lru_lock and isolating it unnecessarily in an
		 * admittedly racy check.
		 */
		/* 如果是一个匿名页，并且此页的page->_count大于page->_mapcount，此页应该处于在其他地方正在被隔离的时候 */
		if (!page_mapping(page) &&
		    page_count(page) > page_mapcount(page))
			continue;

		/* If we already hold the lock, we can skip some rechecking */
		/* 检查是否有上锁，这个锁是zone->lru_lock */
		if (!locked) {
			locked = compact_trylock_irqsave(&zone->lru_lock,
								&flags, cc);
			if (!locked)
				break;
			/* 没上锁的情况，需要检查是否处于LRU中 */
			/* Recheck PageLRU and PageTransHuge under lock */
			if (!PageLRU(page))
				continue;
			/* 如果在lru中，检查是否是大页，做个对齐，防止low_pfn不是页首 */
			if (PageTransHuge(page)) {
				low_pfn += (1 << compound_order(page)) - 1;
				continue;
			}
		}

		lruvec = mem_cgroup_page_lruvec(page, zone);

		/* Try isolate the page */
		/* 将此页从lru中隔离出来 */
		if (__isolate_lru_page(page, isolate_mode) != 0)
			continue;

		VM_BUG_ON_PAGE(PageTransCompound(page), page);

		/* Successfully isolated */
		/* 如果在cgroup的lru缓冲区，则将此页从lru缓冲区中拿出来 */
		del_page_from_lru_list(page, lruvec, page_lru(page));

isolate_success:
		/* 隔离成功，此页已不处于lru中 */
		cc->finished_update_migrate = true;
		/* 将此页加入到本次压缩需要移动页链表中 */
		list_add(&page->lru, migratelist);
		/* 需要移动的页框数量++ */
		cc->nr_migratepages++;
		/* 隔离数量++ */
		nr_isolated++;

		/* Avoid isolating too much */
		/* COMPACT_CLUSTER_MAX代表每次内存压缩所能移动的最大页框数量 */
		if (cc->nr_migratepages == COMPACT_CLUSTER_MAX) {
			++low_pfn;
			break;
		}
	}

	/*
	 * The PageBuddy() check could have potentially brought us outside
	 * the range to be scanned.
	 */
	if (unlikely(low_pfn > end_pfn))
		low_pfn = end_pfn;

	/* 解锁 */
	if (locked)
		spin_unlock_irqrestore(&zone->lru_lock, flags);

	/*
	 * Update the pageblock-skip information and cached scanner pfn,
	 * if the whole pageblock was scanned without isolating any page.
	 */
	/* 如果全部的页框块都扫描过了，并且没有隔离任何一个页，则标记最后这个页所在的pageblock为PB_migrate_skip，然后
	 * 	if (pfn > zone->compact_cached_migrate_pfn[0])
			zone->compact_cached_migrate_pfn[0] = pfn;
		if (cc->mode != MIGRATE_ASYNC &&
		    pfn > zone->compact_cached_migrate_pfn[1])
			zone->compact_cached_migrate_pfn[1] = pfn;
	 *
	 */
	if (low_pfn == end_pfn)
		update_pageblock_skip(cc, valid_page, nr_isolated, true);

	trace_mm_compaction_isolate_migratepages(nr_scanned, nr_isolated);

	/* 统计 */
	count_compact_events(COMPACTMIGRATE_SCANNED, nr_scanned);
	if (nr_isolated)
		count_compact_events(COMPACTISOLATED, nr_isolated);

	return low_pfn;
}

/**
 * isolate_migratepages_range() - isolate migrate-able pages in a PFN range
 * @cc:        Compaction control structure.
 * @start_pfn: The first PFN to start isolating.
 * @end_pfn:   The one-past-last PFN.
 *
 * Returns zero if isolation fails fatally due to e.g. pending signal.
 * Otherwise, function returns one-past-the-last PFN of isolated page
 * (which may be greater than end_pfn if end fell in a middle of a THP page).
 */
unsigned long
isolate_migratepages_range(struct compact_control *cc, unsigned long start_pfn,
							unsigned long end_pfn)
{
	unsigned long pfn, block_end_pfn;

	/* Scan block by block. First and last block may be incomplete */
	pfn = start_pfn;
	block_end_pfn = ALIGN(pfn + 1, pageblock_nr_pages);

	for (; pfn < end_pfn; pfn = block_end_pfn,
				block_end_pfn += pageblock_nr_pages) {

		block_end_pfn = min(block_end_pfn, end_pfn);

		if (!pageblock_pfn_to_page(pfn, block_end_pfn, cc->zone))
			continue;

		pfn = isolate_migratepages_block(cc, pfn, block_end_pfn,
							ISOLATE_UNEVICTABLE);

		/*
		 * In case of fatal failure, release everything that might
		 * have been isolated in the previous iteration, and signal
		 * the failure back to caller.
		 */
		if (!pfn) {
			putback_movable_pages(&cc->migratepages);
			cc->nr_migratepages = 0;
			break;
		}

		if (cc->nr_migratepages == COMPACT_CLUSTER_MAX)
			break;
	}
	acct_isolated(cc->zone, cc);

	return pfn;
}

#endif /* CONFIG_COMPACTION || CONFIG_CMA */
#ifdef CONFIG_COMPACTION
/*
 * Based on information in the current compact_control, find blocks
 * suitable for isolating free pages from and then isolate them.
 */
/* 隔离出空闲页框 */
static void isolate_freepages(struct compact_control *cc)
{
	struct zone *zone = cc->zone;
	struct page *page;
	unsigned long block_start_pfn;	/* start of current pageblock */
	unsigned long isolate_start_pfn; /* exact pfn we start at */
	unsigned long block_end_pfn;	/* end of current pageblock */
	unsigned long low_pfn;	     /* lowest pfn scanner is able to scan */
	int nr_freepages = cc->nr_freepages;
	struct list_head *freelist = &cc->freepages;

	/*
	 * Initialise the free scanner. The starting point is where we last
	 * successfully isolated from, zone-cached value, or the end of the
	 * zone when isolating for the first time. For looping we also need
	 * this pfn aligned down to the pageblock boundary, because we do
	 * block_start_pfn -= pageblock_nr_pages in the for loop.
	 * For ending point, take care when isolating in last pageblock of a
	 * a zone which ends in the middle of a pageblock.
	 * The low boundary is the end of the pageblock the migration scanner
	 * is using.
	 */
	/* 获取开始扫描页框所在的pageblock，并且设置为此pageblock的最后一个页框或者管理区最后一个页框 */
	isolate_start_pfn = cc->free_pfn;
	block_start_pfn = cc->free_pfn & ~(pageblock_nr_pages-1);
	block_end_pfn = min(block_start_pfn + pageblock_nr_pages,
						zone_end_pfn(zone));
	/* 按pageblock_nr_pages对齐，low_pfn保存的是可迁移页框扫描所在的页框号，但是这里有可能migrate_pfn == free_pfn */
	low_pfn = ALIGN(cc->migrate_pfn + 1, pageblock_nr_pages);

	/*
	 * Isolate free pages until enough are available to migrate the
	 * pages on cc->migratepages. We stop searching if the migrate
	 * and free page scanners meet or enough free pages are isolated.
	 */
	/* 开始扫描空闲页框，从管理区最后一个pageblock向migrate_pfn所在的pageblock扫描
	 * block_start_pfn是pageblock开始页框号
	 * block_end_pfn是pageblock结束页框号
	 */
	/* 循环条件， 
	 * 扫描到low_pfn所在pageblokc或者其后一个pageblock，low_pfn是low_pfn保存的是可迁移页框扫描所在的页框号，并按照pageblock_nr_pages对齐。
	 * 并且cc中可移动的页框数量多于cc中空闲页框的数量。由于隔离可移动页是以一个一个pageblock为单位的，所以刚开始时更多是判断cc->nr_migratepages > nr_freepages来决定是否结束
	 * 当扫描到可移动页框扫描所在的pageblock后，则会停止
	 */
	for (; block_start_pfn >= low_pfn && cc->nr_migratepages > nr_freepages;
				block_end_pfn = block_start_pfn,
				block_start_pfn -= pageblock_nr_pages,
				isolate_start_pfn = block_start_pfn) {
		unsigned long isolated;

		/*
		 * This can iterate a massively long zone without finding any
		 * suitable migration targets, so periodically check if we need
		 * to schedule, or even abort async compaction.
		 */
		if (!(block_start_pfn % (SWAP_CLUSTER_MAX * pageblock_nr_pages))
						&& compact_should_abort(cc))
			break;

		/* 检查block_start_pfn和block_end_pfn，如果没问题，返回block_start_pfn所指的页描述符，也就是pageblock第一页描述符 */
		page = pageblock_pfn_to_page(block_start_pfn, block_end_pfn,
									zone);
		if (!page)
			continue;

		/* Check the block is suitable for migration */
		/* 判断是否能够用于迁移页框
		 * 判断条件1: 如果处于伙伴系统中，它所代表的这段连续页框的order值必须小于pageblock的order值
		 * 判断条件2: 此pageblock必须为MIGRATE_MOVABLE或者MIGRATE_CMA类型，而为MIGRATE_RECLAIMABLE类型的pageblock则跳过
		 */
		if (!suitable_migration_target(page))
			continue;

		/* If isolation recently failed, do not retry */
		/* 检查cc中是否标记了即使pageblock标记了跳过也对pageblock进行扫描，并且检查此pageblock是否被标记为跳过 */
		if (!isolation_suitable(cc, page))
			continue;

		/* Found a block suitable for isolating free pages from. */
		/* 扫描从isolate_start_pfn到block_end_pfn的空闲页框，并把它们放入到freelist中，返回此pageblock中总共获得的空闲页框数量 
		 * 第一轮扫描可能会跳过，应该第一次isolate_start_pfn是等于zone最后一个页框的
		 */
		isolated = isolate_freepages_block(cc, &isolate_start_pfn,
					block_end_pfn, freelist, false);
		/* 统计freelist中空闲页框数量 */
		nr_freepages += isolated;

		/*
		 * Remember where the free scanner should restart next time,
		 * which is where isolate_freepages_block() left off.
		 * But if it scanned the whole pageblock, isolate_start_pfn
		 * now points at block_end_pfn, which is the start of the next
		 * pageblock.
		 * In that case we will however want to restart at the start
		 * of the previous pageblock.
		 */
		/* 下次循环开始的页框 */
		cc->free_pfn = (isolate_start_pfn < block_end_pfn) ?
				isolate_start_pfn :
				block_start_pfn - pageblock_nr_pages;

		/*
		 * Set a flag that we successfully isolated in this pageblock.
		 * In the next loop iteration, zone->compact_cached_free_pfn
		 * will not be updated and thus it will effectively contain the
		 * highest pageblock we isolated pages from.
		 */
		/* 设置cc->finished_update_free为true，即表明此次cc获取到了空闲页框链表 */
		if (isolated)
			cc->finished_update_free = true;

		/*
		 * isolate_freepages_block() might have aborted due to async
		 * compaction being contended
		 */
		/* 检查contended，此用于表明是否需要终止 */
		if (cc->contended)
			break;
	}

	/* split_free_page does not map the pages */
	/* 设置页表项，设置为内核使用 */
	map_pages(freelist);

	/*
	 * If we crossed the migrate scanner, we want to keep it that way
	 * so that compact_finished() may detect this
	 */
	/* 保证free_pfn不超过migrate_pfn */
	if (block_start_pfn < low_pfn)
		cc->free_pfn = cc->migrate_pfn;

	cc->nr_freepages = nr_freepages;
}

/*
 * This is a migrate-callback that "allocates" freepages by taking pages
 * from the isolated freelists in the block we are migrating to.
 */
static struct page *compaction_alloc(struct page *migratepage,
					unsigned long data,
					int **result)
{
	/* 获取cc */
	struct compact_control *cc = (struct compact_control *)data;
	struct page *freepage;

	/*
	 * Isolate free pages if necessary, and if we are not aborting due to
	 * contention.
	 */
	/* 如果cc中的空闲页框链表为空 */
	if (list_empty(&cc->freepages)) {
		/* 并且cc->contended没有记录错误代码 */
		if (!cc->contended)
			/* 从cc->free_pfn开始向前获取空闲页 */
			isolate_freepages(cc);

		if (list_empty(&cc->freepages))
			return NULL;
	}
	/* 从cc->freepages链表中拿出一个空闲page */
	freepage = list_entry(cc->freepages.next, struct page, lru);
	list_del(&freepage->lru);
	cc->nr_freepages--;
	
	/* 返回空闲页框 */
	return freepage;
}

/*
 * This is a migrate-callback that "frees" freepages back to the isolated
 * freelist.  All pages on the freelist are from the same zone, so there is no
 * special handling needed for NUMA.
 */
/* 将page释放回到cc中 */
static void compaction_free(struct page *page, unsigned long data)
{
	struct compact_control *cc = (struct compact_control *)data;

	list_add(&page->lru, &cc->freepages);
	cc->nr_freepages++;
}

/* possible outcome of isolate_migratepages */
typedef enum {
	ISOLATE_ABORT,		/* Abort compaction now */
	ISOLATE_NONE,		/* No pages isolated, continue scanning */
	ISOLATE_SUCCESS,	/* Pages isolated, migrate */
} isolate_migrate_t;

/*
 * Isolate all pages that can be migrated from the first suitable block,
 * starting at the block pointed to by the migrate scanner pfn within
 * compact_control.
 */
/* 从cc->migrate_pfn(保存的是扫描可移动页框指针所在的页框号)开始到第一个获取到可移动页框的pageblock结束，获取可移动页框，并放入到cc->migratepages */
static isolate_migrate_t isolate_migratepages(struct zone *zone,
					struct compact_control *cc)
{
	unsigned long low_pfn, end_pfn;
	struct page *page;
	/* 保存同步/异步方式，只有异步的情况下能进行移动页框ISOLATE_ASYNC_MIGRATE */
	const isolate_mode_t isolate_mode =
		(cc->mode == MIGRATE_ASYNC ? ISOLATE_ASYNC_MIGRATE : 0);

	/*
	 * Start at where we last stopped, or beginning of the zone as
	 * initialized by compact_zone()
	 */
	/* 扫描起始页框 */
	low_pfn = cc->migrate_pfn;

	/* Only scan within a pageblock boundary */
	/* 以1024对齐 */
	end_pfn = ALIGN(low_pfn + 1, pageblock_nr_pages);

	/*
	 * Iterate over whole pageblocks until we find the first suitable.
	 * Do not cross the free scanner.
	 */
	for (; end_pfn <= cc->free_pfn;
			low_pfn = end_pfn, end_pfn += pageblock_nr_pages) {

		/*
		 * This can potentially iterate a massively long zone with
		 * many pageblocks unsuitable, so periodically check if we
		 * need to schedule, or even abort async compaction.
		 */
		/* 由于需要扫描很多页框，所以这里做个检查，执行时间过长则睡眠，一般是32个1024页框休眠一下，异步的情况还需要判断运行进程是否需要被调度 */
		if (!(low_pfn % (SWAP_CLUSTER_MAX * pageblock_nr_pages))
						&& compact_should_abort(cc))
			break;

		/* 获取第一个页框，需要检查是否属于此zone */
		page = pageblock_pfn_to_page(low_pfn, end_pfn, zone);
		if (!page)
			continue;

		/* If isolation recently failed, do not retry */
		/* 获取页框的PB_migrate_skip标志，如果设置了则跳过这个1024个页框 */
		if (!isolation_suitable(cc, page))
			continue;

		/*
		 * For async compaction, also only scan in MOVABLE blocks.
		 * Async compaction is optimistic to see if the minimum amount
		 * of work satisfies the allocation.
		 */
		/* 异步情况，如果不是MIGRATE_MOVABLE或MIGRATE_CMA类型则跳过这段页框块 */
		/* 异步不处理RECLAIMABLE的页 */
		if (cc->mode == MIGRATE_ASYNC &&
		    !migrate_async_suitable(get_pageblock_migratetype(page)))
			continue;

		/* Perform the isolation */
		/* 执行完隔离，将low_pfn到end_pfn中正在使用的页框从zone->lru中取出来，返回的是可移动页扫描扫描到的页框号
		 * 而UNMOVABLE类型的页框是不会处于lru链表中的，所以所有不在lru链表中的页都会被跳过
		 * 返回的是扫描到的最后的页
		 */
		low_pfn = isolate_migratepages_block(cc, low_pfn, end_pfn,
								isolate_mode);

		if (!low_pfn || cc->contended)
			return ISOLATE_ABORT;

		/*
		 * Either we isolated something and proceed with migration. Or
		 * we failed and compact_zone should decide if we should
		 * continue or not.
		 */
		/* 跳出，说明这里如果成功只会扫描一个pageblock */
		break;
	}
	/* 统计，里面会再次遍历cc中所有可移动的页，判断它们是RECLAIMABLE还是MOVABLE的页
	 */
	acct_isolated(zone, cc);
	/*
	 * Record where migration scanner will be restarted. If we end up in
	 * the same pageblock as the free scanner, make the scanners fully
	 * meet so that compact_finished() terminates compaction.
	 */
	/* 可移动页扫描到的页框修正 */
	cc->migrate_pfn = (end_pfn <= cc->free_pfn) ? low_pfn : cc->free_pfn;

	return cc->nr_migratepages ? ISOLATE_SUCCESS : ISOLATE_NONE;
}

/* 判断是否结束本次内存压缩 
 * 1.可移动页框扫描的位置是否已经超过了空闲页框扫描的位置，超过则结束压缩
 * 2.判断zone的空闲页框数量是否达到标准，如果没达到zone的low阀值标准则继续
 * 3.判断伙伴系统中是否有比order值大的空闲连续页框块，有则结束压缩
 * 如果是管理员写入到/proc/sys/vm/compact_memory进行强制内存压缩的情况，则判断条件只有第1条
 */
static int compact_finished(struct zone *zone, struct compact_control *cc,
			    const int migratetype)
{
	unsigned int order;
	unsigned long watermark;

	/* 当前进程已经接受了sigkill信号，准备被kill掉的情况，这里就不进行内存压缩了 */
	if (cc->contended || fatal_signal_pending(current))
		return COMPACT_PARTIAL;

	/* Compaction run completes if the migrate and free scanner meet */
	/* 检查可移动页框扫描的位置是否已经超过了空闲页框扫描的位置 */
	if (cc->free_pfn <= cc->migrate_pfn) {
		/* Let the next compaction start anew. */
		/* 超过的情况下，重置可移动页框扫描和空闲页框扫描的起始位置 */
		zone->compact_cached_migrate_pfn[0] = zone->zone_start_pfn;
		zone->compact_cached_migrate_pfn[1] = zone->zone_start_pfn;
		zone->compact_cached_free_pfn = zone_end_pfn(zone);

		/*
		 * Mark that the PG_migrate_skip information should be cleared
		 * by kswapd when it goes to sleep. kswapd does not set the
		 * flag itself as the decision to be clear should be directly
		 * based on an allocation request.
		 */
		/* 如果是在kswapd内核线程中执行的情况下就不会对一些页框进行扫描 
		 * 而如果在alloc_pages()中进行页框压缩的情况下，则会对管理区的所有页框进行扫描
		 */
		if (!current_is_kswapd())
			zone->compact_blockskip_flush = true;

		return COMPACT_COMPLETE;
	}

	/*
	 * order == -1 is expected when compacting via
	 * /proc/sys/vm/compact_memory
	 */
	/* 如果是管理员写入到/proc/sys/vm/compact_memory进行强制内存压缩的情况，则继续压缩 */
	if (cc->order == -1)
		return COMPACT_CONTINUE;

	/* Compaction run is not finished if the watermark is not met */
	/* 获取低内存阀值，保存着此管理区内存压缩的下界，也就是内存至少要回收到这个值 */
	watermark = low_wmark_pages(zone);
	/* 下界加上需要分配的内存页框数量 */
	watermark += (1 << cc->order);

	/* 判断zone的空闲页框数量是否达到标准，如果没达到zone的low阀值标准则继续，达到标准了则往下检查 */
	if (!zone_watermark_ok(zone, cc->order, watermark, 0, 0))
		return COMPACT_CONTINUE;

	/* Direct compactor: Is a suitable page free? */
	/* 遍历管理区中比order值大的所有的free_area[order] */
	for (order = cc->order; order < MAX_ORDER; order++) {
		struct free_area *area = &zone->free_area[order];

		/* Job done if page is free of the right migratetype */
		/* 申请页框时需要的指定页框类型中的链表已经有了足够分配给本次申请的页框数量，不需要继续进行内存压缩了 */
		if (!list_empty(&area->free_list[migratetype]))
			return COMPACT_PARTIAL;

		/* Job done if allocation would set block type */
		/* 要求的此种类型的链表中没有足够页框块，但是其他类型有足够的页框块了，之后也不用继续进行内存压缩 */
		if (cc->order >= pageblock_order && area->nr_free)
			return COMPACT_PARTIAL;
	}

	return COMPACT_CONTINUE;
}

/*
 * compaction_suitable: Is this suitable to run compaction on this zone now?
 * Returns
 *   COMPACT_SKIPPED  - If there are too few free pages for compaction
 *   COMPACT_PARTIAL  - If the allocation would succeed without compaction
 *   COMPACT_CONTINUE - If compaction should run now
 */
/* 检查此zone能否进行内存压缩
 * COMPACT_SKIPPED  内存数量不足以支持进行内存压缩
 * COMPACT_PARTIAL  内存足够不需要进行内存压缩
 * COMPACT_CONTINUE 可以进行内存压缩
 */
unsigned long compaction_suitable(struct zone *zone, int order)
{
	int fragindex;
	unsigned long watermark;

	/*
	 * order == -1 is expected when compacting via
	 * /proc/sys/vm/compact_memory
	 */
	/* order == -1是通过写入/proc/sys/vm/compact_memory来进行内存压缩的，那就强制进行压缩 */
	if (order == -1)
		return COMPACT_CONTINUE;

	/*
	 * Watermarks for order-0 must be met for compaction. Note the 2UL.
	 * This is because during migration, copies of pages need to be
	 * allocated and for a short time, the footprint is higher
	 */
	/* 检查管理区的空闲页框数量是否小于(低阀值+本次分配需要的order*2)，如果没超过这个值，则此次压缩跳过，因为压缩时需要一些内存，但是内存不足 */
	watermark = low_wmark_pages(zone) + (2UL << order);
	if (!zone_watermark_ok(zone, 0, watermark, 0, 0))
		return COMPACT_SKIPPED;

	/*
	 * fragmentation index determines if allocation failures are due to
	 * low memory or external fragmentation
	 *
	 * index of -1000 implies allocations might succeed depending on
	 * watermarks
	 * index towards 0 implies failure is due to lack of memory
	 * index towards 1000 implies failure is due to fragmentation
	 *
	 * Only compact if a failure would be due to fragmentation.
	 */
	/* 计算空闲块(连续页框块)的数量并返回一个值，这是一个经验值，用于判断是否需要继续，其实主要判断内存是否足够
	 * 当fragindex为-1000时说明此管理区的伙伴系统中有合适的order次方数量的内存处于free_area[order]链表中
	 */
	fragindex = fragmentation_index(zone, order);
	/* sysctl_extfrag_threshold保存的时内存外碎片的允许阀值，默认是500 */
	if (fragindex >= 0 && fragindex <= sysctl_extfrag_threshold)
		return COMPACT_SKIPPED;

	if (fragindex == -1000 && zone_watermark_ok(zone, order, watermark,
	    0, 0))
		return COMPACT_PARTIAL;

	return COMPACT_CONTINUE;
}

/* 内存压缩主要实现函数 */
static int compact_zone(struct zone *zone, struct compact_control *cc)
{
	int ret;
	/* 管理区开始页框号 */
	unsigned long start_pfn = zone->zone_start_pfn;
	/* 管理区结束页框号 */
	unsigned long end_pfn = zone_end_pfn(zone);
	/* 获取可进行移动的页框类型(__GFP_RECLAIMABLE、__GFP_MOVABLE) */
	const int migratetype = gfpflags_to_migratetype(cc->gfp_mask);
	/* 同步还是异步 
	 * 同步为1，异步为0
	 * 轻同步和同步都是同步
	 */
	const bool sync = cc->mode != MIGRATE_ASYNC;

	/* 根据传入的cc->order判断此次压缩是否能够进行，主要是因为压缩需要部分内存，这里面会判断内存是否足够 */
	ret = compaction_suitable(zone, cc->order);
	switch (ret) {
	/* 内存足够用于分配，所以此次压缩直接跳过 */
	case COMPACT_PARTIAL:
	/* 内存数量不足以进行内存压缩 */
	case COMPACT_SKIPPED:
		/* Compaction is likely to fail */
		return ret;
	/* 可以进行内存压缩 */
	case COMPACT_CONTINUE:
		/* Fall through to compaction */
		;
	}

	/*
	 * Clear pageblock skip if there were failures recently and compaction
	 * is about to be retried after being deferred. kswapd does not do
	 * this reset as it'll reset the cached information when going to sleep.
	 */
	/* 如果不是在kswapd线程中，并且推迟次数超过了最大推迟次数则会执行这个if语句 */
	if (compaction_restarting(zone, cc->order) && !current_is_kswapd())
		/* 设置zone中所有pageblock都不能跳过扫描 */
		__reset_isolation_suitable(zone);

	/*
	 * Setup to move all movable pages to the end of the zone. Used cached
	 * information on where the scanners should start but check that it
	 * is initialised by ensuring the values are within zone boundaries.
	 */
	/* 可移动页框扫描起始页框号，在__reset_isolation_suitable会被设置为zone中第一个页框 */
	cc->migrate_pfn = zone->compact_cached_migrate_pfn[sync];
	/* 空闲页框扫描起始页框号，这两个都是在__reset_isolation_suitable()中设置，此项被设置为zone中最后一个页框 */
	cc->free_pfn = zone->compact_cached_free_pfn;
	/* 检查cc->free_pfn，并将其重置到管理区最后一个完整pageblock的最后一块页框，
	 * 有可能管理区的大小并不是pageblock的整数倍，最后一个pageblock不是完整的，就把这个页框块忽略，不进行扫描 
	 */
	if (cc->free_pfn < start_pfn || cc->free_pfn > end_pfn) {
		cc->free_pfn = end_pfn & ~(pageblock_nr_pages-1);
		zone->compact_cached_free_pfn = cc->free_pfn;
	}
	/* 同上，检查cc->migrate_pfn，并整理可移动页框扫描的起始页框 */
	if (cc->migrate_pfn < start_pfn || cc->migrate_pfn > end_pfn) {
		cc->migrate_pfn = start_pfn;
		zone->compact_cached_migrate_pfn[0] = cc->migrate_pfn;
		zone->compact_cached_migrate_pfn[1] = cc->migrate_pfn;
	}

	trace_mm_compaction_begin(start_pfn, cc->migrate_pfn, cc->free_pfn, end_pfn);
	
	/* 将处于pagevec中的页都放回原本所属的lru中，这一步很重要 */
	migrate_prep_local();

	/* 判断是否结束本次内存压缩 
	 * 1.可移动页框扫描的位置是否已经超过了空闲页框扫描的位置，超过则结束压缩
	 * 2.判断zone的空闲页框数量是否达到标准，如果没达到zone的low阀值标准则继续
	 * 3.判断伙伴系统中是否有比order值大的空闲连续页框块，有则结束压缩
	 * 如果是管理员写入到/proc/sys/vm/compact_memory进行强制内存压缩的情况，则判断条件只有第1条
	 */
	while ((ret = compact_finished(zone, cc, migratetype)) ==
						COMPACT_CONTINUE) {
		int err;

		/* 将可移动页(MOVABLE和CMA和RECLAIMABLE)从zone->lru隔离出来，存到cc->migratepages这个链表，一个一个pageblock进行扫描，当一个pageblock扫描成功获取到可移动页后就返回
		 * 一次扫描最多32*1024个页框
		 */
		/* 异步不处理RECLAIMABLE页 */
		switch (isolate_migratepages(zone, cc)) {
		case ISOLATE_ABORT:
			/* 失败，把这些页放回到lru或者原来的地方 */
			ret = COMPACT_PARTIAL;
			putback_movable_pages(&cc->migratepages);
			cc->nr_migratepages = 0;
			goto out;
		case ISOLATE_NONE:
			continue;
		case ISOLATE_SUCCESS:
			;
		}

		/* 将隔离出来的页进行迁移，如果到这里，cc->migratepages中最多也只有一个pageblock的页框数量，并且这些页框都是可移动的 
		 * 空闲页框会在compaction_alloc中获取
		 * 也就是把隔离出来的一个pageblock中可移动页进行移动
		 */
		err = migrate_pages(&cc->migratepages, compaction_alloc,
				compaction_free, (unsigned long)cc, cc->mode,
				MR_COMPACTION);

		trace_mm_compaction_migratepages(cc->nr_migratepages, err,
							&cc->migratepages);

		/* All pages were either migrated or will be released */
		/* 设置所有可移动页框为0 */
		cc->nr_migratepages = 0;
		if (err) {
			/* 将剩余的可移动页框返回原来的位置 */
			putback_movable_pages(&cc->migratepages);
			/*
			 * migrate_pages() may return -ENOMEM when scanners meet
			 * and we want compact_finished() to detect it
			 */
			if (err == -ENOMEM && cc->free_pfn > cc->migrate_pfn) {
				ret = COMPACT_PARTIAL;
				goto out;
			}
		}
	}

out:
	/* Release free pages and check accounting */
	/* 将剩余的空闲页框放回伙伴系统 */
	cc->nr_freepages -= release_freepages(&cc->freepages);
	VM_BUG_ON(cc->nr_freepages != 0);

	trace_mm_compaction_end(ret);

	return ret;
}

static unsigned long compact_zone_order(struct zone *zone, int order,
		gfp_t gfp_mask, enum migrate_mode mode, int *contended)
{
	unsigned long ret;
	struct compact_control cc = {
		/* 压缩结束后空闲页框数量 */
		.nr_freepages = 0,
		/* 压缩结束后移动的页框数量 */
		.nr_migratepages = 0,
		.order = order,
		/* 表示需要移动的页框类型，有movable和reclaimable两种，可以同时设置 */
		.gfp_mask = gfp_mask,
		/* 管理区 */
		.zone = zone,
		/* 同步或异步 */
		.mode = mode,
	};
	/* 初始化一个空闲页框链表头 */
	INIT_LIST_HEAD(&cc.freepages);
	/* 初始化一个movable页框链表头 */
	INIT_LIST_HEAD(&cc.migratepages);

	/* 进行内存压缩 */
	ret = compact_zone(zone, &cc);

	VM_BUG_ON(!list_empty(&cc.freepages));
	VM_BUG_ON(!list_empty(&cc.migratepages));

	*contended = cc.contended;
	return ret;
}

int sysctl_extfrag_threshold = 500;

/**
 * try_to_compact_pages - Direct compact to satisfy a high-order allocation
 * @zonelist: The zonelist used for the current allocation
 * @order: The order of the current allocation
 * @gfp_mask: The GFP mask of the current allocation
 * @nodemask: The allowed nodes to allocate from
 * @mode: The migration mode for async, sync light, or sync migration
 * @contended: Return value that determines if compaction was aborted due to
 *	       need_resched() or lock contention
 * @candidate_zone: Return the zone where we think allocation should succeed
 *
 * This is the main entry point for direct page compaction.
 */
/* 尝试每个管理区进行内存压缩空闲出一些页 
 * order: 2的次方，如果是分配时调用到，这个就是分配时希望获取的order，如果是通过写入/proc/sys/vm/compact_memory文件进行强制内存压缩，order就是-1
 *
 */
unsigned long try_to_compact_pages(struct zonelist *zonelist,
			int order, gfp_t gfp_mask, nodemask_t *nodemask,
			enum migrate_mode mode, int *contended,
			struct zone **candidate_zone)
{
	enum zone_type high_zoneidx = gfp_zone(gfp_mask);
	/* 表示运行使用文件系统IO */
	int may_enter_fs = gfp_mask & __GFP_FS;
	/* 表示可以使用磁盘IO */
	int may_perform_io = gfp_mask & __GFP_IO;
	struct zoneref *z;
	struct zone *zone;
	int rc = COMPACT_DEFERRED;
	int alloc_flags = 0;
	int all_zones_contended = COMPACT_CONTENDED_LOCK; /* init for &= op */

	*contended = COMPACT_CONTENDED_NONE;

	/* Check if the GFP flags allow compaction */
	/* 如果order=0或者不允许使用文件系统IO和磁盘IO，则跳过本次压缩，因为不使用IO有可能导致死锁 */
	if (!order || !may_enter_fs || !may_perform_io)
		return COMPACT_SKIPPED;

#ifdef CONFIG_CMA
	/* 在启动了CMA的情况下，如果标记了需要的内存为MIGRATE_MOVABLE，则添加一个ALLOC_CMA标志 */
	if (gfpflags_to_migratetype(gfp_mask) == MIGRATE_MOVABLE)
		alloc_flags |= ALLOC_CMA;
#endif
	/* Compact each zone in the list */
	/* 遍历管理区链表中所有的管理区 */
	for_each_zone_zonelist_nodemask(zone, z, zonelist, high_zoneidx,
								nodemask) {
		int status;
		int zone_contended;

		/* 检查管理区设置中是否需要跳过此次压缩 
		 * 判断标准是:
		 * zone->compact_considered是否小于1UL << zone->compact_defer_shift
		 * 小于则推迟，并且zone->compact_considered++，也就是这个函数会主动去推迟此管理区的内存压缩
		 */
		if (compaction_deferred(zone, order))
			continue;

		/* 进行管理区的内存压缩 */
		status = compact_zone_order(zone, order, gfp_mask, mode,
							&zone_contended);
		rc = max(status, rc);
		/*
		 * It takes at least one zone that wasn't lock contended
		 * to clear all_zones_contended.
		 */
		all_zones_contended &= zone_contended;

		/* If a normal allocation would succeed, stop compacting */
		/* 判断压缩后是否足够进行内存分配，如果足够，则不会对下个zone进行压缩了，直接跳出 */
		if (zone_watermark_ok(zone, order, low_wmark_pages(zone), 0,
				      alloc_flags)) {
			*candidate_zone = zone;
			/*
			 * We think the allocation will succeed in this zone,
			 * but it is not certain, hence the false. The caller
			 * will repeat this with true if allocation indeed
			 * succeeds in this zone.
			 */
			/* 重新设置内存压缩计数器，让其归0，也就是重新计算内存压缩请求 */
			compaction_defer_reset(zone, order, false);
			/*
			 * It is possible that async compaction aborted due to
			 * need_resched() and the watermarks were ok thanks to
			 * somebody else freeing memory. The allocation can
			 * however still fail so we better signal the
			 * need_resched() contention anyway (this will not
			 * prevent the allocation attempt).
			 */
			/* 异步情况下需要被调度时会设置 */
			if (zone_contended == COMPACT_CONTENDED_SCHED)
				*contended = COMPACT_CONTENDED_SCHED;

			goto break_loop;
		}

		/* 如果是同步压缩 */
		if (mode != MIGRATE_ASYNC) {
			/*
			 * We think that allocation won't succeed in this zone
			 * so we defer compaction there. If it ends up
			 * succeeding after all, it will be reset.
			 */
			/* 提高内存压缩计数器的阀值，zone的内存压缩计数器阀值 */
			defer_compaction(zone, order);
		}

		/*
		 * We might have stopped compacting due to need_resched() in
		 * async compaction, or due to a fatal signal detected. In that
		 * case do not try further zones and signal need_resched()
		 * contention.
		 */
		if ((zone_contended == COMPACT_CONTENDED_SCHED)
					|| fatal_signal_pending(current)) {
			*contended = COMPACT_CONTENDED_SCHED;
			goto break_loop;
		}

		continue;
break_loop:
		/*
		 * We might not have tried all the zones, so  be conservative
		 * and assume they are not all lock contended.
		 */
		all_zones_contended = 0;
		break;
	}

	/*
	 * If at least one zone wasn't deferred or skipped, we report if all
	 * zones that were tried were lock contended.
	 */
	if (rc > COMPACT_SKIPPED && all_zones_contended)
		*contended = COMPACT_CONTENDED_LOCK;

	return rc;
}


/* Compact all zones within a node */
static void __compact_pgdat(pg_data_t *pgdat, struct compact_control *cc)
{
	int zoneid;
	struct zone *zone;

	for (zoneid = 0; zoneid < MAX_NR_ZONES; zoneid++) {

		zone = &pgdat->node_zones[zoneid];
		if (!populated_zone(zone))
			continue;

		cc->nr_freepages = 0;
		cc->nr_migratepages = 0;
		cc->zone = zone;
		INIT_LIST_HEAD(&cc->freepages);
		INIT_LIST_HEAD(&cc->migratepages);

		if (cc->order == -1 || !compaction_deferred(zone, cc->order))
			compact_zone(zone, cc);

		if (cc->order > 0) {
			if (zone_watermark_ok(zone, cc->order,
						low_wmark_pages(zone), 0, 0))
				compaction_defer_reset(zone, cc->order, false);
		}

		VM_BUG_ON(!list_empty(&cc->freepages));
		VM_BUG_ON(!list_empty(&cc->migratepages));
	}
}

void compact_pgdat(pg_data_t *pgdat, int order)
{
	struct compact_control cc = {
		.order = order,
		.mode = MIGRATE_ASYNC,
	};

	if (!order)
		return;

	__compact_pgdat(pgdat, &cc);
}

static void compact_node(int nid)
{
	struct compact_control cc = {
		.order = -1,
		.mode = MIGRATE_SYNC,
		.ignore_skip_hint = true,
	};

	__compact_pgdat(NODE_DATA(nid), &cc);
}

/* Compact all nodes in the system */
static void compact_nodes(void)
{
	int nid;

	/* Flush pending updates to the LRU lists */
	lru_add_drain_all();

	for_each_online_node(nid)
		compact_node(nid);
}

/* The written value is actually unused, all memory is compacted */
int sysctl_compact_memory;

/* This is the entry point for compacting all nodes via /proc/sys/vm */
int sysctl_compaction_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos)
{
	if (write)
		compact_nodes();

	return 0;
}

int sysctl_extfrag_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec_minmax(table, write, buffer, length, ppos);

	return 0;
}

#if defined(CONFIG_SYSFS) && defined(CONFIG_NUMA)
static ssize_t sysfs_compact_node(struct device *dev,
			struct device_attribute *attr,
			const char *buf, size_t count)
{
	int nid = dev->id;

	if (nid >= 0 && nid < nr_node_ids && node_online(nid)) {
		/* Flush pending updates to the LRU lists */
		lru_add_drain_all();

		compact_node(nid);
	}

	return count;
}
static DEVICE_ATTR(compact, S_IWUSR, NULL, sysfs_compact_node);

int compaction_register_node(struct node *node)
{
	return device_create_file(&node->dev, &dev_attr_compact);
}

void compaction_unregister_node(struct node *node)
{
	return device_remove_file(&node->dev, &dev_attr_compact);
}
#endif /* CONFIG_SYSFS && CONFIG_NUMA */

#endif /* CONFIG_COMPACTION */
