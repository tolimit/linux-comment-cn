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
	/* �����MIGRATE_CMA���ͻ���MIGRATE_MOVABLE���򷵻��� */
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
	/* ��������ʼҳ�� */
	unsigned long start_pfn = zone->zone_start_pfn;
	/* ����������ҳ�� */
	unsigned long end_pfn = zone_end_pfn(zone);
	unsigned long pfn;

	/* 0���������첽��1��������ͬ����������ƶ�ҳ��ɨ�����ʼλ�ã�Ϊ��������һ��ҳ�� */
	zone->compact_cached_migrate_pfn[0] = start_pfn;
	zone->compact_cached_migrate_pfn[1] = start_pfn;
	/* ���ÿ���ҳ��ɨ����ʼλ��Ϊ���������һ��ҳ�� */
	zone->compact_cached_free_pfn = end_pfn;
	zone->compact_blockskip_flush = false;

	/* Walk the zone and mark every pageblock as suitable for isolation */
	/* ��������������ҳ��ÿ����1024��ҳ��Ҳ����1024��ҳ��Ϊһ��pageblock */
	for (pfn = start_pfn; pfn < end_pfn; pfn += pageblock_nr_pages) {
		struct page *page;
		/* ����Ƿ���Ҫ���� */
		cond_resched();

		/* �Ƿ�Ϊ��Чҳ��� */
		if (!pfn_valid(pfn))
			continue;

		/* ҳ������ */
		page = pfn_to_page(pfn);
		/* �ж��Ƿ��ڴ˹����� */
		if (zone != page_zone(page))
			continue;
		/* �Ѵ�ҳ������ҳ��������PB_migrate_skip��0����������������ҳ��Ҫ����ѹ�� */
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
/* ɨ���start_pfn��end_pfn�Ŀ���ҳ�򣬲������Ƿ��뵽freelist�У����ش�pageblock���ܹ���õĿ���ҳ������ */
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
	/* ��pageblock��start��end����ɨ�� */
	for (; blockpfn < end_pfn; blockpfn++, cursor++) {
		int isolated, i;
		/* ��ǰҳ�� */
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
		/* ����ҳ����Ƿ���ȷ */
		if (!pfn_valid_within(blockpfn))
			goto isolate_fail;

		/* valid_page�ǿ�ʼɨ���ҳ�� */
		if (!valid_page)
			valid_page = page;
		/* ����ҳ�Ƿ��ڻ��ϵͳ�У�����˵��������ʹ�õ�ҳ�������� */
		if (!PageBuddy(page))
			goto isolate_fail;

		/*
		 * If we already hold the lock, we can skip some rechecking.
		 * Note that if we hold the lock now, checked_pageblock was
		 * already set in some previous iteration (or strict is true),
		 * so it is correct to skip the suitable migration target
		 * recheck as well.
		 */
		/* ��ȡ�� */
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
		/* ��page��ʼ����������ҳ����Ϊ�����ĵ���ҳ�򣬷���������orderֵ����page��ҳ�������У������п��ܻ�����pageblock������ */
		isolated = split_free_page(page);
		/* �����ܹ���õĿ���ҳ�� */
		total_isolated += isolated;
		/* ��isolated����������ҳ�����freelist�� */
		for (i = 0; i < isolated; i++) {
			list_add(&page->lru, freelist);
			page++;
		}

		/* If a page was split, advance to the end of it */
		/* ���������������ҳ����Ϊ�������ο���ҳ��ȫ�����뵽��freelist�� */
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

	/* ���ռ�������ͷŵ� */
	if (locked)
		spin_unlock_irqrestore(&cc->zone->lock, flags);

	/* Update the pageblock-skip if the whole pageblock was scanned */
	/* ɨ�����˴�pageblock������total_isolatedΪ0�Ļ������Ǵ�pageblockΪ���� */
	if (blockpfn == end_pfn)
		update_pageblock_skip(cc, valid_page, total_isolated, false);

	/* ͳ�� */
	count_compact_events(COMPACTFREE_SCANNED, nr_scanned);
	if (total_isolated)
		count_compact_events(COMPACTISOLATED, total_isolated);
	/* �����ܹ���õĿ���ҳ�� */
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
/* ��һ��pageblock�����п����ƶ���ҳ�������� */
static unsigned long
isolate_migratepages_block(struct compact_control *cc, unsigned long low_pfn,
			unsigned long end_pfn, isolate_mode_t isolate_mode)
{
	struct zone *zone = cc->zone;
	unsigned long nr_scanned = 0, nr_isolated = 0;
	/* ���ƶ���ҳ������ */
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
	/* ���isolated�Ƿ�С��LRU������(inactive + active) / 2�����������ʾ�Ѿ�������ҳ�������� */
	while (unlikely(too_many_isolated(zone))) {
		/* async migration should just abort */
		if (cc->mode == MIGRATE_ASYNC)
			return 0;

		/* ����100ms�����ߣ��ȴ��豸û��ô��æ */
		congestion_wait(BLK_RW_ASYNC, HZ/10);

		if (fatal_signal_pending(current))
			return 0;
	}
	/* ������첽���ã����ҵ�ǰ������Ҫ���ȵĻ��������� */
	if (compact_should_abort(cc))
		return 0;

	/* Time to isolate some pages for migration */
	/* ����ÿһ��ҳ�� */
	for (; low_pfn < end_pfn; low_pfn++) {
		/*
		 * Periodically drop the lock (if held) regardless of its
		 * contention, to give chance to IRQs. Abort async compaction
		 * if contended.
		 */
		/* ������ͷŵ�zone->lru_lock����� */
		if (!(low_pfn % SWAP_CLUSTER_MAX)
		    && compact_unlock_should_abort(&zone->lru_lock, flags,
								&locked, cc))
			break;

		if (!pfn_valid_within(low_pfn))
			continue;
		/* ɨ�����++ */
		nr_scanned++;

		/* ����ҳ��Ż�ȡҳ������ */
		page = pfn_to_page(low_pfn);

		/* ����valid_page */
		if (!valid_page)
			valid_page = page;

		/*
		 * Skip if free. We read page order here without zone lock
		 * which is generally unsafe, but the race window is small and
		 * the worst thing that can happen is that we skip some
		 * potential isolation targets.
		 */
		/* ����ҳ�Ƿ��ڻ��ϵͳ�У���Ҫ��ͨ��page->_mapcount�жϣ�����ڻ��ϵͳ�У��������������ڴ� */
		if (PageBuddy(page)) {
			/* ��ȡ���ҳ��ʼ��order�η���ҳ��Ϊ���ϵͳ��һ���ڴ� */
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
		/* ���´�����ҳ���ڻ��ϵͳ�е������������ҳ����ʹ�õ�ҳ*/
		/* ���ҳ������lru�еĴ�����isolated��ҳ�ǲ�����lru�еģ�����balloon��ҳҲ������lru��?
		 * ���ƶ���ҳ������LRU�У�����LRU�е�ҳ���ᱻ����������Ͱ�UNMOVABLE��������
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
		/* �����ҳ��͸����ҳ�Ĵ�����Ҳ��������͸����ҳ����ϵͳ�ʱ����ʵʱ���ã�����Ҫ������Ч */
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
		/* �����һ������ҳ�����ұ����ô�������page->_mapcount����������ҳ��ע��˵��ҳ���п��ܱ��������ڴ��в���������������֪������жϵ� */
		if (!page_mapping(page) &&
		    page_count(page) > page_mapcount(page))
			continue;

		/* If we already hold the lock, we can skip some rechecking */
		/* ����Ƿ����������������zone->lru_lock */
		if (!locked) {
			locked = compact_trylock_irqsave(&zone->lru_lock,
								&flags, cc);
			if (!locked)
				break;
			/* û�������������Ҫ����Ƿ���LRU�� */
			/* Recheck PageLRU and PageTransHuge under lock */
			if (!PageLRU(page))
				continue;
			/* �����lru�У�����Ƿ��Ǵ�ҳ���������룬��ֹlow_pfn����ҳ�� */
			if (PageTransHuge(page)) {
				low_pfn += (1 << compound_order(page)) - 1;
				continue;
			}
		}

		lruvec = mem_cgroup_page_lruvec(page, zone);

		/* Try isolate the page */
		/* ����ҳ��lru�и������ */
		if (__isolate_lru_page(page, isolate_mode) != 0)
			continue;

		VM_BUG_ON_PAGE(PageTransCompound(page), page);

		/* Successfully isolated */
		/* �����cgroup��lru���������򽫴�ҳ��lru���������ó��� */
		del_page_from_lru_list(page, lruvec, page_lru(page));

isolate_success:
		/* ����ɹ�����ҳ�Ѳ�����lru�� */
		cc->finished_update_migrate = true;
		/* ����ҳ���뵽����ѹ����Ҫ�ƶ�ҳ������ */
		list_add(&page->lru, migratelist);
		/* ��Ҫ�ƶ���ҳ������++ */
		cc->nr_migratepages++;
		/* ��������++ */
		nr_isolated++;

		/* Avoid isolating too much */
		/* COMPACT_CLUSTER_MAX����ÿ���ڴ�ѹ�������ƶ������ҳ������ */
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

	/* ���� */
	if (locked)
		spin_unlock_irqrestore(&zone->lru_lock, flags);

	/*
	 * Update the pageblock-skip information and cached scanner pfn,
	 * if the whole pageblock was scanned without isolating any page.
	 */
	/* ���ȫ����ҳ��鶼ɨ����ˣ�����û�и����κ�һ��ҳ������������ҳ���ڵ�pageblockΪPB_migrate_skip��Ȼ��
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

	/* ͳ�� */
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
/* ���������ҳ�� */
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
	/* ��ȡ��ʼɨ��ҳ�����ڵ�pageblock����������Ϊ��pageblock�����һ��ҳ����߹��������һ��ҳ�� */
	isolate_start_pfn = cc->free_pfn;
	block_start_pfn = cc->free_pfn & ~(pageblock_nr_pages-1);
	block_end_pfn = min(block_start_pfn + pageblock_nr_pages,
						zone_end_pfn(zone));
	/* ��pageblock_nr_pages���룬low_pfn������ǿ�Ǩ��ҳ��ɨ�����ڵ�ҳ��ţ����������п���migrate_pfn == free_pfn */
	low_pfn = ALIGN(cc->migrate_pfn + 1, pageblock_nr_pages);

	/*
	 * Isolate free pages until enough are available to migrate the
	 * pages on cc->migratepages. We stop searching if the migrate
	 * and free page scanners meet or enough free pages are isolated.
	 */
	/* ��ʼɨ�����ҳ�򣬴ӹ��������һ��pageblock��migrate_pfn���ڵ�pageblockɨ��
	 * block_start_pfn��pageblock��ʼҳ���
	 * block_end_pfn��pageblock����ҳ���
	 */
	/* ѭ�������� 
	 * ɨ�赽low_pfn����pageblokc�������һ��pageblock��low_pfn��low_pfn������ǿ�Ǩ��ҳ��ɨ�����ڵ�ҳ��ţ�������pageblock_nr_pages���롣
	 * ����cc�п��ƶ���ҳ����������cc�п���ҳ������������ڸ�����ƶ�ҳ����һ��һ��pageblockΪ��λ�ģ����Ըտ�ʼʱ�������ж�cc->nr_migratepages > nr_freepages�������Ƿ����
	 * ��ɨ�赽���ƶ�ҳ��ɨ�����ڵ�pageblock�����ֹͣ
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

		/* ���block_start_pfn��block_end_pfn�����û���⣬����block_start_pfn��ָ��ҳ��������Ҳ����pageblock��һҳ������ */
		page = pageblock_pfn_to_page(block_start_pfn, block_end_pfn,
									zone);
		if (!page)
			continue;

		/* Check the block is suitable for migration */
		/* �ж��Ƿ��ܹ�����Ǩ��ҳ��
		 * �ж�����1: ������ڻ��ϵͳ�У������������������ҳ���orderֵ����С��pageblock��orderֵ
		 * �ж�����2: ��pageblock����ΪMIGRATE_MOVABLE����MIGRATE_CMA���ͣ���ΪMIGRATE_RECLAIMABLE���͵�pageblock������
		 */
		if (!suitable_migration_target(page))
			continue;

		/* If isolation recently failed, do not retry */
		/* ���cc���Ƿ����˼�ʹpageblock���������Ҳ��pageblock����ɨ�裬���Ҽ���pageblock�Ƿ񱻱��Ϊ���� */
		if (!isolation_suitable(cc, page))
			continue;

		/* Found a block suitable for isolating free pages from. */
		/* ɨ���isolate_start_pfn��block_end_pfn�Ŀ���ҳ�򣬲������Ƿ��뵽freelist�У����ش�pageblock���ܹ���õĿ���ҳ������ 
		 * ��һ��ɨ����ܻ�������Ӧ�õ�һ��isolate_start_pfn�ǵ���zone���һ��ҳ���
		 */
		isolated = isolate_freepages_block(cc, &isolate_start_pfn,
					block_end_pfn, freelist, false);
		/* ͳ��freelist�п���ҳ������ */
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
		/* �´�ѭ����ʼ��ҳ�� */
		cc->free_pfn = (isolate_start_pfn < block_end_pfn) ?
				isolate_start_pfn :
				block_start_pfn - pageblock_nr_pages;

		/*
		 * Set a flag that we successfully isolated in this pageblock.
		 * In the next loop iteration, zone->compact_cached_free_pfn
		 * will not be updated and thus it will effectively contain the
		 * highest pageblock we isolated pages from.
		 */
		/* ����cc->finished_update_freeΪtrue���������˴�cc��ȡ���˿���ҳ������ */
		if (isolated)
			cc->finished_update_free = true;

		/*
		 * isolate_freepages_block() might have aborted due to async
		 * compaction being contended
		 */
		/* ���contended�������ڱ����Ƿ���Ҫ��ֹ */
		if (cc->contended)
			break;
	}

	/* split_free_page does not map the pages */
	/* ����ҳ�������Ϊ�ں�ʹ�� */
	map_pages(freelist);

	/*
	 * If we crossed the migrate scanner, we want to keep it that way
	 * so that compact_finished() may detect this
	 */
	/* ��֤free_pfn������migrate_pfn */
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
	/* ��ȡcc */
	struct compact_control *cc = (struct compact_control *)data;
	struct page *freepage;

	/*
	 * Isolate free pages if necessary, and if we are not aborting due to
	 * contention.
	 */
	/* ���cc�еĿ���ҳ������Ϊ�� */
	if (list_empty(&cc->freepages)) {
		/* ����cc->contendedû�м�¼������� */
		if (!cc->contended)
			/* ��cc->free_pfn��ʼ��ǰ��ȡ����ҳ */
			isolate_freepages(cc);

		if (list_empty(&cc->freepages))
			return NULL;
	}
	/* ��cc->freepages�������ó�һ������page */
	freepage = list_entry(cc->freepages.next, struct page, lru);
	list_del(&freepage->lru);
	cc->nr_freepages--;
	
	/* ���ؿ���ҳ�� */
	return freepage;
}

/*
 * This is a migrate-callback that "frees" freepages back to the isolated
 * freelist.  All pages on the freelist are from the same zone, so there is no
 * special handling needed for NUMA.
 */
/* ��page�ͷŻص�cc�� */
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
/* ��cc->migrate_pfn(�������ɨ����ƶ�ҳ��ָ�����ڵ�ҳ���)��ʼ����һ����ȡ�����ƶ�ҳ���pageblock��������ȡ���ƶ�ҳ�򣬲����뵽cc->migratepages */
static isolate_migrate_t isolate_migratepages(struct zone *zone,
					struct compact_control *cc)
{
	unsigned long low_pfn, end_pfn;
	struct page *page;
	/* ����ͬ��/�첽��ʽ��ֻ���첽��������ܽ����ƶ�ҳ��ISOLATE_ASYNC_MIGRATE */
	const isolate_mode_t isolate_mode =
		(cc->mode == MIGRATE_ASYNC ? ISOLATE_ASYNC_MIGRATE : 0);

	/*
	 * Start at where we last stopped, or beginning of the zone as
	 * initialized by compact_zone()
	 */
	/* ɨ����ʼҳ�� */
	low_pfn = cc->migrate_pfn;

	/* Only scan within a pageblock boundary */
	/* ��1024���� */
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
		/* ������Ҫɨ��ܶ�ҳ����������������飬ִ��ʱ�������˯�ߣ�һ����32��1024ҳ������һ�£��첽���������Ҫ�ж����н����Ƿ���Ҫ������ */
		if (!(low_pfn % (SWAP_CLUSTER_MAX * pageblock_nr_pages))
						&& compact_should_abort(cc))
			break;

		/* ��ȡ��һ��ҳ����Ҫ����Ƿ����ڴ�zone */
		page = pageblock_pfn_to_page(low_pfn, end_pfn, zone);
		if (!page)
			continue;

		/* If isolation recently failed, do not retry */
		/* ��ȡҳ���PB_migrate_skip��־��������������������1024��ҳ�� */
		if (!isolation_suitable(cc, page))
			continue;

		/*
		 * For async compaction, also only scan in MOVABLE blocks.
		 * Async compaction is optimistic to see if the minimum amount
		 * of work satisfies the allocation.
		 */
		/* �첽������������MIGRATE_MOVABLE��MIGRATE_CMA�������������ҳ��� */
		/* �첽������RECLAIMABLE��ҳ */
		if (cc->mode == MIGRATE_ASYNC &&
		    !migrate_async_suitable(get_pageblock_migratetype(page)))
			continue;

		/* Perform the isolation */
		/* ִ������룬��low_pfn��end_pfn������ʹ�õ�ҳ���zone->lru��ȡ���������ص��ǿ��ƶ�ҳɨ��ɨ�赽��ҳ���
		 * ��UNMOVABLE���͵�ҳ���ǲ��ᴦ��lru�����еģ��������в���lru�����е�ҳ���ᱻ����
		 * ���ص���ɨ�赽������ҳ
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
		/* ������˵����������ɹ�ֻ��ɨ��һ��pageblock */
		break;
	}
	/* ͳ�ƣ�������ٴα���cc�����п��ƶ���ҳ���ж�������RECLAIMABLE����MOVABLE��ҳ
	 */
	acct_isolated(zone, cc);
	/*
	 * Record where migration scanner will be restarted. If we end up in
	 * the same pageblock as the free scanner, make the scanners fully
	 * meet so that compact_finished() terminates compaction.
	 */
	/* ���ƶ�ҳɨ�赽��ҳ������ */
	cc->migrate_pfn = (end_pfn <= cc->free_pfn) ? low_pfn : cc->free_pfn;

	return cc->nr_migratepages ? ISOLATE_SUCCESS : ISOLATE_NONE;
}

/* �ж��Ƿ�����ڴ�ѹ�� */
static int compact_finished(struct zone *zone, struct compact_control *cc,
			    const int migratetype)
{
	unsigned int order;
	unsigned long watermark;

	/* ��ǰ�����Ѿ�������sigkill�źţ�׼����kill�������������Ͳ������ڴ�ѹ���� */
	if (cc->contended || fatal_signal_pending(current))
		return COMPACT_PARTIAL;

	/* Compaction run completes if the migrate and free scanner meet */
	/* �����ƶ�ҳ��ɨ���λ���Ƿ��Ѿ������˿���ҳ��ɨ���λ�� */
	if (cc->free_pfn <= cc->migrate_pfn) {
		/* Let the next compaction start anew. */
		/* ����������£����ÿ��ƶ�ҳ��ɨ��Ϳ���ҳ��ɨ�����ʼλ�� */
		zone->compact_cached_migrate_pfn[0] = zone->zone_start_pfn;
		zone->compact_cached_migrate_pfn[1] = zone->zone_start_pfn;
		zone->compact_cached_free_pfn = zone_end_pfn(zone);

		/*
		 * Mark that the PG_migrate_skip information should be cleared
		 * by kswapd when it goes to sleep. kswapd does not set the
		 * flag itself as the decision to be clear should be directly
		 * based on an allocation request.
		 */
		/* �������kswapd�ں��߳���ִ�е�����¾Ͳ����һЩҳ�����ɨ�� 
		 * �������alloc_pages()�н���ҳ��ѹ��������£����Թ�����������ҳ�����ɨ��
		 */
		if (!current_is_kswapd())
			zone->compact_blockskip_flush = true;

		return COMPACT_COMPLETE;
	}

	/*
	 * order == -1 is expected when compacting via
	 * /proc/sys/vm/compact_memory
	 */
	/* ����ǹ���Աд�뵽/proc/sys/vm/compact_memory����ǿ���ڴ�ѹ��������������ѹ�� */
	if (cc->order == -1)
		return COMPACT_CONTINUE;

	/* Compaction run is not finished if the watermark is not met */
	/* ��ȡ���ڴ淧ֵ�������Ŵ˹������ڴ�ѹ�����½磬Ҳ�����ڴ�����Ҫ���յ����ֵ */
	watermark = low_wmark_pages(zone);
	/* �½������Ҫ������ڴ�ҳ������ */
	watermark += (1 << cc->order);

	/* �ж��Ƿ�ﵽ��׼��û�ﵽ��׼��������ﵽ��׼�������¼�� */
	if (!zone_watermark_ok(zone, cc->order, watermark, 0, 0))
		return COMPACT_CONTINUE;

	/* Direct compactor: Is a suitable page free? */
	/* �����������б�orderֵ������е�free_area[order] */
	for (order = cc->order; order < MAX_ORDER; order++) {
		struct free_area *area = &zone->free_area[order];

		/* Job done if page is free of the right migratetype */
		/* ����ҳ��ʱ��Ҫ��ָ��ҳ�������е������Ѿ������㹻��������������ҳ������������Ҫ���������ڴ�ѹ���� */
		if (!list_empty(&area->free_list[migratetype]))
			return COMPACT_PARTIAL;

		/* Job done if allocation would set block type */
		/* Ҫ��Ĵ������͵�������û���㹻ҳ��飬���������������㹻��ҳ����ˣ�֮��Ҳ���ü��������ڴ�ѹ�� */
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
/* COMPACT_SKIPPED  �ڴ�����������֧�ֽ����ڴ�ѹ��
 * COMPACT_PARTIAL  �ڴ��㹻����Ҫ�����ڴ�ѹ��
 * COMPACT_CONTINUE ���Խ����ڴ�ѹ��
 */
unsigned long compaction_suitable(struct zone *zone, int order)
{
	int fragindex;
	unsigned long watermark;

	/*
	 * order == -1 is expected when compacting via
	 * /proc/sys/vm/compact_memory
	 */
	/* order == -1��ͨ��д��/proc/sys/vm/compact_memory�������ڴ�ѹ���ģ��Ǿ�ǿ�ƽ���ѹ�� */
	if (order == -1)
		return COMPACT_CONTINUE;

	/*
	 * Watermarks for order-0 must be met for compaction. Note the 2UL.
	 * This is because during migration, copies of pages need to be
	 * allocated and for a short time, the footprint is higher
	 */
	/* ���������Ŀ���ҳ�������Ƿ�С��(�ͷ�ֵ+���η�����Ҫ��order*2)�����û�������ֵ����˴�ѹ����������Ϊѹ��ʱ��ҪһЩ�ڴ棬�����ڴ治�� */
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
	/* ������п�(����ҳ���)������������һ��ֵ������һ������ֵ�������ж��Ƿ���Ҫ��������ʵ��Ҫ�ж��ڴ��Ƿ��㹻
	 * ��fragindexΪ-1000ʱ˵���˹������Ļ��ϵͳ���к��ʵ�order�η��������ڴ洦��free_area[order]������
	 */
	fragindex = fragmentation_index(zone, order);
	/* sysctl_extfrag_threshold�����ʱ�ڴ�����Ƭ��������ֵ��Ĭ����500 */
	if (fragindex >= 0 && fragindex <= sysctl_extfrag_threshold)
		return COMPACT_SKIPPED;

	if (fragindex == -1000 && zone_watermark_ok(zone, order, watermark,
	    0, 0))
		return COMPACT_PARTIAL;

	return COMPACT_CONTINUE;
}

/* �ڴ�ѹ����Ҫʵ�ֺ��� */
static int compact_zone(struct zone *zone, struct compact_control *cc)
{
	int ret;
	/* ��������ʼҳ��� */
	unsigned long start_pfn = zone->zone_start_pfn;
	/* ����������ҳ��� */
	unsigned long end_pfn = zone_end_pfn(zone);
	/* ��ȡ�ɽ����ƶ���ҳ������(__GFP_RECLAIMABLE��__GFP_MOVABLE) */
	const int migratetype = gfpflags_to_migratetype(cc->gfp_mask);
	/* ͬ�������첽 
	 * ͬ��Ϊ1���첽Ϊ0
	 */
	const bool sync = cc->mode != MIGRATE_ASYNC;

	/* ���ݴ����cc->order�жϴ˴�ѹ���Ƿ��ܹ����У���Ҫ����Ϊѹ����Ҫ�����ڴ棬��������ж��ڴ��Ƿ��㹻 */
	ret = compaction_suitable(zone, cc->order);
	switch (ret) {
	/* �ڴ��㹻���ڷ��䣬���Դ˴�ѹ��ֱ������ */
	case COMPACT_PARTIAL:
	/* �ڴ����������Խ����ڴ�ѹ�� */
	case COMPACT_SKIPPED:
		/* Compaction is likely to fail */
		return ret;
	/* ���Խ����ڴ�ѹ�� */
	case COMPACT_CONTINUE:
		/* Fall through to compaction */
		;
	}

	/*
	 * Clear pageblock skip if there were failures recently and compaction
	 * is about to be retried after being deferred. kswapd does not do
	 * this reset as it'll reset the cached information when going to sleep.
	 */
	/* ���������kswapd�߳��У������Ƴٴ�������������Ƴٴ������ִ�����if��� */
	if (compaction_restarting(zone, cc->order) && !current_is_kswapd())
		/* ����zone������pageblock����������ɨ�� */
		__reset_isolation_suitable(zone);

	/*
	 * Setup to move all movable pages to the end of the zone. Used cached
	 * information on where the scanners should start but check that it
	 * is initialised by ensuring the values are within zone boundaries.
	 */
	/* ���ƶ�ҳ��ɨ����ʼҳ��ţ���__reset_isolation_suitable�ᱻ����Ϊzone�е�һ��ҳ�� */
	cc->migrate_pfn = zone->compact_cached_migrate_pfn[sync];
	/* ����ҳ��ɨ����ʼҳ��ţ�������������__reset_isolation_suitable()�����ã��������Ϊzone�����һ��ҳ�� */
	cc->free_pfn = zone->compact_cached_free_pfn;
	/* ���cc->free_pfn�����������õ����������һ������pageblock�����һ��ҳ��
	 * �п��ܹ������Ĵ�С������pageblock�������������һ��pageblock���������ģ��Ͱ����ҳ�����ԣ�������ɨ�� 
	 */
	if (cc->free_pfn < start_pfn || cc->free_pfn > end_pfn) {
		cc->free_pfn = end_pfn & ~(pageblock_nr_pages-1);
		zone->compact_cached_free_pfn = cc->free_pfn;
	}
	/* ͬ�ϣ����cc->migrate_pfn�����������ƶ�ҳ��ɨ�����ʼҳ�� */
	if (cc->migrate_pfn < start_pfn || cc->migrate_pfn > end_pfn) {
		cc->migrate_pfn = start_pfn;
		zone->compact_cached_migrate_pfn[0] = cc->migrate_pfn;
		zone->compact_cached_migrate_pfn[1] = cc->migrate_pfn;
	}

	trace_mm_compaction_begin(start_pfn, cc->migrate_pfn, cc->free_pfn, end_pfn);
	
	/* ������pagevec�е�ҳ���Ż�ԭ��������lru�У���һ������Ҫ */
	migrate_prep_local();

	/* compact_finished�����ж��Ƿ��Ѿ�����ڴ�ѹ��
	 * ��Ҫ�ж�cc->free_pfn <= cc->migrate_pfn������û�з�������cc->contended�б����Ƿ���Ҫ��ֹ
	 */
	while ((ret = compact_finished(zone, cc, migratetype)) ==
						COMPACT_CONTINUE) {
		int err;

		/* �����ƶ�ҳ(MOVABLE��CMA��RECLAIMABLE)��zone->lru����������浽cc->migratepages���������һ��һ��pageblock����ɨ�裬��һ��pageblockɨ��ɹ���ȡ�����ƶ�ҳ��ͷ���
		 * һ��ɨ�����32*1024��ҳ��
		 */
		/* �첽������RECLAIMABLEҳ */
		switch (isolate_migratepages(zone, cc)) {
		case ISOLATE_ABORT:
			/* ʧ�ܣ�����Щҳ�Żص�lru����ԭ���ĵط� */
			ret = COMPACT_PARTIAL;
			putback_movable_pages(&cc->migratepages);
			cc->nr_migratepages = 0;
			goto out;
		case ISOLATE_NONE:
			continue;
		case ISOLATE_SUCCESS:
			;
		}

		/* �����������ҳ����Ǩ�ƣ���������cc->migratepages�����Ҳֻ��һ��pageblock��ҳ��������������Щҳ���ǿ��ƶ��� 
		 * ����ҳ�����compaction_alloc�л�ȡ
		 * Ҳ���ǰѸ��������һ��pageblock�п��ƶ�ҳ�����ƶ�
		 */
		err = migrate_pages(&cc->migratepages, compaction_alloc,
				compaction_free, (unsigned long)cc, cc->mode,
				MR_COMPACTION);

		trace_mm_compaction_migratepages(cc->nr_migratepages, err,
							&cc->migratepages);

		/* All pages were either migrated or will be released */
		/* �������п��ƶ�ҳ��Ϊ0 */
		cc->nr_migratepages = 0;
		if (err) {
			/* ��ʣ��Ŀ��ƶ�ҳ�򷵻�ԭ����λ�� */
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
	/* ��ʣ��Ŀ���ҳ��Żػ��ϵͳ */
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
		/* ѹ�����������ҳ������ */
		.nr_freepages = 0,
		/* ѹ���������ƶ���ҳ������ */
		.nr_migratepages = 0,
		.order = order,
		/* ��ʾ��Ҫ�ƶ���ҳ�����ͣ���movable��reclaimable���֣�����ͬʱ���� */
		.gfp_mask = gfp_mask,
		/* ������ */
		.zone = zone,
		/* ͬ�����첽 */
		.mode = mode,
	};
	/* ��ʼ��һ������ҳ������ͷ */
	INIT_LIST_HEAD(&cc.freepages);
	/* ��ʼ��һ��movableҳ������ͷ */
	INIT_LIST_HEAD(&cc.migratepages);

	/* �����ڴ�ѹ�� */
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
/* ����ÿ�������������ڴ�ѹ�����г�һЩҳ 
 * order: 2�Ĵη�������Ƿ���ʱ���õ���������Ƿ���ʱϣ����ȡ��order�������ͨ��д��/proc/sys/vm/compact_memory�ļ�����ǿ���ڴ�ѹ����order����-1
 *
 */
unsigned long try_to_compact_pages(struct zonelist *zonelist,
			int order, gfp_t gfp_mask, nodemask_t *nodemask,
			enum migrate_mode mode, int *contended,
			struct zone **candidate_zone)
{
	enum zone_type high_zoneidx = gfp_zone(gfp_mask);
	/* ��ʾ����ʹ���ļ�ϵͳIO */
	int may_enter_fs = gfp_mask & __GFP_FS;
	/* ��ʾ����ʹ�ô���IO */
	int may_perform_io = gfp_mask & __GFP_IO;
	struct zoneref *z;
	struct zone *zone;
	int rc = COMPACT_DEFERRED;
	int alloc_flags = 0;
	int all_zones_contended = COMPACT_CONTENDED_LOCK; /* init for &= op */

	*contended = COMPACT_CONTENDED_NONE;

	/* Check if the GFP flags allow compaction */
	/* ���order=0���߲�����ʹ���ļ�ϵͳIO�ʹ���IO������������ѹ������Ϊ��ʹ��IO�п��ܵ������� */
	if (!order || !may_enter_fs || !may_perform_io)
		return COMPACT_SKIPPED;

#ifdef CONFIG_CMA
	/* ��������CMA������£�����������Ҫ���ڴ�ΪMIGRATE_MOVABLE��������һ��ALLOC_CMA��־ */
	if (gfpflags_to_migratetype(gfp_mask) == MIGRATE_MOVABLE)
		alloc_flags |= ALLOC_CMA;
#endif
	/* Compact each zone in the list */
	/* �������������������еĹ����� */
	for_each_zone_zonelist_nodemask(zone, z, zonelist, high_zoneidx,
								nodemask) {
		int status;
		int zone_contended;

		/* ���������������Ƿ���Ҫ�����˴�ѹ�� 
		 * �жϱ�׼��:
		 * zone->compact_considered�Ƿ�С��1UL << zone->compact_defer_shift
		 * С�����Ƴ٣�����zone->compact_considered++��Ҳ�����������������ȥ�Ƴٴ˹��������ڴ�ѹ��
		 */
		if (compaction_deferred(zone, order))
			continue;

		/* ���й��������ڴ�ѹ�� */
		status = compact_zone_order(zone, order, gfp_mask, mode,
							&zone_contended);
		rc = max(status, rc);
		/*
		 * It takes at least one zone that wasn't lock contended
		 * to clear all_zones_contended.
		 */
		all_zones_contended &= zone_contended;

		/* If a normal allocation would succeed, stop compacting */
		/* �ж�ѹ�����Ƿ��㹻�����ڴ���䣬����㹻���򲻻���¸�zone����ѹ���ˣ�ֱ������ */
		if (zone_watermark_ok(zone, order, low_wmark_pages(zone), 0,
				      alloc_flags)) {
			*candidate_zone = zone;
			/*
			 * We think the allocation will succeed in this zone,
			 * but it is not certain, hence the false. The caller
			 * will repeat this with true if allocation indeed
			 * succeeds in this zone.
			 */
			/* ���������ڴ�ѹ���������������0��Ҳ�������¼����ڴ�ѹ������ */
			compaction_defer_reset(zone, order, false);
			/*
			 * It is possible that async compaction aborted due to
			 * need_resched() and the watermarks were ok thanks to
			 * somebody else freeing memory. The allocation can
			 * however still fail so we better signal the
			 * need_resched() contention anyway (this will not
			 * prevent the allocation attempt).
			 */
			/* �첽�������Ҫ������ʱ������ */
			if (zone_contended == COMPACT_CONTENDED_SCHED)
				*contended = COMPACT_CONTENDED_SCHED;

			goto break_loop;
		}

		/* �����ͬ��ѹ�� */
		if (mode != MIGRATE_ASYNC) {
			/*
			 * We think that allocation won't succeed in this zone
			 * so we defer compaction there. If it ends up
			 * succeeding after all, it will be reset.
			 */
			/* ����ڴ�ѹ���������ķ�ֵ��zone���ڴ�ѹ����������ֵ */
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