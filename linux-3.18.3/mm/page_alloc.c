/*
 *  linux/mm/page_alloc.c
 *
 *  Manages the free list, the system allocates free pages here.
 *  Note that kmalloc() lives in slab.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *  Swap reorganised 29.12.95, Stephen Tweedie
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
 *  Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
 *  Zone balancing, Kanoj Sarcar, SGI, Jan 2000
 *  Per cpu hot/cold page lists, bulk allocation, Martin J. Bligh, Sept 2002
 *          (lots of bits borrowed from Ingo Molnar & Andrew Morton)
 */

#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/jiffies.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kmemcheck.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/oom.h>
#include <linux/notifier.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/memory_hotplug.h>
#include <linux/nodemask.h>
#include <linux/vmalloc.h>
#include <linux/vmstat.h>
#include <linux/mempolicy.h>
#include <linux/stop_machine.h>
#include <linux/sort.h>
#include <linux/pfn.h>
#include <linux/backing-dev.h>
#include <linux/fault-inject.h>
#include <linux/page-isolation.h>
#include <linux/page_cgroup.h>
#include <linux/debugobjects.h>
#include <linux/kmemleak.h>
#include <linux/compaction.h>
#include <trace/events/kmem.h>
#include <linux/prefetch.h>
#include <linux/mm_inline.h>
#include <linux/migrate.h>
#include <linux/page-debug-flags.h>
#include <linux/hugetlb.h>
#include <linux/sched/rt.h>

#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/div64.h>
#include "internal.h"

/* prevent >1 _updater_ of zone percpu pageset ->high and ->batch fields */
static DEFINE_MUTEX(pcp_batch_high_lock);
#define MIN_PERCPU_PAGELIST_FRACTION	(8)

#ifdef CONFIG_USE_PERCPU_NUMA_NODE_ID
DEFINE_PER_CPU(int, numa_node);
EXPORT_PER_CPU_SYMBOL(numa_node);
#endif

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
/*
 * N.B., Do NOT reference the '_numa_mem_' per cpu variable directly.
 * It will not be defined when CONFIG_HAVE_MEMORYLESS_NODES is not defined.
 * Use the accessor functions set_numa_mem(), numa_mem_id() and cpu_to_mem()
 * defined in <linux/topology.h>.
 */
DEFINE_PER_CPU(int, _numa_mem_);		/* Kernel "local memory" node */
EXPORT_PER_CPU_SYMBOL(_numa_mem_);
int _node_numa_mem_[MAX_NUMNODES];
#endif

/*
 * Array of node states.
 */
nodemask_t node_states[NR_NODE_STATES] __read_mostly = {
	[N_POSSIBLE] = NODE_MASK_ALL,
	[N_ONLINE] = { { [0] = 1UL } },
#ifndef CONFIG_NUMA
	[N_NORMAL_MEMORY] = { { [0] = 1UL } },
#ifdef CONFIG_HIGHMEM
	[N_HIGH_MEMORY] = { { [0] = 1UL } },
#endif
#ifdef CONFIG_MOVABLE_NODE
	[N_MEMORY] = { { [0] = 1UL } },
#endif
	[N_CPU] = { { [0] = 1UL } },
#endif	/* NUMA */
};
EXPORT_SYMBOL(node_states);

/* Protect totalram_pages and zone->managed_pages */
static DEFINE_SPINLOCK(managed_page_count_lock);

unsigned long totalram_pages __read_mostly;
unsigned long totalreserve_pages __read_mostly;
/*
 * When calculating the number of globally allowed dirty pages, there
 * is a certain number of per-zone reserves that should not be
 * considered dirtyable memory.  This is the sum of those reserves
 * over all existing zones that contribute dirtyable memory.
 */
unsigned long dirty_balance_reserve __read_mostly;

int percpu_pagelist_fraction;
gfp_t gfp_allowed_mask __read_mostly = GFP_BOOT_MASK;

#ifdef CONFIG_PM_SLEEP
/*
 * The following functions are used by the suspend/hibernate code to temporarily
 * change gfp_allowed_mask in order to avoid using I/O during memory allocations
 * while devices are suspended.  To avoid races with the suspend/hibernate code,
 * they should always be called with pm_mutex held (gfp_allowed_mask also should
 * only be modified with pm_mutex held, unless the suspend/hibernate code is
 * guaranteed not to run in parallel with that modification).
 */

static gfp_t saved_gfp_mask;

void pm_restore_gfp_mask(void)
{
	WARN_ON(!mutex_is_locked(&pm_mutex));
	if (saved_gfp_mask) {
		gfp_allowed_mask = saved_gfp_mask;
		saved_gfp_mask = 0;
	}
}

void pm_restrict_gfp_mask(void)
{
	WARN_ON(!mutex_is_locked(&pm_mutex));
	WARN_ON(saved_gfp_mask);
	saved_gfp_mask = gfp_allowed_mask;
	gfp_allowed_mask &= ~GFP_IOFS;
}

bool pm_suspended_storage(void)
{
	if ((gfp_allowed_mask & GFP_IOFS) == GFP_IOFS)
		return false;
	return true;
}
#endif /* CONFIG_PM_SLEEP */

#ifdef CONFIG_HUGETLB_PAGE_SIZE_VARIABLE
int pageblock_order __read_mostly;
#endif

static void __free_pages_ok(struct page *page, unsigned int order);

/*
 * results with 256, 32 in the lowmem_reserve sysctl:
 *	1G machine -> (16M dma, 800M-16M normal, 1G-800M high)
 *	1G machine -> (16M dma, 784M normal, 224M high)
 *	NORMAL allocation will leave 784M/256 of ram reserved in the ZONE_DMA
 *	HIGHMEM allocation will leave 224M/32 of ram reserved in ZONE_NORMAL
 *	HIGHMEM allocation will (224M+784M)/256 of ram reserved in ZONE_DMA
 *
 * TBD: should special case ZONE_DMA32 machines here - in those we normally
 * don't need any ZONE_NORMAL reservation
 */
int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES-1] = {
#ifdef CONFIG_ZONE_DMA
	 256,
#endif
#ifdef CONFIG_ZONE_DMA32
	 256,
#endif
#ifdef CONFIG_HIGHMEM
	 32,
#endif
	 32,
};

EXPORT_SYMBOL(totalram_pages);

static char * const zone_names[MAX_NR_ZONES] = {
#ifdef CONFIG_ZONE_DMA
	 "DMA",
#endif
#ifdef CONFIG_ZONE_DMA32
	 "DMA32",
#endif
	 "Normal",
#ifdef CONFIG_HIGHMEM
	 "HighMem",
#endif
	 "Movable",
};

int min_free_kbytes = 1024;
int user_min_free_kbytes = -1;

static unsigned long __meminitdata nr_kernel_pages;
static unsigned long __meminitdata nr_all_pages;
static unsigned long __meminitdata dma_reserve;

#ifdef CONFIG_HAVE_MEMBLOCK_NODE_MAP
static unsigned long __meminitdata arch_zone_lowest_possible_pfn[MAX_NR_ZONES];
static unsigned long __meminitdata arch_zone_highest_possible_pfn[MAX_NR_ZONES];
static unsigned long __initdata required_kernelcore;
static unsigned long __initdata required_movablecore;
static unsigned long __meminitdata zone_movable_pfn[MAX_NUMNODES];

/* movable_zone is the "real" zone pages in ZONE_MOVABLE are taken from */
int movable_zone;
EXPORT_SYMBOL(movable_zone);
#endif /* CONFIG_HAVE_MEMBLOCK_NODE_MAP */

#if MAX_NUMNODES > 1
int nr_node_ids __read_mostly = MAX_NUMNODES;
int nr_online_nodes __read_mostly = 1;
EXPORT_SYMBOL(nr_node_ids);
EXPORT_SYMBOL(nr_online_nodes);
#endif

int page_group_by_mobility_disabled __read_mostly;

void set_pageblock_migratetype(struct page *page, int migratetype)
{
	if (unlikely(page_group_by_mobility_disabled &&
		     migratetype < MIGRATE_PCPTYPES))
		migratetype = MIGRATE_UNMOVABLE;

	set_pageblock_flags_group(page, (unsigned long)migratetype,
					PB_migrate, PB_migrate_end);
}

bool oom_killer_disabled __read_mostly;

#ifdef CONFIG_DEBUG_VM
static int page_outside_zone_boundaries(struct zone *zone, struct page *page)
{
	int ret = 0;
	unsigned seq;
	unsigned long pfn = page_to_pfn(page);
	unsigned long sp, start_pfn;

	do {
		seq = zone_span_seqbegin(zone);
		start_pfn = zone->zone_start_pfn;
		sp = zone->spanned_pages;
		if (!zone_spans_pfn(zone, pfn))
			ret = 1;
	} while (zone_span_seqretry(zone, seq));

	if (ret)
		pr_err("page 0x%lx outside node %d zone %s [ 0x%lx - 0x%lx ]\n",
			pfn, zone_to_nid(zone), zone->name,
			start_pfn, start_pfn + sp);

	return ret;
}

static int page_is_consistent(struct zone *zone, struct page *page)
{
	if (!pfn_valid_within(page_to_pfn(page)))
		return 0;
	if (zone != page_zone(page))
		return 0;

	return 1;
}
/*
 * Temporary debugging check for pages not lying within a given zone.
 */
static int bad_range(struct zone *zone, struct page *page)
{
	if (page_outside_zone_boundaries(zone, page))
		return 1;
	if (!page_is_consistent(zone, page))
		return 1;

	return 0;
}
#else
static inline int bad_range(struct zone *zone, struct page *page)
{
	return 0;
}
#endif

static void bad_page(struct page *page, const char *reason,
		unsigned long bad_flags)
{
	static unsigned long resume;
	static unsigned long nr_shown;
	static unsigned long nr_unshown;

	/* Don't complain about poisoned pages */
	if (PageHWPoison(page)) {
		page_mapcount_reset(page); /* remove PageBuddy */
		return;
	}

	/*
	 * Allow a burst of 60 reports, then keep quiet for that minute;
	 * or allow a steady drip of one report per second.
	 */
	if (nr_shown == 60) {
		if (time_before(jiffies, resume)) {
			nr_unshown++;
			goto out;
		}
		if (nr_unshown) {
			printk(KERN_ALERT
			      "BUG: Bad page state: %lu messages suppressed\n",
				nr_unshown);
			nr_unshown = 0;
		}
		nr_shown = 0;
	}
	if (nr_shown++ == 0)
		resume = jiffies + 60 * HZ;

	printk(KERN_ALERT "BUG: Bad page state in process %s  pfn:%05lx\n",
		current->comm, page_to_pfn(page));
	dump_page_badflags(page, reason, bad_flags);

	print_modules();
	dump_stack();
out:
	/* Leave bad fields for debug, except PageBuddy could make trouble */
	page_mapcount_reset(page); /* remove PageBuddy */
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
}

/*
 * Higher-order pages are called "compound pages".  They are structured thusly:
 *
 * The first PAGE_SIZE page is called the "head page".
 *
 * The remaining PAGE_SIZE pages are called "tail pages".
 *
 * All pages have PG_compound set.  All tail pages have their ->first_page
 * pointing at the head page.
 *
 * The first tail page's ->lru.next holds the address of the compound page's
 * put_page() function.  Its ->lru.prev holds the order of allocation.
 * This usage means that zero-order pages may not be compound.
 */

static void free_compound_page(struct page *page)
{
	__free_pages_ok(page, compound_order(page));
}

/* 如果用于大页，那么这里是对这些连续的页组成的大页进行处理 */
void prep_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;

	/* page[1].lru.next设置为指向析构函数free_compound_page */
	set_compound_page_dtor(page, free_compound_page);
	/* page[1].lru.prev设置为大页的order值 */
	set_compound_order(page, order);
	/* 设置大页的第一个页的PG_head */
	__SetPageHead(page);
	for (i = 1; i < nr_pages; i++) {
		struct page *p = page + i;
		/* 大页中所有页的page->_count都设置为0 */
		set_page_count(p, 0);
		/* 大页中所有页的page->first_page都指向这段组成大页的连续页框的第一个页 */
		p->first_page = page;
		/* Make sure p->first_page is always valid for PageTail() */
		smp_wmb();
		/* 这段连续页框的最后一个页设置PG_tail标志 */
		__SetPageTail(p);
	}
}

/* update __split_huge_page_refcount if you change this function */
static int destroy_compound_page(struct page *page, unsigned long order)
{
	int i;
	int nr_pages = 1 << order;
	int bad = 0;

	if (unlikely(compound_order(page) != order)) {
		bad_page(page, "wrong compound order", 0);
		bad++;
	}

	__ClearPageHead(page);

	for (i = 1; i < nr_pages; i++) {
		struct page *p = page + i;

		if (unlikely(!PageTail(p))) {
			bad_page(page, "PageTail not set", 0);
			bad++;
		} else if (unlikely(p->first_page != page)) {
			bad_page(page, "first_page not consistent", 0);
			bad++;
		}
		__ClearPageTail(p);
	}

	return bad;
}

static inline void prep_zero_page(struct page *page, unsigned int order,
							gfp_t gfp_flags)
{
	int i;

	/*
	 * clear_highpage() will use KM_USER0, so it's a bug to use __GFP_ZERO
	 * and __GFP_HIGHMEM from hard or soft interrupt context.
	 */
	VM_BUG_ON((gfp_flags & __GFP_HIGHMEM) && in_interrupt());
	for (i = 0; i < (1 << order); i++)
		clear_highpage(page + i);
}

#ifdef CONFIG_DEBUG_PAGEALLOC
unsigned int _debug_guardpage_minorder;

static int __init debug_guardpage_minorder_setup(char *buf)
{
	unsigned long res;

	if (kstrtoul(buf, 10, &res) < 0 ||  res > MAX_ORDER / 2) {
		printk(KERN_ERR "Bad debug_guardpage_minorder value\n");
		return 0;
	}
	_debug_guardpage_minorder = res;
	printk(KERN_INFO "Setting debug_guardpage_minorder to %lu\n", res);
	return 0;
}
__setup("debug_guardpage_minorder=", debug_guardpage_minorder_setup);

static inline void set_page_guard_flag(struct page *page)
{
	__set_bit(PAGE_DEBUG_FLAG_GUARD, &page->debug_flags);
}

static inline void clear_page_guard_flag(struct page *page)
{
	__clear_bit(PAGE_DEBUG_FLAG_GUARD, &page->debug_flags);
}
#else
static inline void set_page_guard_flag(struct page *page) { }
static inline void clear_page_guard_flag(struct page *page) { }
#endif

static inline void set_page_order(struct page *page, unsigned int order)
{
	set_page_private(page, order);
	__SetPageBuddy(page);
}

/* 设置page->_mapcount = -1 并且 page->private = 0 */
static inline void rmv_page_order(struct page *page)
{
	__ClearPageBuddy(page);
	set_page_private(page, 0);
}

/*
 * This function checks whether a page is free && is the buddy
 * we can do coalesce a page and its buddy if
 * (a) the buddy is not in a hole &&
 * (b) the buddy is in the buddy system &&
 * (c) a page and its buddy have the same order &&
 * (d) a page and its buddy are in the same zone.
 *
 * For recording whether a page is in the buddy system, we set ->_mapcount
 * PAGE_BUDDY_MAPCOUNT_VALUE.
 * Setting, clearing, and testing _mapcount PAGE_BUDDY_MAPCOUNT_VALUE is
 * serialized by zone->lock.
 *
 * For recording page's order, we use page_private(page).
 */
/* 
 * 返回0说明page和buddy不能够合并
 * 返回1说明page和buddy可以合并
 */
static inline int page_is_buddy(struct page *page, struct page *buddy,
							unsigned int order)
{
	/* 检查buddy对应的pfnid是否有效 */
	if (!pfn_valid_within(page_to_pfn(buddy)))
		return 0;

	if (page_is_guard(buddy) && page_order(buddy) == order) {
		VM_BUG_ON_PAGE(page_count(buddy) != 0, buddy);

		/* 检查page和buddy是否处于同一个zone */
		if (page_zone_id(page) != page_zone_id(buddy))
			return 0;

		return 1;
	}

	if (PageBuddy(buddy) && page_order(buddy) == order) {
		VM_BUG_ON_PAGE(page_count(buddy) != 0, buddy);

		/*
		 * zone check is done late to avoid uselessly
		 * calculating zone/node ids for pages that could
		 * never merge.
		 */
		/* 检查是否属于同一个zone */
		if (page_zone_id(page) != page_zone_id(buddy))
			return 0;

		return 1;
	}
	return 0;
}

/*
 * Freeing function for a buddy system allocator.
 *
 * The concept of a buddy system is to maintain direct-mapped table
 * (containing bit values) for memory blocks of various "orders".
 * The bottom level table contains the map for the smallest allocatable
 * units of memory (here, pages), and each level above it describes
 * pairs of units from the levels below, hence, "buddies".
 * At a high level, all that happens here is marking the table entry
 * at the bottom level available, and propagating the changes upward
 * as necessary, plus some accounting needed to play nicely with other
 * parts of the VM system.
 * At each level, we keep a list of pages, which are heads of continuous
 * free pages of length of (1 << order) and marked with _mapcount
 * PAGE_BUDDY_MAPCOUNT_VALUE. Page's order is recorded in page_private(page)
 * field.
 * So when we are allocating or freeing one, we can derive the state of the
 * other.  That is, if we allocate a small block, and both were
 * free, the remainder of the region must be split into blocks.
 * If a block is freed, and its buddy is also free, then this
 * triggers coalescing into a block of larger size.
 *
 * -- nyc
 */

static inline void __free_one_page(struct page *page,
		unsigned long pfn,
		struct zone *zone, unsigned int order,
		int migratetype)
{
	/* 保存块中第一个页框的下标，这个下标相对于管理区而言，而不是node */
	unsigned long page_idx;
	unsigned long combined_idx;
	unsigned long uninitialized_var(buddy_idx);
	struct page *buddy;
	int max_order = MAX_ORDER;

	VM_BUG_ON(!zone_is_initialized(zone));

	if (unlikely(PageCompound(page)))
		if (unlikely(destroy_compound_page(page, order)))
			return;

	VM_BUG_ON(migratetype == -1);
	if (is_migrate_isolate(migratetype)) {
		/*
		 * We restrict max order of merging to prevent merge
		 * between freepages on isolate pageblock and normal
		 * pageblock. Without this, pageblock isolation
		 * could cause incorrect freepage accounting.
		 */
		/* 如果管理区使用了内存隔离，则最大的order应该为内存块最大的order */
		max_order = min(MAX_ORDER, pageblock_order + 1);
	} else {
		__mod_zone_freepage_state(zone, 1 << order, migratetype);
	}

	/* page的pfn号 */
	page_idx = pfn & ((1 << max_order) - 1);

	VM_BUG_ON_PAGE(page_idx & ((1 << order) - 1), page);
	VM_BUG_ON_PAGE(bad_range(zone, page), page);

	/* 主要，最多循环9次，每次都尽量把一个块和它的伙伴进行合并，以最小块开始 */
	while (order < max_order - 1) {
		/* buddy_idx = page_idx ^ (1 << order) */
		/* buddy_idx是page_idx的伙伴的页框号 */
		/* 伙伴的页框号就是page_idx的第(1 << order)位的相反数，比如(1<<order)是4，page_idx是01110，则buddy_idx是01010，由此可见伙伴并不一定是之后的区间 */
		/*
		 *      对于000000 ~ 001000这个页框号区间，假设order是3，左边是第一种情况，右边是另一种情况
		 *
		 *                            -----------
		 *                           |           |
		 *                           |           |
		 *                           |           |
		 * page_idx = 000100 ------> |-----------|    计算后buddy_idx = 000100
		 *                           |           |
		 *                           |           |
		 *                           |           |
		 * 计算后buddy_idx = 000000   -----------     page_idx = 000000
		 */
		buddy_idx = __find_buddy_index(page_idx, order);
		/* 伙伴的页描述符，就是buddy_idx对应的页描述符 */
		buddy = page + (buddy_idx - page_idx);
		
		/* 检查buddy与page是否是伙伴，并且检查buddy是否是大小为2^order个空闲页框块的第一个页
		 * 如果是，说明这个buddy是可以进行合并的，否则跳出
		 */
		if (!page_is_buddy(page, buddy, order))
			break;
		/*
		 * Our buddy is free or it is CONFIG_DEBUG_PAGEALLOC guard page,
		 * merge with it and move up one order.
		 */
		/* 以下是找到的buddy是可以进行合并的情况才会执行 */
		
		if (page_is_guard(buddy)) {
			/* 设置了PAGE_DEBUG_FLAG_GUARD的情况 */

			/* 清除PAGE_DEBUG_FLAG_GUARD位 */
			clear_page_guard_flag(buddy);
			/* 清空伙伴的buddy的private，这个private用于保存在伙伴系统中的连续页框的order值 */
			set_page_private(buddy, 0);
			if (!is_migrate_isolate(migratetype)) {
				__mod_zone_freepage_state(zone, 1 << order,
							  migratetype);
			}
		} else {
			/* 将伙伴从当前空闲链表中移除出来 */
			list_del(&buddy->lru);
			/* 此order的连续页框块数量-- */
			zone->free_area[order].nr_free--;
			/* 设置page->_mapcount = -1 并且 page->private = 0
			 * _mapcount说明此页框空闲的，没有被使用，private在空闲的页框中用于表示连续页框的order值，这里也清空，后面会在这段连续页框块的第一个page中设置
			 */
			rmv_page_order(buddy);
		}
		/* combined_idx 是 buddy_idx 与 page_idx 中最小的那个idx */
		combined_idx = buddy_idx & page_idx;
		/* 这里会获得合并后的连续页框块的第一个page的描述符 */
		page = page + (combined_idx - page_idx);
		/* 这块合并好的连续页框块的第一个page的ID */
		page_idx = combined_idx;
		/* order++，继续尝试进行合并 */
		order++;
	}
	/* 循环结束，已经不能够继续进行合并了，这时候会对这块连续页框块的第一个page设置order值，设置在page->private中 */
	set_page_order(page, order);
	
	/*
	 * If this is not the largest possible page, check if the buddy
	 * of the next-highest order is free. If it is, it's possible
	 * that pages are being freed that will coalesce soon. In case,
	 * that is happening, add the free page to the tail of the list
	 * so it's less likely to be used soon and more likely to be merged
	 * as a higher order page
	 */
	/* 这里会检查能否再进一步合并，因为上面的循环最多只能将order合并到9，而order最大能到10，但是这里只是检查能否合并，如果能够合并，也没有进行合并 */
	if ((order < MAX_ORDER-2) && pfn_valid_within(page_to_pfn(buddy))) {
		struct page *higher_page, *higher_buddy;
		/* combined_idx 是 buddy_idx 与 page_idx 中最小的那个idx
		 * 从上面看下来，应该就等于page_idx
		 */
		combined_idx = buddy_idx & page_idx;
		/* 这里就是page的描述符，combined_idx == page_idx */
		higher_page = page + (combined_idx - page_idx);
		/* 找到order+1的伙伴 */
		buddy_idx = __find_buddy_index(combined_idx, order + 1);
		/* 获取buddy_idx对应的页描述符 */
		higher_buddy = higher_page + (buddy_idx - combined_idx);
		/* 检查higher_buddy与higher_page是否是伙伴，并且检查higher_buddy是否是大小为2^order个空闲页框块的第一个页
		 * 如果是，说明这个higher_buddy是可以进行合并的，否则跳出
		 * 这里比较奇怪，检查的是order+1，而page的order是order，并不是order+1
		 */
		if (page_is_buddy(higher_page, higher_buddy, order + 1)) {
			/* 加入到zone管理区order链表的尾部 */
			list_add_tail(&page->lru,
				&zone->free_area[order].free_list[migratetype]);
			goto out;
		}
	}

	/* 加入空闲块链表 */
	list_add(&page->lru, &zone->free_area[order].free_list[migratetype]);
out:
	/* 对应空闲链表中空闲块数量加1 */
	zone->free_area[order].nr_free++;
}

static inline int free_pages_check(struct page *page)
{
	const char *bad_reason = NULL;
	unsigned long bad_flags = 0;

	/* 参数是否正确，_mapcount应该为0 */
	if (unlikely(page_mapcount(page)))
		bad_reason = "nonzero mapcount";

	/* 页是否处于高速缓存或者匿名区中 */
	if (unlikely(page->mapping != NULL))
		bad_reason = "non-NULL mapping";
	
	/* 还有进程在使用此页 */
	if (unlikely(atomic_read(&page->_count) != 0))
		bad_reason = "nonzero _count";

	
	if (unlikely(page->flags & PAGE_FLAGS_CHECK_AT_FREE)) {
		bad_reason = "PAGE_FLAGS_CHECK_AT_FREE flag(s) set";
		bad_flags = PAGE_FLAGS_CHECK_AT_FREE;
	}
	
	if (unlikely(mem_cgroup_bad_page_check(page)))
		bad_reason = "cgroup check failed";
	if (unlikely(bad_reason)) {
		bad_page(page, bad_reason, bad_flags);
		return 1;
	}
	page_cpupid_reset_last(page);
	if (page->flags & PAGE_FLAGS_CHECK_AT_PREP)
		page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
	return 0;
}

/*
 * Frees a number of pages from the PCP lists
 * Assumes all pages on list are in same zone, and of same order.
 * count is the number of pages to free.
 *
 * If the zone was previously in an "all pages pinned" state then look to
 * see if this freeing clears that state.
 *
 * And clear the zone's pages_scanned counter, to hold off the "all pages are
 * pinned" detection logic.
 */
static void free_pcppages_bulk(struct zone *zone, int count,
					struct per_cpu_pages *pcp)
{
	int migratetype = 0;
	int batch_free = 0;
	int to_free = count;
	unsigned long nr_scanned;

	/* 将管理区上锁 */
	spin_lock(&zone->lock);
	nr_scanned = zone_page_state(zone, NR_PAGES_SCANNED);
	if (nr_scanned)
		__mod_zone_page_state(zone, NR_PAGES_SCANNED, -nr_scanned);

	/* to_free代表放回伙伴系统的页框数量 */
	while (to_free) {
		struct page *page;
		struct list_head *list;

		/*
		 * Remove pages from lists in a round-robin fashion. A
		 * batch_free count is maintained that is incremented when an
		 * empty list is encountered.  This is so more pages are freed
		 * off fuller lists instead of spinning excessively around empty
		 * lists
		 */
		/* 找一个可以移动的页框类型链表 */
		do {
			batch_free++;
			if (++migratetype == MIGRATE_PCPTYPES)
				migratetype = 0;
			list = &pcp->lists[migratetype];
		} while (list_empty(list));

		/* This is the only non-empty list. Free them all. */
		if (batch_free == MIGRATE_PCPTYPES)
			batch_free = to_free;

		do {
			int mt;	/* migratetype of the to-be-freed page */

			/* 从页框链表中取出一个页框 */
			page = list_entry(list->prev, struct page, lru);
			list_del(&page->lru);

			/* 此页框的标识符 */
			mt = get_freepage_migratetype(page);
			if (unlikely(has_isolate_pageblock(zone)))
				mt = get_pageblock_migratetype(page);

			/* MIGRATE_MOVABLE list may include MIGRATE_RESERVEs */
			/* 这个函数用于释放页框，可以用于放入伙伴系统 */
			__free_one_page(page, page_to_pfn(page), zone, 0, mt);
			trace_mm_page_pcpu_drain(page, 0, mt);
		} while (--to_free && --batch_free && !list_empty(list));
	}
	spin_unlock(&zone->lock);
}

static void free_one_page(struct zone *zone,
				struct page *page, unsigned long pfn,
				unsigned int order,
				int migratetype)
{
	unsigned long nr_scanned;
	/* 管理区上锁 */
	spin_lock(&zone->lock);
	
	/* 数据更新 */
	nr_scanned = zone_page_state(zone, NR_PAGES_SCANNED);
	if (nr_scanned)
		__mod_zone_page_state(zone, NR_PAGES_SCANNED, -nr_scanned);

	/* 如果有内存隔离使用的pageblock */
	if (unlikely(has_isolate_pageblock(zone) ||
		is_migrate_isolate(migratetype))) {
		migratetype = get_pfnblock_migratetype(page, pfn);
	}
	/* 释放page开始的order次方个页框到伙伴系统，这些页框的类型是migratetype */
	__free_one_page(page, pfn, zone, order, migratetype);
	/* 管理区解锁 */
	spin_unlock(&zone->lock);
}

static bool free_pages_prepare(struct page *page, unsigned int order)
{
	int i;
	int bad = 0;

	trace_mm_page_free(page, order);
	kmemcheck_free_shadow(page, order);

	/* 如果是匿名页框 */
	if (PageAnon(page))
		page->mapping = NULL;

	/* 检查这个连续页框中所有的页 */
	for (i = 0; i < (1 << order); i++)
		bad += free_pages_check(page + i);
	if (bad)
		return false;

	if (!PageHighMem(page)) {
		/* 不是高端内存区 */
		/* 检查这段内存是否有上锁 */
		debug_check_no_locks_freed(page_address(page),
					   PAGE_SIZE << order);
		debug_check_no_obj_freed(page_address(page),
					   PAGE_SIZE << order);
	}
	arch_free_page(page, order);
	kernel_map_pages(page, 1 << order, 0);

	return true;
}

static void __free_pages_ok(struct page *page, unsigned int order)
{
	unsigned long flags;
	int migratetype;
	/* 获取页框号 */
	unsigned long pfn = page_to_pfn(page);

	/* 准备，各种检查 */
	if (!free_pages_prepare(page, order))
		return;

	/* 获取页框所在pageblock的页框类型 */
	migratetype = get_pfnblock_migratetype(page, pfn);
	/* 禁止中断 */
	local_irq_save(flags);
	/* 统计当前CPU一共释放的页框数 */
	__count_vm_events(PGFREE, 1 << order);
	/* 设置这块连续页框块的类型与所在pageblock类型一致，保存在page->index中 */
	set_freepage_migratetype(page, migratetype);
	/* 释放函数 */
	free_one_page(page_zone(page), page, pfn, order, migratetype);
	local_irq_restore(flags);
}

void __init __free_pages_bootmem(struct page *page, unsigned int order)
{
	/* 需要释放的页数量 */
	unsigned int nr_pages = 1 << order;
	struct page *p = page;
	unsigned int loop;

	/* 预取指令，该指令用于把将要使用到的数据从内存提前装入缓存中，以减少访问主存的指令执行时的延迟 */
	prefetchw(p);
	for (loop = 0; loop < (nr_pages - 1); loop++, p++) {
		/* 预取下一个页描述符 */
		prefetchw(p + 1);
		__ClearPageReserved(p);
		/* 设置page->_count = 0 */
		set_page_count(p, 0);
	}
	__ClearPageReserved(p);
	set_page_count(p, 0);

	/* 管理区的managed_pages加上这些页数量 */
	page_zone(page)->managed_pages += nr_pages;
	/* 将首页框的_count设置为1，代表被使用，因为被使用的页框才能够释放 */
	set_page_refcounted(page);
	/* 释放到管理区的伙伴系统 */
	__free_pages(page, order);
}

#ifdef CONFIG_CMA
/* Free whole pageblock and set its migration type to MIGRATE_CMA. */
void __init init_cma_reserved_pageblock(struct page *page)
{
	unsigned i = pageblock_nr_pages;
	struct page *p = page;

	do {
		__ClearPageReserved(p);
		set_page_count(p, 0);
	} while (++p, --i);

	set_pageblock_migratetype(page, MIGRATE_CMA);

	if (pageblock_order >= MAX_ORDER) {
		i = pageblock_nr_pages;
		p = page;
		do {
			set_page_refcounted(p);
			__free_pages(p, MAX_ORDER - 1);
			p += MAX_ORDER_NR_PAGES;
		} while (i -= MAX_ORDER_NR_PAGES);
	} else {
		set_page_refcounted(page);
		__free_pages(page, pageblock_order);
	}

	adjust_managed_page_count(page, pageblock_nr_pages);
}
#endif

/*
 * The order of subdivision here is critical for the IO subsystem.
 * Please do not alter this order without good reasons and regression
 * testing. Specifically, as large blocks of memory are subdivided,
 * the order in which smaller blocks are delivered depends on the order
 * they're subdivided in this function. This is the primary factor
 * influencing the order in which pages are delivered to the IO
 * subsystem according to empirical testing, and this is also justified
 * by considering the behavior of a buddy system containing a single
 * large block of memory acted on by a series of small allocations.
 * This behavior is a critical factor in sglist merging's success.
 *
 * -- nyc
 */
/* 此函数用于将多余的块放入伙伴系统中
 * 算法思想，因为伙伴系统中获得的块是连续的，比如我们需要2个页框，但是伙伴系统从连续的8个页框中分配给我们两个
 * 此时将8个页框中后4个放入伙伴系统中4个连续页框的链表，再将所剩4个中的后2个放入2个连续页框的链表，结束
 *
 */
static inline void expand(struct zone *zone, struct page *page,
	int low, int high, struct free_area *area,
	int migratetype)
{
	unsigned long size = 1 << high;

	/* low是目标次方数，high是当前次方数，比如我们需要2个页框，这里low就是1，而我们是从连续8个页框的伙伴系统链表中分配的，这里high就是3 */
	while (high > low) {
		area--;
		high--;
		size >>= 1;
		VM_BUG_ON_PAGE(bad_range(zone, &page[size]), &page[size]);

#ifdef CONFIG_DEBUG_PAGEALLOC
		if (high < debug_guardpage_minorder()) {
			/*
			 * Mark as guard pages (or page), that will allow to
			 * merge back to allocator when buddy will be freed.
			 * Corresponding page table entries will not be touched,
			 * pages will stay not present in virtual address space
			 */
			INIT_LIST_HEAD(&page[size].lru);
			set_page_guard_flag(&page[size]);
			/* 设置需要放入链表中的头页框的private为次方数 */
			set_page_private(&page[size], high);
			/* Guard pages are not available for any usage */
			__mod_zone_freepage_state(zone, -(1 << high),
						  migratetype);
			continue;
		}
#endif
		/* 使用page->lru链表结点加入到伙伴系统的空闲链表中 */
		list_add(&page[size].lru, &area->free_list[migratetype]);
		area->nr_free++;
		/* 设置需要放入链表中的头页框的private为次方数 */
		set_page_order(&page[size], high);
	}
}

/*
 * This page is about to be returned from the page allocator
 */
/* 检查页描述符中的参数是否为空闲页 */
static inline int check_new_page(struct page *page)
{
	const char *bad_reason = NULL;
	unsigned long bad_flags = 0;

	/* page->_mapcount = -1为空闲页，这里返回的是page->_mapcount + 1 */
	if (unlikely(page_mapcount(page)))
		bad_reason = "nonzero mapcount";
	/* page->mapping用于当页作为映射页或者匿名页时，指向struct address_space或者struct anon_vma */
	if (unlikely(page->mapping != NULL))
		bad_reason = "non-NULL mapping";
	/* 页框的引用计数，如果为-1，则此页框空闲，并可分配给任一进程或内核；如果大于或等于0，则说明页框被分配给了一个或多个进程，或用于存放内核数据。page_count()返回_count加1的值，也就是该页的使用者数目 */
	if (unlikely(atomic_read(&page->_count) != 0))
		bad_reason = "nonzero _count";
	if (unlikely(page->flags & PAGE_FLAGS_CHECK_AT_PREP)) {
		bad_reason = "PAGE_FLAGS_CHECK_AT_PREP flag set";
		bad_flags = PAGE_FLAGS_CHECK_AT_PREP;
	}
	if (unlikely(mem_cgroup_bad_page_check(page)))
		bad_reason = "cgroup check failed";
	if (unlikely(bad_reason)) {
		bad_page(page, bad_reason, bad_flags);
		return 1;
	}
	return 0;
}

/* 对新的页框进行一些参数的设置和操作 */
static int prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags)
{
	int i;

	/* 遍历每个页，对每个页进行检查 */
	for (i = 0; i < (1 << order); i++) {
		struct page *p = page + i;
		if (unlikely(check_new_page(p)))
			return 1;
	}

	/* 设置page->private = 0 */
	set_page_private(page, 0);
	/* 设置page->_count = 1 */
	set_page_refcounted(page);

	arch_alloc_page(page, order);
	/* 如果是低端内存，需要对其进行处理 */
	kernel_map_pages(page, 1 << order, 1);

	/* 如果需要对页清0，则调用prep_zero_page()对页进行清0 */
	if (gfp_flags & __GFP_ZERO)
		prep_zero_page(page, order, gfp_flags);

	/* 如果分配时要求的是大页，这将这些连续页框组成为一个大页 
	 * 具体做法:
	 * 1.所有页的page->first_page指向第一个页
	 * 2.第一个页置位PG_head
	 * 3.最后一个页置位PG_tail
	 * 4.所有页的page->_count设置为0
	 */
	if (order && (gfp_flags & __GFP_COMP))
		prep_compound_page(page, order);

	return 0;
}

/*
 * Go through the free lists for the given migratetype and remove
 * the smallest available page from the freelists
 */
static inline
struct page *__rmqueue_smallest(struct zone *zone, unsigned int order,
						int migratetype)
{
	unsigned int current_order;
	struct free_area *area;
	struct page *page;

	/* Find a page of the appropriate size in the preferred list */
	/* 循环遍历这层之后的空闲链表 */
	for (current_order = order; current_order < MAX_ORDER; ++current_order) {
		area = &(zone->free_area[current_order]);
		/* 如果当前空闲链表为空，则从更高一级的链表中获取空闲页框 */
		if (list_empty(&area->free_list[migratetype]))
			continue;
		/* 获取空闲链表中第一个结点所代表的连续页框 */
		page = list_entry(area->free_list[migratetype].next,
							struct page, lru);
		/* 将页框从空闲链表中删除 */
		list_del(&page->lru);
		/* 将首页框的private设置为0 */
		rmv_page_order(page);
		area->nr_free--;
		/* 如果从更高级的页框的链表中分配，这里会将多余的页框放回伙伴系统的链表中，比如我们只需要2个页框，但是这里是从8个连续页框的链表分配给我们的，那其他6个就要拆分为2和4个分别放入链表中 */
		expand(zone, page, order, current_order, area, migratetype);
		/* 设置页框的类型 */
		set_freepage_migratetype(page, migratetype);
		return page;
	}

	return NULL;
}


/*
 * This array describes the order lists are fallen back to when
 * the free lists for the desirable migrate type are depleted
 */
static int fallbacks[MIGRATE_TYPES][4] = {
	[MIGRATE_UNMOVABLE]   = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE,     MIGRATE_RESERVE },
	[MIGRATE_RECLAIMABLE] = { MIGRATE_UNMOVABLE,   MIGRATE_MOVABLE,     MIGRATE_RESERVE },
#ifdef CONFIG_CMA
	[MIGRATE_MOVABLE]     = { MIGRATE_CMA,         MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE, MIGRATE_RESERVE },
	[MIGRATE_CMA]         = { MIGRATE_RESERVE }, /* Never used */
#else
	[MIGRATE_MOVABLE]     = { MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE,   MIGRATE_RESERVE },
#endif
	[MIGRATE_RESERVE]     = { MIGRATE_RESERVE }, /* Never used */
#ifdef CONFIG_MEMORY_ISOLATION
	[MIGRATE_ISOLATE]     = { MIGRATE_RESERVE }, /* Never used */
#endif
};

/*
 * Move the free pages in a range to the free lists of the requested type.
 * Note that start_page and end_pages are not aligned on a pageblock
 * boundary. If alignment is required, use move_freepages_block()
 */
/* 将此段页框中的空闲页框移动到新的migratetype类型的伙伴系统链表中 */
int move_freepages(struct zone *zone,
			  struct page *start_page, struct page *end_page,
			  int migratetype)
{
	struct page *page;
	unsigned long order;
	int pages_moved = 0;

#ifndef CONFIG_HOLES_IN_ZONE
	/*
	 * page_zone is not safe to call in this context when
	 * CONFIG_HOLES_IN_ZONE is set. This bug check is probably redundant
	 * anyway as we check zone boundaries in move_freepages_block().
	 * Remove at a later date when no bug reports exist related to
	 * grouping pages by mobility
	 */
	VM_BUG_ON(page_zone(start_page) != page_zone(end_page));
#endif
	/* 遍历这组页框 */
	for (page = start_page; page <= end_page;) {
		/* Make sure we are not inadvertently changing nodes */
		VM_BUG_ON_PAGE(page_to_nid(page) != zone_to_nid(zone), page);

		/* 检查页框和页框号是否属于内存，如果不正确则跳过 */
		if (!pfn_valid_within(page_to_pfn(page))) {
			page++;
			continue;
		}

		/* 如果页框不在伙伴系统中则跳到下一页，通过判断page->_mapcount是否等于-128 */
		if (!PageBuddy(page)) {
			page++;
			continue;
		}

		/* 获取此页框的order号，保存在page->private中 */
		order = page_order(page);
		/* 从伙伴系统中拿出来，并放到新的migratetype类型中的order链表中 */
		list_move(&page->lru,
			  &zone->free_area[order].free_list[migratetype]);
		/* 将这段空闲页框的首页设置为新的类型page->index = migratetype */
		set_freepage_migratetype(page, migratetype);
		/* 跳过此order个页框数量 */
		page += 1 << order;
		/* 记录拿出来了多少个页框 */
		pages_moved += 1 << order;
	}
	/* 返回一共拿出来的页框 */
	return pages_moved;
}

/* 将page所在的pageblock中所有空闲页框移动到新的类型链表中
 * 比如一段连续页框块，order为8，那么就会移动zone->free_area[8].free_list[新的类型]这个空闲页框块中
 */
int move_freepages_block(struct zone *zone, struct page *page,
				int migratetype)
{
	unsigned long start_pfn, end_pfn;
	struct page *start_page, *end_page;

	/* 根据page
	 * 将start_pfn设置为page所在pageblock的起始页框
	 * 将end_pfn设置为page所在pageblock的结束页框
	 * start_page指向start_pfn对应的页描述符
	 * end_page指向end_page对应的页描述符
	 */
	start_pfn = page_to_pfn(page);
	start_pfn = start_pfn & ~(pageblock_nr_pages-1);
	start_page = pfn_to_page(start_pfn);
	end_page = start_page + pageblock_nr_pages - 1;
	end_pfn = start_pfn + pageblock_nr_pages - 1;

	/* Do not cross zone boundaries */
	/* 检查开始页框是否属于zone中，如果不属于，则用page作为开始页框 
	 * 因为有可能pageblock中一半在上一个zone中，一半在本zone中
	 */
	if (!zone_spans_pfn(zone, start_pfn))
		start_page = page;
	/* 同上如果结束页框不属于zone，不过这里直接返回0 */
	if (!zone_spans_pfn(zone, end_pfn))
		return 0;

	/* 将此pageblock中的空闲页框全部移动到新的migratetype类型的伙伴系统链表中 */
	return move_freepages(zone, start_page, end_page, migratetype);
}

static void change_pageblock_range(struct page *pageblock_page,
					int start_order, int migratetype)
{
	int nr_pageblocks = 1 << (start_order - pageblock_order);

	while (nr_pageblocks--) {
		set_pageblock_migratetype(pageblock_page, migratetype);
		pageblock_page += pageblock_nr_pages;
	}
}

/*
 * If breaking a large block of pages, move all free pages to the preferred
 * allocation list. If falling back for a reclaimable kernel allocation, be
 * more aggressive about taking ownership of free pages.
 *
 * On the other hand, never change migration type of MIGRATE_CMA pageblocks
 * nor move CMA pages to different free lists. We don't want unmovable pages
 * to be allocated from MIGRATE_CMA areas.
 *
 * Returns the new migratetype of the pageblock (or the same old migratetype
 * if it was unchanged).
 */
/* 在当前start_migratetype中没有足够的页进行分配时，则会将获取到的migratetype类型的pageblock中的所有空闲页框移动到start_migratetype中，返回获取的页框本来所属的类型  
 * 在调用前，page一定是migratetype类型的
 * 里面的具体做法是:
 * page是属于migratetype类型的pageblock中的一个页，然后函数中会根据page获取其所在的pageblock
 * 从pageblock开始的第一页遍历到此pageblock的最后一页
 * 然后根据page->_mapcount是否等于-1，如果等于-1，说明此页在伙伴系统中，不等于-1则下一页
 * 对page->_mapcount == -1的页获取order值，order值保存在page->private中，然后将这一段连续空闲页框移动到start_type类型的free_list中
 * 对这段连续空闲页框首页设置为start_type类型，这样就能表示此段连续空闲页框都是此类型了，通过page->index = start_type设置
 * 继续遍历，直到整个pageblock遍历结束，这样整个pageblock中的空闲页框都被移动到start_type类型中了
 */
static int try_to_steal_freepages(struct zone *zone, struct page *page,
				  int start_type, int fallback_type)
{
	/* page是当前遍历到的migratetype当中order页的首页描述符，并不是我们需要的migratetype中的页
	 * order是当前遍历到的migratetype当中order，并不是当前需要分配的order
	 */
	int current_order = page_order(page);

	/*
	 * When borrowing from MIGRATE_CMA, we need to release the excess
	 * buddy pages to CMA itself. We also ensure the freepage_migratetype
	 * is set to CMA so it is returned to the correct freelist in case
	 * the page ends up being not actually allocated from the pcp lists.
	 */
	/* 如果是CMA类型则不做处理 */
	if (is_migrate_cma(fallback_type))
		return fallback_type;

	/* Take ownership for orders >= pageblock_order */
	/* 如果当前需要的order值大于默认一个内存块的order值(这个值为MAX_ORDER-1或者大页的大小)，就算出需要多少块pageblock才能达到order，然后把这些pageblock都设置为start_type 
	 * 这种情况发生在pageblock_order等于大页的大小，而内核配置了CONFIG_FORCE_ORDER，导致order >= pageblock_order
	 */
	if (current_order >= pageblock_order) {
		/* 计算出需要的pageblock的块数，然后将每一块都设置为需要的类型，这种情况下并没有把它们从旧类型的伙伴系统移到需要类型的伙伴系统中，在外面函数会将其移出来 */
		change_pageblock_range(page, current_order, start_type);
		return start_type;
	}

	/* 如果order大于pageblock_order的一半，或者类型是MIGRATE_RECLAIMABLE，或者内核关闭了页可迁移的特性，则从此页所属的mirgatetype和order链表中获取页框放到start_type中 
	 * 如果oder小于pageblock_order / 2并且start_type != MIGRATE_RECLAIMABLE并且page_group_by_mobility_disabled == false，就不会移动页框。
	 */
	if (current_order >= pageblock_order / 2 ||
	    start_type == MIGRATE_RECLAIMABLE ||
	    page_group_by_mobility_disabled) {
		int pages;

		/* 这个page所在的pageblock必定属于fallback_type类型
		 * 将这个page所在的pageblock中所有空闲页框移动到start_type类型的free_list链表中，order不变，返回移动的页数量，但是已经在使用的页会被跳过，并且这些已经被使用的页不会被更改为新的类型
		 * 具体做法:
		 * 从pageblock开始的第一页遍历到此pageblock的最后一页
		 * 然后根据page->_mapcount是否等于-1，如果等于-1，说明此页在伙伴系统中，不等于-1则下一页
		 * 对page->_mapcount == -1的页获取order值，order值保存在page->private中，然后将这一段连续空闲页框移动到start_type类型的free_list中
		 * 对这段连续空闲页框首页设置为start_type类型，这样就能表示此段连续空闲页框都是此类型了，通过page->index = start_type设置
		 * 继续遍历，直到整个pageblock遍历结束，这样整个pageblock中的空闲页框都被移动到start_type类型中了
		 */
		pages = move_freepages_block(zone, page, start_type);

		/* Claim the whole block if over half of it is free */
		/* 如果这块pageblock中的页数量大于pageblock的页数量的一半，则设置这块pageblock为新的migratetype类型，如果小于，则不会把此pageblock设置为新的类型
		 * 如果不将pageblock设置为新的类型，会导致一种情况: 空闲页的migratetype类型与pageblock的migratetype类型不一致
		 * 对于这种情况，在这些正在使用的块被释放时，会被检查是否与所属pageblock的类型一致，不一致则会设置为一致
		 * 一个zone的每个pageblock的状态占4位，保存在zone->pageblock_flags指向的一个位图中
		 */
		if (pages >= (1 << (pageblock_order-1)) ||
				page_group_by_mobility_disabled) {
			set_pageblock_migratetype(page, start_type);
			return start_type;
		}
	}
	/* 返回是从哪个migratetype中移动的页框 */
	return fallback_type;
}

/* Remove an element from the buddy allocator from the fallback list */
/* 根据fallbacks数组中定义的优先级，从其他migratetype类型的链表中获取连续页框，返回第一个页框的页描述符 
 * start_migratetype是申请页框时需要但是又缺少的类型
 */
static inline struct page *
__rmqueue_fallback(struct zone *zone, unsigned int order, int start_migratetype)
{
	struct free_area *area;
	unsigned int current_order;
	struct page *page;
	int migratetype, new_type, i;

	/* Find the largest possible block of pages in the other list */
	/* 遍历不同order的链表，如果需要分配2个连续页框，则会遍历1024,512,256,128,64,32,16,8,4,2,1这几个链表，注意这里是倒着遍历的 */
	for (current_order = MAX_ORDER-1;
				current_order >= order && current_order <= MAX_ORDER-1;
				--current_order) { 	
		for (i = 0;; i++) {  	/* 遍历order链表中对应fallbacks优先级的类型链表 */

			/* 根据fallbacks和i获取migratetype,start_migratetype是申请页框时需要的类型 */
			/*static int fallbacks[MIGRATE_TYPES][4] = {
			 *	[MIGRATE_UNMOVABLE]   = { MIGRATE_RECLAIMABLE, MIGRATE_MOVABLE,     MIGRATE_RESERVE },
			 *	[MIGRATE_RECLAIMABLE] = { MIGRATE_UNMOVABLE,   MIGRATE_MOVABLE,     MIGRATE_RESERVE },
			 *#ifdef CONFIG_CMA
			 *	[MIGRATE_MOVABLE]     = { MIGRATE_CMA,         MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE, MIGRATE_RESERVE },
			 *	[MIGRATE_CMA]         = { MIGRATE_RESERVE }, 
			 *#else
			 *	[MIGRATE_MOVABLE]     = { MIGRATE_RECLAIMABLE, MIGRATE_UNMOVABLE,   MIGRATE_RESERVE },
			 *#endif
			 *	[MIGRATE_RESERVE]     = { MIGRATE_RESERVE }, 
			 *#ifdef CONFIG_MEMORY_ISOLATION
			 *	[MIGRATE_ISOLATE]     = { MIGRATE_RESERVE }, 
			 *#endif
			 *};
			 */
			migratetype = fallbacks[start_migratetype][i];

			/* MIGRATE_RESERVE handled later if necessary */
			/* 这里不能分配MIGRATE_RESERVE类型的内存，这部分内存是保留使用，最后其他的migratetype都没有内存可分配才会分配MIGRATE_RESERVE类型的内存 */
			if (migratetype == MIGRATE_RESERVE)
				break;

			/* 当前order的链表，current_order从10 ~ order */
			area = &(zone->free_area[current_order]);
			/* 链表为空，说明这个链表页没有内存 */
			if (list_empty(&area->free_list[migratetype]))
				continue;

			/* 有空余的内存，即将分配 */
			/* 从链表中获取第一个节点，但是注意，这里分配的内存可能大于我们需要的数量(从其他order链表中获取的连续页框)，之后会调用expand把多余的放回去 */
			page = list_entry(area->free_list[migratetype].next,
					struct page, lru);
			area->nr_free--;

			/* 在当前start_migratetype中没有足够的页进行分配时，则会将获取到的migratetype类型的pageblock中的所有空闲页框移动到start_migratetype中，返回获取的页框本来所属的类型  
			 * 只有系统禁止了page_group_by_mobility_disabled或者order > pageblock_order / 2，才会这样做
			 * 在调用前，page一定是migratetype类型的
			 * 里面的具体做法是:
			 * page是属于migratetype类型的pageblock中的一个页，然后函数中会根据page获取其所在的pageblock
			 * 从pageblock开始的第一页遍历到此pageblock的最后一页
			 * 然后根据page->_mapcount是否等于-1，如果等于-1，说明此页在伙伴系统中，不等于-1则下一页
			 * 对page->_mapcount == -1的页获取order值，order值保存在page->private中，然后将这一段连续空闲页框移动到start_type类型的free_list中
			 * 对这段连续空闲页框首页设置为start_type类型，这样就能表示此段连续空闲页框都是此类型了，通过page->index = start_type设置
			 * 继续遍历，直到整个pageblock遍历结束，这样整个pageblock中的空闲页框都被移动到start_type类型中了
			 */
			new_type = try_to_steal_freepages(zone, page,
							  start_migratetype,
							  migratetype);

			/* 从伙伴系统中拿出来，因为在try_to_steal_freepages已经将新的页框放到了需要的start_mirgatetype的链表中
			 * 并且此order并不一定是所需要order的上级，因为order是倒着遍历了，比如我们需要32个MIGRATE_UNMOVABLE页框，但是移动的是1024个MIGRATE_MOVABLE页框到MIGRATE_UNMOVABLE的order=10的链表中。
			 */
			list_del(&page->lru);
			/* 设置page->_mapcount = -1 并且 page->private = 0 */
			rmv_page_order(page);

			/* 如果有多余的页框，则把多余的页框放回伙伴系统中 */
			expand(zone, page, order, current_order, area,
			       new_type);
			/* The freepage_migratetype may differ from pageblock's
			 * migratetype depending on the decisions in
			 * try_to_steal_freepages. This is OK as long as it does
			 * not differ for MIGRATE_CMA type.
			 */
			/* 设置获取的页框的类型为新的类型，因为在try_to_steal_freepages()中cma类型是直接返回的，而其他类型都会在里面被设置，page->index = new_type
			 * 到这里，page已经是一个2^oder连续页框的内存段，之后就把它返回到申请者就好
			 */
			set_freepage_migratetype(page, new_type);

			trace_mm_page_alloc_extfrag(page, order, current_order,
				start_migratetype, migratetype, new_type);

			return page;
		}
	}

	return NULL;
}

/*
 * Do the hard work of removing an element from the buddy allocator.
 * Call me with the zone->lock already held.
 */
/* 从伙伴系统中获取2的order次方个页框，返回第一个页框的描述符
 * zone: 管理区描述符
 * order: 需要页面的2的次方数
 * migratetype: 从此类型中获取，这时传入的时需求的页框类型
 */
static struct page *__rmqueue(struct zone *zone, unsigned int order,
						int migratetype)
{
	struct page *page;

retry_reserve:
	/* 直接从migratetype类型的链表中获取了2的order次方个页框 */
	page = __rmqueue_smallest(zone, order, migratetype);

	/* 如果page为空，没有在需要的migratetype类型中分配获得页框，说明当前需求类型(migratetype)的页框没有空闲，会根据fallback数组中定义好的优先级从其他类型的页框中获取页框，一次移动一个pageblock */
	if (unlikely(!page) && migratetype != MIGRATE_RESERVE) {
		/* 根据fallbacks数组从其他migratetype类型的链表中获取内存 */
		page = __rmqueue_fallback(zone, order, migratetype);

		/*
		 * Use MIGRATE_RESERVE rather than fail an allocation. goto
		 * is used because __rmqueue_smallest is an inline function
		 * and we want just one call site
		 */
		 /* 从其他类型的空闲页框链表中也没有获得页框，设定为默认类型的页框，重试一次 */
		if (!page) {
			/* 定义从页框属性为MIGRATE_RESERVE的空闲链表中查找 */
			migratetype = MIGRATE_RESERVE;
			/* 重试尝试从MIGRATE_RESERVE类型的链表中找出空闲内存 */
			goto retry_reserve;
		}
	}

	trace_mm_page_alloc_zone_locked(page, order, migratetype);
	return page;
}

/*
 * Obtain a specified number of elements from the buddy allocator, all under
 * a single hold of the lock, for efficiency.  Add them to the supplied list.
 * Returns the number of new pages which were placed at *list.
 */
static int rmqueue_bulk(struct zone *zone, unsigned int order,
			unsigned long count, struct list_head *list,
			int migratetype, bool cold)
{
	int i;

	/* 上锁 */
	spin_lock(&zone->lock);
	for (i = 0; i < count; ++i) {
		struct page *page = __rmqueue(zone, order, migratetype);
		if (unlikely(page == NULL))
			break;

		/*
		 * Split buddy pages returned by expand() are received here
		 * in physical page order. The page is added to the callers and
		 * list and the list head then moves forward. From the callers
		 * perspective, the linked list is ordered by page number in
		 * some conditions. This is useful for IO devices that can
		 * merge IO requests if the physical pages are ordered
		 * properly.
		 */
		if (likely(!cold))
			list_add(&page->lru, list);
		else
			list_add_tail(&page->lru, list);
		list = &page->lru;
		if (is_migrate_cma(get_freepage_migratetype(page)))
			__mod_zone_page_state(zone, NR_FREE_CMA_PAGES,
					      -(1 << order));
	}
	__mod_zone_page_state(zone, NR_FREE_PAGES, -(i << order));
	spin_unlock(&zone->lock);
	return i;
}

#ifdef CONFIG_NUMA
/*
 * Called from the vmstat counter updater to drain pagesets of this
 * currently executing processor on remote nodes after they have
 * expired.
 *
 * Note that this function must be called with the thread pinned to
 * a single processor.
 */
void drain_zone_pages(struct zone *zone, struct per_cpu_pages *pcp)
{
	unsigned long flags;
	int to_drain, batch;

	local_irq_save(flags);
	batch = ACCESS_ONCE(pcp->batch);
	to_drain = min(pcp->count, batch);
	if (to_drain > 0) {
		free_pcppages_bulk(zone, to_drain, pcp);
		pcp->count -= to_drain;
	}
	local_irq_restore(flags);
}
#endif

/*
 * Drain pages of the indicated processor.
 *
 * The processor must either be the current processor and the
 * thread pinned to the current processor or a processor that
 * is not online.
 */
static void drain_pages(unsigned int cpu)
{
	unsigned long flags;
	struct zone *zone;

	for_each_populated_zone(zone) {
		struct per_cpu_pageset *pset;
		struct per_cpu_pages *pcp;

		local_irq_save(flags);
		pset = per_cpu_ptr(zone->pageset, cpu);

		pcp = &pset->pcp;
		if (pcp->count) {
			free_pcppages_bulk(zone, pcp->count, pcp);
			pcp->count = 0;
		}
		local_irq_restore(flags);
	}
}

/*
 * Spill all of this CPU's per-cpu pages back into the buddy allocator.
 */
void drain_local_pages(void *arg)
{
	drain_pages(smp_processor_id());
}

/*
 * Spill all the per-cpu pages from all CPUs back into the buddy allocator.
 *
 * Note that this code is protected against sending an IPI to an offline
 * CPU but does not guarantee sending an IPI to newly hotplugged CPUs:
 * on_each_cpu_mask() blocks hotplug and won't talk to offlined CPUs but
 * nothing keeps CPUs from showing up after we populated the cpumask and
 * before the call to on_each_cpu_mask().
 */
void drain_all_pages(void)
{
	int cpu;
	struct per_cpu_pageset *pcp;
	struct zone *zone;

	/*
	 * Allocate in the BSS so we wont require allocation in
	 * direct reclaim path for CONFIG_CPUMASK_OFFSTACK=y
	 */
	static cpumask_t cpus_with_pcps;

	/*
	 * We don't care about racing with CPU hotplug event
	 * as offline notification will cause the notified
	 * cpu to drain that CPU pcps and on_each_cpu_mask
	 * disables preemption as part of its processing
	 */
	for_each_online_cpu(cpu) {
		bool has_pcps = false;
		for_each_populated_zone(zone) {
			pcp = per_cpu_ptr(zone->pageset, cpu);
			if (pcp->pcp.count) {
				has_pcps = true;
				break;
			}
		}
		if (has_pcps)
			cpumask_set_cpu(cpu, &cpus_with_pcps);
		else
			cpumask_clear_cpu(cpu, &cpus_with_pcps);
	}
	on_each_cpu_mask(&cpus_with_pcps, drain_local_pages, NULL, 1);
}

#ifdef CONFIG_HIBERNATION

void mark_free_pages(struct zone *zone)
{
	unsigned long pfn, max_zone_pfn;
	unsigned long flags;
	unsigned int order, t;
	struct list_head *curr;

	if (zone_is_empty(zone))
		return;

	spin_lock_irqsave(&zone->lock, flags);

	max_zone_pfn = zone_end_pfn(zone);
	for (pfn = zone->zone_start_pfn; pfn < max_zone_pfn; pfn++)
		if (pfn_valid(pfn)) {
			struct page *page = pfn_to_page(pfn);

			if (!swsusp_page_is_forbidden(page))
				swsusp_unset_page_free(page);
		}

	for_each_migratetype_order(order, t) {
		list_for_each(curr, &zone->free_area[order].free_list[t]) {
			unsigned long i;

			pfn = page_to_pfn(list_entry(curr, struct page, lru));
			for (i = 0; i < (1UL << order); i++)
				swsusp_set_page_free(pfn_to_page(pfn + i));
		}
	}
	spin_unlock_irqrestore(&zone->lock, flags);
}
#endif /* CONFIG_PM */

/*
 * Free a 0-order page
 * cold == true ? free a cold page : free a hot page
 */
void free_hot_cold_page(struct page *page, bool cold)
{
	/* 页框所处管理区 */
	struct zone *zone = page_zone(page);
	struct per_cpu_pages *pcp;
	unsigned long flags;
	/* 页框号 */
	unsigned long pfn = page_to_pfn(page);
	int migratetype;

	/* 检查 */
	if (!free_pages_prepare(page, 0))
		return;

	/* 获取页框所在pageblock的页框类型 */
	migratetype = get_pfnblock_migratetype(page, pfn);
	/* 设置页框类型为pageblock的页框类型，因为在页框使用过程中，这段pageblock可以移动到了其他类型(比如MIGRATE_MOVABLE -> MIGRATE_UNMOVABLE) */
	set_freepage_migratetype(page, migratetype);
	local_irq_save(flags);
	__count_vm_event(PGFREE);

	/*
	 * We only track unmovable, reclaimable and movable on pcp lists.
	 * Free ISOLATE pages back to the allocator because they are being
	 * offlined but treat RESERVE as movable pages so we can get those
	 * areas back if necessary. Otherwise, we may have to free
	 * excessively into the page allocator
	 */
	if (migratetype >= MIGRATE_PCPTYPES) {
		/* 如果不是高速缓存类型，则放回伙伴系统 */
		if (unlikely(is_migrate_isolate(migratetype))) {
			free_one_page(zone, page, pfn, 0, migratetype);
			goto out;
		}
		migratetype = MIGRATE_MOVABLE;
	}

	/* 放入当前CPU高速缓存中，要以migratetype区分开来 */
	pcp = &this_cpu_ptr(zone->pageset)->pcp;
	if (!cold)
		list_add(&page->lru, &pcp->lists[migratetype]);
	else
		list_add_tail(&page->lru, &pcp->lists[migratetype]);
	pcp->count++;

	/* 当前CPU高速缓存中页框数量高于最大值，将pcp->batch数量的页框放回伙伴系统 */
	if (pcp->count >= pcp->high) {
		unsigned long batch = ACCESS_ONCE(pcp->batch);
		free_pcppages_bulk(zone, batch, pcp);
		pcp->count -= batch;
	}

out:
	local_irq_restore(flags);
}

/*
 * Free a list of 0-order pages
 */
void free_hot_cold_page_list(struct list_head *list, bool cold)
{
	struct page *page, *next;

	list_for_each_entry_safe(page, next, list, lru) {
		trace_mm_page_free_batched(page, cold);
		free_hot_cold_page(page, cold);
	}
}

/*
 * split_page takes a non-compound higher-order page, and splits it into
 * n (1<<order) sub-pages: page[0..n]
 * Each sub-page must be freed individually.
 *
 * Note: this is probably too low level an operation for use in drivers.
 * Please consult with lkml before using this in your driver.
 */
void split_page(struct page *page, unsigned int order)
{
	int i;

	VM_BUG_ON_PAGE(PageCompound(page), page);
	VM_BUG_ON_PAGE(!page_count(page), page);

#ifdef CONFIG_KMEMCHECK
	/*
	 * Split shadow pages too, because free(page[0]) would
	 * otherwise free the whole shadow.
	 */
	if (kmemcheck_page_is_tracked(page))
		split_page(virt_to_page(page[0].shadow), order);
#endif

	for (i = 1; i < (1 << order); i++)
		set_page_refcounted(page + i);
}
EXPORT_SYMBOL_GPL(split_page);

/* 将page开始的2^order个页框数量从伙伴系统中拿出来 */
int __isolate_free_page(struct page *page, unsigned int order)
{
	unsigned long watermark;
	struct zone *zone;
	int mt;

	BUG_ON(!PageBuddy(page));

	/* 获取管理区 */
	zone = page_zone(page);
	/* 获取此页所在的pageblock的类型 */
	mt = get_pageblock_migratetype(page);

	/* 如果此pageblock的类型不是isolate */
	if (!is_migrate_isolate(mt)) {
		/* Obey watermarks as if the page was being allocated */
		/* 当前阀值 = zone的低阀值 + 1^order */
		watermark = low_wmark_pages(zone) + (1 << order);
		/* 检查zone的空闲内存数量，这里我们设置了watermark，zone的最低空闲内存不能少于这个数，少于则直接返回 */
		if (!zone_watermark_ok(zone, 0, watermark, 0, 0))
			return 0;

		__mod_zone_freepage_state(zone, -(1UL << order), mt);
	}

	/* Remove page from free list */
	/* 从伙伴系统中拿出这段连续页框 */
	list_del(&page->lru);
	zone->free_area[order].nr_free--;
	rmv_page_order(page);

	/* Set the pageblock if the isolated page is at least a pageblock */
	/* 如果这段空闲的连续页框大于一个pageblock，则把这个pageblock设置为MIGRATE_MOVABLE 
	 * 这里有个疑问，如果page数量跨过两个pageblock，那两个pageblock都要被设置类型?如果第二个pageblock中只有这段连续页框的最后那一页，也要被设置类型?从调用关系看不太可能会经历两个pageblock
	 */
	if (order >= pageblock_order - 1) {
		/* 这段空闲的连续页框的最后一个页框 */
		struct page *endpage = page + (1 << order) - 1;
		for (; page < endpage; page += pageblock_nr_pages) {
			/* 获取page所在的pageblock的类型 */
			int mt = get_pageblock_migratetype(page);
			/* 不是isolate类型，也不是cma类型， 则设置为MIGRATE_MOVABLE类型 */
			if (!is_migrate_isolate(mt) && !is_migrate_cma(mt))
				set_pageblock_migratetype(page,
							  MIGRATE_MOVABLE);
		}
	}

	return 1UL << order;
}

/*
 * Similar to split_page except the page is already free. As this is only
 * being used for migration, the migratetype of the block also changes.
 * As this is called with interrupts disabled, the caller is responsible
 * for calling arch_alloc_page() and kernel_map_page() after interrupts
 * are enabled.
 *
 * Note: this is probably too low level an operation for use in drivers.
 * Please consult with lkml before using this in your driver.
 */
int split_free_page(struct page *page)
{
	unsigned int order;
	int nr_pages;

	order = page_order(page);
	/* 将page开始的2^order个页框数量从伙伴系统中拿出来，并且可能会设置pageblock的类型 */
	nr_pages = __isolate_free_page(page, order);
	if (!nr_pages)
		return 0;

	/* Split into individual pages */
	set_page_refcounted(page);
	split_page(page, order);
	return nr_pages;
}

/*
 * Really, prep_compound_page() should be called from __rmqueue_bulk().  But
 * we cheat by calling it from here, in the order > 0 path.  Saves a branch
 * or two.
 */
static inline
struct page *buffered_rmqueue(struct zone *preferred_zone,
			struct zone *zone, unsigned int order,
			gfp_t gfp_flags, int migratetype)
{
	unsigned long flags;
	struct page *page;
	bool cold = ((gfp_flags & __GFP_COLD) != 0);

again:
	if (likely(order == 0)) {
		/* 这里是只需要分配一个页框，会从每CPU高速缓存中分配 */
		struct per_cpu_pages *pcp;
		struct list_head *list;

		local_irq_save(flags);
		/* 获取此zone的每CPU高速缓存 */
		pcp = &this_cpu_ptr(zone->pageset)->pcp;
		/* 获取需要的类型的页框的高速缓存链表，高速缓存中也区分migratetype类型的链表，链表中保存的页框对应的页描述符 */
		list = &pcp->lists[migratetype];
		if (list_empty(list)) {
			/* 如果当前migratetype的每CPU高速缓存链表中没有空闲的页框，从伙伴系统中获取batch个页框加入到这个链表中，batch保存在每CPU高速缓存描述符中，在rmqueue_bulk中是每次要1个页框，要batch次，也就是这些页框是离散的 */
			pcp->count += rmqueue_bulk(zone, 0,
					pcp->batch, list,
					migratetype, cold);
			if (unlikely(list_empty(list)))
				goto failed;
		}

		if (cold)
			/* 需要冷的高速缓存，则从每CPU高速缓存的双向链表的后面开始分配 */
			page = list_entry(list->prev, struct page, lru);
		else
			/* 需要热的高速缓存，则从每CPU高速缓存的双向链表的前面开始分配，因为释放时会从链表头插入，所以链表头是热的高速缓存 */
			page = list_entry(list->next, struct page, lru);
		/* 从每CPU高速缓存链表中拿出来 */
		list_del(&page->lru);
		/* 每CPU高速缓存中页框数量-- */
		pcp->count--;
	} else {
		/* 需要多个页框，从伙伴系统中分配，但是申请多个页框时是有可能会发生失败的情况的，而分配时又表明__GFP_NOFAIL不允许发生失败，所以这里给出一个警告 */
		if (unlikely(gfp_flags & __GFP_NOFAIL)) {
			/*
			 * __GFP_NOFAIL is not to be used in new code.
			 *
			 * All __GFP_NOFAIL callers should be fixed so that they
			 * properly detect and handle allocation failures.
			 *
			 * We most definitely don't want callers attempting to
			 * allocate greater than order-1 page units with
			 * __GFP_NOFAIL.
			 */
			WARN_ON_ONCE(order > 1);
		}
		spin_lock_irqsave(&zone->lock, flags);
		/* 从伙伴系统中获取连续页框，返回第一个页的页描述符 */
		page = __rmqueue(zone, order, migratetype);
		spin_unlock(&zone->lock);
		if (!page)
			goto failed;
		/* 统计，减少zone的此页所属pageblock类型的free_pages数量统计，因为里面使用加法，所以这里传进负数 */
		__mod_zone_freepage_state(zone, -(1 << order),
					  get_freepage_migratetype(page));
	}

	/* 如果原本并不是期望从此zone分配内存，但是现在从此zone分配到内存了，那么就对此zone的NR_ALLOC_BATCH计数减掉本次分配的页框 
	 * 这个NR_ALLOC_BATCH表示的是允许这样分配的页框数量，而不是已经进行这样分配的页框数量
	 */
	__mod_zone_page_state(zone, NR_ALLOC_BATCH, -(1 << order));
	/* 如果此zone的NR_ALLOC_BATCH小于0了，则标记ZONE_FAIR_DEPLETED */
	if (atomic_long_read(&zone->vm_stat[NR_ALLOC_BATCH]) <= 0 &&
	    !test_bit(ZONE_FAIR_DEPLETED, &zone->flags))
		set_bit(ZONE_FAIR_DEPLETED, &zone->flags);

	__count_zone_vm_events(PGALLOC, zone, 1 << order);
	/* 主要是numa相关的计数 */
	zone_statistics(preferred_zone, zone, gfp_flags);
	local_irq_restore(flags);

	VM_BUG_ON_PAGE(bad_range(zone, page), page);
	/* 检查所有分配的连续页框是否为空闲页，并对新的页框进行一定的处理 */
	if (prep_new_page(page, order, gfp_flags))
		goto again;
	/* 返回第一个页描述符 */
	return page;

failed:
	/* 分配失败 */
	local_irq_restore(flags);
	return NULL;
}

#ifdef CONFIG_FAIL_PAGE_ALLOC

static struct {
	struct fault_attr attr;

	u32 ignore_gfp_highmem;
	u32 ignore_gfp_wait;
	u32 min_order;
} fail_page_alloc = {
	.attr = FAULT_ATTR_INITIALIZER,
	.ignore_gfp_wait = 1,
	.ignore_gfp_highmem = 1,
	.min_order = 1,
};

static int __init setup_fail_page_alloc(char *str)
{
	return setup_fault_attr(&fail_page_alloc.attr, str);
}
__setup("fail_page_alloc=", setup_fail_page_alloc);

static bool should_fail_alloc_page(gfp_t gfp_mask, unsigned int order)
{
	if (order < fail_page_alloc.min_order)
		return false;
	if (gfp_mask & __GFP_NOFAIL)
		return false;
	if (fail_page_alloc.ignore_gfp_highmem && (gfp_mask & __GFP_HIGHMEM))
		return false;
	if (fail_page_alloc.ignore_gfp_wait && (gfp_mask & __GFP_WAIT))
		return false;

	return should_fail(&fail_page_alloc.attr, 1 << order);
}

#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS

static int __init fail_page_alloc_debugfs(void)
{
	umode_t mode = S_IFREG | S_IRUSR | S_IWUSR;
	struct dentry *dir;

	dir = fault_create_debugfs_attr("fail_page_alloc", NULL,
					&fail_page_alloc.attr);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	if (!debugfs_create_bool("ignore-gfp-wait", mode, dir,
				&fail_page_alloc.ignore_gfp_wait))
		goto fail;
	if (!debugfs_create_bool("ignore-gfp-highmem", mode, dir,
				&fail_page_alloc.ignore_gfp_highmem))
		goto fail;
	if (!debugfs_create_u32("min-order", mode, dir,
				&fail_page_alloc.min_order))
		goto fail;

	return 0;
fail:
	debugfs_remove_recursive(dir);

	return -ENOMEM;
}

late_initcall(fail_page_alloc_debugfs);

#endif /* CONFIG_FAULT_INJECTION_DEBUG_FS */

#else /* CONFIG_FAIL_PAGE_ALLOC */

static inline bool should_fail_alloc_page(gfp_t gfp_mask, unsigned int order)
{
	return false;
}

#endif /* CONFIG_FAIL_PAGE_ALLOC */

/*
 * Return true if free pages are above 'mark'. This takes into account the order
 * of the allocation.
 */
/* 如果 分配后剩余的页框数量 大于 降低后的mask加上此zone保留的内存数量，则返回真，否则返回假
 * z: 目标zone
 * order: 需要分配的页框数量的order值
 * mark: zone对应的阀值的值(min或者low或者high)
 * classzone_idx: 管理区的类型的偏移量，0是 ZONE_DMA , 1是 ZONE_NORMAL , 2是 ZONE_HIGHMEM , 3是 ZONE_MOVABLE
 * alloc_flags: 分配标志
 * free_pages: zone的空闲页框数量
 */
static bool __zone_watermark_ok(struct zone *z, unsigned int order,
			unsigned long mark, int classzone_idx, int alloc_flags,
			long free_pages)
{
	/* free_pages my go negative - that's OK */
	/* zone的某个阀值，这里算是目标阀值 */
	long min = mark;
	int o;
	long free_cma = 0;

	/* zone空闲页框数量 - 需要分配的页框数量 - 1 后剩余的空闲页框数量 */
	free_pages -= (1 << order) - 1;
	/* 如果有ALLOC_HIGH，那么目标阀值就等于原来阀值的一半 */
	if (alloc_flags & ALLOC_HIGH)
		min -= min / 2;
	/* 如果有ALLOC_HARDER，那么目标阀值就等于原来阀值的1/4 
	 * 这里要注意，如果是GFP_ATOMIC标志，那么会有(ALLOC_HIGH | ALLOC_HARDER)
	 * 也就是GFP_ATOMIC标志，会让目标阀值降为原来阀值的1/8
	 */
	if (alloc_flags & ALLOC_HARDER)
		min -= min / 4;
#ifdef CONFIG_CMA
	/* If allocation can't use CMA areas don't use free CMA pages */
	/* 如果没有ALLOC_CMA标志，则获取此zone空闲的cma数量 */
	if (!(alloc_flags & ALLOC_CMA))
		free_cma = zone_page_state(z, NR_FREE_CMA_PAGES);
#endif

	/* free_pages - free_cma是如果现在把1^order的页框数量分配后，剩余的空闲页框(如果不使用cma，还要把空闲cma数量减掉) 
	 * 分配后剩余的页框数量 小于等于 降低后的阀值加上此zone保留的内存数量
	 * 那么就返回false
	 * 如果 分配后剩余的页框数量 大于 降低后的阀值加上此zone保留的内存数量
	 * 就继续往下
	 */
	if (free_pages - free_cma <= min + z->lowmem_reserve[classzone_idx])
		return false;
	for (o = 0; o < order; o++) {
		/* At the next order, this order's pages become unavailable */
		free_pages -= z->free_area[o].nr_free << o;

		/* Require fewer higher order pages to be free */
		min >>= 1;

		if (free_pages <= min)
			return false;
	}
	return true;
}

/* 分配后剩余的页框数量是否大于阀值加上此zone保留的内存数量 
 * 大于算通过，小于等于算失败
 * 如果有ALLOC_HIGH和ALLOC_HARDER，那么可能会对阀值降低
 */
bool zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
		      int classzone_idx, int alloc_flags)
{
	return __zone_watermark_ok(z, order, mark, classzone_idx, alloc_flags,
					zone_page_state(z, NR_FREE_PAGES));
}

bool zone_watermark_ok_safe(struct zone *z, unsigned int order,
			unsigned long mark, int classzone_idx, int alloc_flags)
{
	long free_pages = zone_page_state(z, NR_FREE_PAGES);

	if (z->percpu_drift_mark && free_pages < z->percpu_drift_mark)
		free_pages = zone_page_state_snapshot(z, NR_FREE_PAGES);

	return __zone_watermark_ok(z, order, mark, classzone_idx, alloc_flags,
								free_pages);
}

#ifdef CONFIG_NUMA
/*
 * zlc_setup - Setup for "zonelist cache".  Uses cached zone data to
 * skip over zones that are not allowed by the cpuset, or that have
 * been recently (in last second) found to be nearly full.  See further
 * comments in mmzone.h.  Reduces cache footprint of zonelist scans
 * that have to skip over a lot of full or unallowed zones.
 *
 * If the zonelist cache is present in the passed zonelist, then
 * returns a pointer to the allowed node mask (either the current
 * tasks mems_allowed, or node_states[N_MEMORY].)
 *
 * If the zonelist cache is not available for this zonelist, does
 * nothing and returns NULL.
 *
 * If the fullzones BITMAP in the zonelist cache is stale (more than
 * a second since last zap'd) then we zap it out (clear its bits.)
 *
 * We hold off even calling zlc_setup, until after we've checked the
 * first zone in the zonelist, on the theory that most allocations will
 * be satisfied from that first zone, so best to examine that zone as
 * quickly as we can.
 */
static nodemask_t *zlc_setup(struct zonelist *zonelist, int alloc_flags)
{
	struct zonelist_cache *zlc;	/* cached zonelist speedup info */
	nodemask_t *allowednodes;	/* zonelist_cache approximation */

	zlc = zonelist->zlcache_ptr;
	if (!zlc)
		return NULL;

	if (time_after(jiffies, zlc->last_full_zap + HZ)) {
		bitmap_zero(zlc->fullzones, MAX_ZONES_PER_ZONELIST);
		zlc->last_full_zap = jiffies;
	}

	allowednodes = !in_interrupt() && (alloc_flags & ALLOC_CPUSET) ?
					&cpuset_current_mems_allowed :
					&node_states[N_MEMORY];
	return allowednodes;
}

/*
 * Given 'z' scanning a zonelist, run a couple of quick checks to see
 * if it is worth looking at further for free memory:
 *  1) Check that the zone isn't thought to be full (doesn't have its
 *     bit set in the zonelist_cache fullzones BITMAP).
 *  2) Check that the zones node (obtained from the zonelist_cache
 *     z_to_n[] mapping) is allowed in the passed in allowednodes mask.
 * Return true (non-zero) if zone is worth looking at further, or
 * else return false (zero) if it is not.
 *
 * This check -ignores- the distinction between various watermarks,
 * such as GFP_HIGH, GFP_ATOMIC, PF_MEMALLOC, ...  If a zone is
 * found to be full for any variation of these watermarks, it will
 * be considered full for up to one second by all requests, unless
 * we are so low on memory on all allowed nodes that we are forced
 * into the second scan of the zonelist.
 *
 * In the second scan we ignore this zonelist cache and exactly
 * apply the watermarks to all zones, even it is slower to do so.
 * We are low on memory in the second scan, and should leave no stone
 * unturned looking for a free page.
 */
static int zlc_zone_worth_trying(struct zonelist *zonelist, struct zoneref *z,
						nodemask_t *allowednodes)
{
	struct zonelist_cache *zlc;	/* cached zonelist speedup info */
	int i;				/* index of *z in zonelist zones */
	int n;				/* node that zone *z is on */

	zlc = zonelist->zlcache_ptr;
	if (!zlc)
		return 1;

	i = z - zonelist->_zonerefs;
	n = zlc->z_to_n[i];

	/* This zone is worth trying if it is allowed but not full */
	return node_isset(n, *allowednodes) && !test_bit(i, zlc->fullzones);
}

/*
 * Given 'z' scanning a zonelist, set the corresponding bit in
 * zlc->fullzones, so that subsequent attempts to allocate a page
 * from that zone don't waste time re-examining it.
 */
static void zlc_mark_zone_full(struct zonelist *zonelist, struct zoneref *z)
{
	struct zonelist_cache *zlc;	/* cached zonelist speedup info */
	int i;				/* index of *z in zonelist zones */

	zlc = zonelist->zlcache_ptr;
	if (!zlc)
		return;

	i = z - zonelist->_zonerefs;

	set_bit(i, zlc->fullzones);
}

/*
 * clear all zones full, called after direct reclaim makes progress so that
 * a zone that was recently full is not skipped over for up to a second
 */
static void zlc_clear_zones_full(struct zonelist *zonelist)
{
	struct zonelist_cache *zlc;	/* cached zonelist speedup info */

	zlc = zonelist->zlcache_ptr;
	if (!zlc)
		return;

	bitmap_zero(zlc->fullzones, MAX_ZONES_PER_ZONELIST);
}

/* local_zone和zone是否属于同一个node */
static bool zone_local(struct zone *local_zone, struct zone *zone)
{
	return local_zone->node == zone->node;
}

static bool zone_allows_reclaim(struct zone *local_zone, struct zone *zone)
{
	return node_distance(zone_to_nid(local_zone), zone_to_nid(zone)) <
				RECLAIM_DISTANCE;
}

#else	/* CONFIG_NUMA */

static nodemask_t *zlc_setup(struct zonelist *zonelist, int alloc_flags)
{
	return NULL;
}

static int zlc_zone_worth_trying(struct zonelist *zonelist, struct zoneref *z,
				nodemask_t *allowednodes)
{
	return 1;
}

static void zlc_mark_zone_full(struct zonelist *zonelist, struct zoneref *z)
{
}

static void zlc_clear_zones_full(struct zonelist *zonelist)
{
}

static bool zone_local(struct zone *local_zone, struct zone *zone)
{
	return true;
}

static bool zone_allows_reclaim(struct zone *local_zone, struct zone *zone)
{
	return true;
}

#endif	/* CONFIG_NUMA */

/* 重新设置除目标zone之外，node中在此zone前面的zone的batch页数量大小 */
static void reset_alloc_batches(struct zone *preferred_zone)
{
	/* 指向node的第一个zone */
	struct zone *zone = preferred_zone->zone_pgdat->node_zones;

	
	do {
		/* batch页数量 = high阀值 - 低阀值 - 当前batch数量 */
		mod_zone_page_state(zone, NR_ALLOC_BATCH,
			high_wmark_pages(zone) - low_wmark_pages(zone) -
			atomic_long_read(&zone->vm_stat[NR_ALLOC_BATCH]));
		clear_bit(ZONE_FAIR_DEPLETED, &zone->flags);
	} while (zone++ != preferred_zone);
}

/*
 * get_page_from_freelist goes through the zonelist trying to allocate
 * a page.
 */
/* 从管理区链表中遍历所有管理区，获取指定连续的页框数 
 * 在遍历管理区时，如果此zone当前空闲内存减去需要申请的内存之后，空闲内存是低于low阀值，那么此zone会进行快速内存回收
 * 第一轮循环会尝试只从preferred_zone这个zone中获取连续页框，如果无法获取，会进入第二轮循环
 * 第二轮循环会遍历整个zonelist中的zone，从里面获取连续页框
 */
static struct page *
get_page_from_freelist(gfp_t gfp_mask, nodemask_t *nodemask, unsigned int order,
		struct zonelist *zonelist, int high_zoneidx, int alloc_flags,
		struct zone *preferred_zone, int classzone_idx, int migratetype)
{
	struct zoneref *z;
	struct page *page = NULL;
	struct zone *zone;
	nodemask_t *allowednodes = NULL;/* zonelist_cache approximation */
	int zlc_active = 0;		/* set if using zonelist_cache */
	int did_zlc_setup = 0;		/* just call zlc_setup() one time */
	/* 是否考虑脏页过多的判断值，如果脏页过多，则不在此zone进行分配 */
	bool consider_zone_dirty = (alloc_flags & ALLOC_WMARK_LOW) &&
				(gfp_mask & __GFP_WRITE);
	int nr_fair_skipped = 0;
	bool zonelist_rescan;

zonelist_scan:
	zonelist_rescan = false;

	/*
	 * Scan zonelist, looking for a zone with enough free.
	 * See also __cpuset_node_allowed_softwall() comment in kernel/cpuset.c.
	 */
	/* 遍历结点中的管理区，如果要求从高端内存分配，则顺序为ZONE_HighMen -> ZONE_NORMAL -> ZONE_DMA
	 * 如果没要求从高端内存分配，则顺序为ZONE_NORMAL -> ZONE_DMA
	 */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
						high_zoneidx, nodemask) {
		unsigned long mark;

		if (IS_ENABLED(CONFIG_NUMA) && zlc_active &&
			!zlc_zone_worth_trying(zonelist, z, allowednodes))
				continue;

		/* 检查此管理区是否属于该CPU所允许分配的管理区 */
		if (cpusets_enabled() &&
			(alloc_flags & ALLOC_CPUSET) &&
			!cpuset_zone_allowed_softwall(zone, gfp_mask))
				continue;
		/*
		 * Distribute pages in proportion to the individual
		 * zone size to ensure fair page aging.  The zone a
		 * page was allocated in should have no effect on the
		 * time the page has in memory before being reclaimed.
		 */
		/* 公平分配，标记了ALLOC_FAIR的情况，会只从preferred_zone这个zone所在node
		 * 所以第一轮循环，会只尝试从preferred_zone所在node进行分配
		 * 而第二轮循环，会遍历整个zonelist里的包含的其他node的zone
		 */
		if (alloc_flags & ALLOC_FAIR) {
			/* 判断zone和preferred_zone是否属于同一个node，不属于则跳出循环，因为后面的页不会属于此node了 */
			if (!zone_local(preferred_zone, zone))
				break;
			/* 此zone属于此node，看看ZONE_FAIR_DEPLETED标记有没有置位，置位了说明此zone可用于其他zone的页框数量已经用尽 */
			if (test_bit(ZONE_FAIR_DEPLETED, &zone->flags)) {
				nr_fair_skipped++;
				continue;
			}
		}
		/*
		 * When allocating a page cache page for writing, we
		 * want to get it from a zone that is within its dirty
		 * limit, such that no single zone holds more than its
		 * proportional share of globally allowed dirty pages.
		 * The dirty limits take into account the zone's
		 * lowmem reserves and high watermark so that kswapd
		 * should be able to balance it without having to
		 * write pages from its LRU list.
		 *
		 * This may look like it could increase pressure on
		 * lower zones by failing allocations in higher zones
		 * before they are full.  But the pages that do spill
		 * over are limited as the lower zones are protected
		 * by this very same mechanism.  It should not become
		 * a practical burden to them.
		 *
		 * XXX: For now, allow allocations to potentially
		 * exceed the per-zone dirty limit in the slowpath
		 * (ALLOC_WMARK_LOW unset) before going into reclaim,
		 * which is important when on a NUMA setup the allowed
		 * zones are together not big enough to reach the
		 * global limit.  The proper fix for these situations
		 * will require awareness of zones in the
		 * dirty-throttling and the flusher threads.
		 */
		/* 如果gfp_mask中允许进行脏页回写，那么如果此zone在内存中有过多的脏页，则跳过此zone，不对此zone进行处理
		 * 这里大概意思是脏页过多，kswapd会将这些脏页进行回写，这里就不将这些脏页进行回写了，会增加整个zone的压力
		 */
		if (consider_zone_dirty && !zone_dirty_ok(zone))
			continue;

		/* 选择阀值，阀值保存在管理区的watermark中，分别有alloc_min alloc_low alloc_high三种，选择任何一种都会要求分配后空闲页框数量不能少于阀值，默认是alloc_low */
		mark = zone->watermark[alloc_flags & ALLOC_WMARK_MASK];
		
		/* 根据阀值查看管理区中是否有足够的空闲页框，空闲内存数量保存在 zone->vm_stat[NR_FREE_PAGES]，这里的检查算法是: 分配后剩余的页框数量是否大于阀值加上此zone保留的内存数量，高于则返回true
		 * 三个阀值的大小关系是min < low < high
		 * high一般用于判断zone是否平衡
		 * 快速分配时，用的阀值是low
		 * 慢速分配中，用的阀值是min
		 * 在准备oom进程时，用的阀值是high
		 * 分配后剩余的页框数量低于或等于阀值加上此zone保留的内存数量，那么进行快速内存回收
		 */
		if (!zone_watermark_ok(zone, order, mark,
				       classzone_idx, alloc_flags)) {
			/* 没有足够的空闲页框 */
			int ret;

			/* Checked here to keep the fast path fast */
			BUILD_BUG_ON(ALLOC_NO_WATERMARKS < NR_WMARK);
			/* 如果分配标志中有 ALLOC_NO_WATERMARKS标志，代表无视阀值，直接分配 */
			if (alloc_flags & ALLOC_NO_WATERMARKS)
				goto try_this_zone;

			if (IS_ENABLED(CONFIG_NUMA) &&
					!did_zlc_setup && nr_online_nodes > 1) {
				/*
				 * we do zlc_setup if there are multiple nodes
				 * and before considering the first zone allowed
				 * by the cpuset.
				 */
				/* NUMA系统中如果使用了zlc(zonelist_cache)，则取出此zonelist允许的node列表 */
				allowednodes = zlc_setup(zonelist, alloc_flags);
				zlc_active = 1;
				did_zlc_setup = 1;
			}

			/* 
			 * 判断是否对此zone进行内存回收，如果开启了内存回收，则会对此zone进行内存回收，否则，通过距离判断是否进行内存回收
			 * zone_allows_reclaim()函数实际上就是判断zone所在node是否与preferred_zone所在node的距离 < RECLAIM_DISTANCE(30或10)
			 * 当内存回收未开启的情况下，只会对距离比较近的zone进行回收
			 */
			if (zone_reclaim_mode == 0 ||
			    !zone_allows_reclaim(preferred_zone, zone))
				goto this_zone_full;

			/*
			 * As we may have just activated ZLC, check if the first
			 * eligible zone has failed zone_reclaim recently.
			 */
			if (IS_ENABLED(CONFIG_NUMA) && zlc_active &&
				!zlc_zone_worth_trying(zonelist, z, allowednodes))
				continue;

			/*
			 * 这里就叫做快速回收，因为这里会选择尽量快的回收方式
			 * 回收到了2^order数量的页框时，才会返回真，即使回收了，没达到这个数量，也返回假
			 */
			ret = zone_reclaim(zone, gfp_mask, order);
			switch (ret) {
			case ZONE_RECLAIM_NOSCAN:  	/* 没有进行回收 */
				/* did not scan */
				continue;
			case ZONE_RECLAIM_FULL: 		/* 没有找到可回收的页面，也就是回收到的页框数量为0 */
				/* scanned but unreclaimable */
				continue;
			default:
				/* 回收到了一些或者回收到了2^order个页框，都会执行到这 */
				
				/* did we reclaim enough */
				/* 回收到了一些页，这里继续检查阀值是否足够分配连续页框，足够则跳到 try_this_zone 尝试在此zone中分配 */
				if (zone_watermark_ok(zone, order, mark,
						classzone_idx, alloc_flags))
					goto try_this_zone;

				/*
				 * Failed to reclaim enough to meet watermark.
				 * Only mark the zone full if checking the min
				 * watermark or if we failed to reclaim just
				 * 1<<order pages or else the page allocator
				 * fastpath will prematurely mark zones full
				 * when the watermark is between the low and
				 * min watermarks.
				 */
				/* 如果是按照min阀值进行分配的(在慢速分配中会尝试)，或者从此zone回收到一些页框了(但不足以分配)，则跳到this_zone_full，标记此zone */
				if (((alloc_flags & ALLOC_WMARK_MASK) == ALLOC_WMARK_MIN) ||
				    ret == ZONE_RECLAIM_SOME)
					goto this_zone_full;

				continue;
			}
		}

try_this_zone:
		/* 尝试从这个zone获取连续页框
		 * 只有当此zone中空闲页框数量 - 本次需要分配的数量 > 此zone的low阀值，这样才能执行到这
		 * 如果本意从preferred_zone分配内存，但是preferred_zone没有足够内存，到到了此zone进行分配，那么分配的页数量会统计到此zone的NR_ALLOC_BATCH
		 */
		page = buffered_rmqueue(preferred_zone, zone, order,
						gfp_mask, migratetype);
		/* 分配到了连续页框，跳出循环 */
		if (page)
			break;
this_zone_full:
		if (IS_ENABLED(CONFIG_NUMA) && zlc_active)
			/* 在zonelist的zonelist_cache中标记此node为满状态 */
			zlc_mark_zone_full(zonelist, z);
	}

	/* 分配到了连续页框 */
	if (page) {
		/*
		 * page->pfmemalloc is set when ALLOC_NO_WATERMARKS was
		 * necessary to allocate the page. The expectation is
		 * that the caller is taking steps that will free more
		 * memory. The caller should avoid the page being used
		 * for !PFMEMALLOC purposes.
		 */
		/* 如果分配时有 ALLOC_NO_WATERMARKS 标记则记录到页描述符中 */
		page->pfmemalloc = !!(alloc_flags & ALLOC_NO_WATERMARKS);
		/* 将连续页框中第一个页的页描述符返回 */
		return page;
	}

	/*
	 * The first pass makes sure allocations are spread fairly within the
	 * local node.  However, the local node might have free pages left
	 * after the fairness batches are exhausted, and remote zones haven't
	 * even been considered yet.  Try once more without fairness, and
	 * include remote zones now, before entering the slowpath and waking
	 * kswapd: prefer spilling to a remote zone over swapping locally.
	 */
	 /* 这里是失败时才会 */
	/* 如果第一次ALLOC_FAIR分配没有能够分配到内存，第二次尝试非ALLOC_FAIR分配 
	 * 第二次会遍历zonelist中其他node上的zone
	 * 而第一次公平分配不会
	 */
	if (alloc_flags & ALLOC_FAIR) {
		alloc_flags &= ~ALLOC_FAIR;
		/* nr_fair_skipped不为0，说明此node有些zone的batch页已经用尽，这里要增加一些给它 */
		if (nr_fair_skipped) {
			zonelist_rescan = true;
			/* 重新设置除目标zone之外，node中在此目标zone前面的zone的batch页数量大小 
			 * 设置为: batch页数量 = high阀值 - 低阀值 - 当前batch数量
			 */
			reset_alloc_batches(preferred_zone);
		}
		if (nr_online_nodes > 1)
			zonelist_rescan = true;
	}

	if (unlikely(IS_ENABLED(CONFIG_NUMA) && zlc_active)) {
		/* Disable zlc cache for second zonelist scan */
		/* 禁止zonelist_cache，zonelist_cache用于快速扫描的，它标记着哪个node有空闲内存哪个node没有，扫描时就跳过某些node */
		zlc_active = 0;
		zonelist_rescan = true;
	}

	/* 跳回去，尝试再次扫描一遍zonelist，这里最多只会进行一次再次扫描，因为第二次就不会把 zonelist_rescan 设置为true了 */
	if (zonelist_rescan)
		goto zonelist_scan;

	return NULL;
}

/*
 * Large machines with many possible nodes should not always dump per-node
 * meminfo in irq context.
 */
static inline bool should_suppress_show_mem(void)
{
	bool ret = false;

#if NODES_SHIFT > 8
	ret = in_interrupt();
#endif
	return ret;
}

static DEFINE_RATELIMIT_STATE(nopage_rs,
		DEFAULT_RATELIMIT_INTERVAL,
		DEFAULT_RATELIMIT_BURST);

void warn_alloc_failed(gfp_t gfp_mask, int order, const char *fmt, ...)
{
	unsigned int filter = SHOW_MEM_FILTER_NODES;

	if ((gfp_mask & __GFP_NOWARN) || !__ratelimit(&nopage_rs) ||
	    debug_guardpage_minorder() > 0)
		return;

	/*
	 * This documents exceptions given to allocations in certain
	 * contexts that are allowed to allocate outside current's set
	 * of allowed nodes.
	 */
	if (!(gfp_mask & __GFP_NOMEMALLOC))
		if (test_thread_flag(TIF_MEMDIE) ||
		    (current->flags & (PF_MEMALLOC | PF_EXITING)))
			filter &= ~SHOW_MEM_FILTER_NODES;
	if (in_interrupt() || !(gfp_mask & __GFP_WAIT))
		filter &= ~SHOW_MEM_FILTER_NODES;

	if (fmt) {
		struct va_format vaf;
		va_list args;

		va_start(args, fmt);

		vaf.fmt = fmt;
		vaf.va = &args;

		pr_warn("%pV", &vaf);

		va_end(args);
	}

	pr_warn("%s: page allocation failure: order:%d, mode:0x%x\n",
		current->comm, order, gfp_mask);

	dump_stack();
	if (!should_suppress_show_mem())
		show_mem(filter);
}

static inline int
should_alloc_retry(gfp_t gfp_mask, unsigned int order,
				unsigned long did_some_progress,
				unsigned long pages_reclaimed)
{
	/* Do not loop if specifically requested */
	if (gfp_mask & __GFP_NORETRY)
		return 0;

	/* Always retry if specifically requested */
	if (gfp_mask & __GFP_NOFAIL)
		return 1;

	/*
	 * Suspend converts GFP_KERNEL to __GFP_WAIT which can prevent reclaim
	 * making forward progress without invoking OOM. Suspend also disables
	 * storage devices so kswapd will not help. Bail if we are suspending.
	 */
	if (!did_some_progress && pm_suspended_storage())
		return 0;

	/*
	 * In this implementation, order <= PAGE_ALLOC_COSTLY_ORDER
	 * means __GFP_NOFAIL, but that may not be true in other
	 * implementations.
	 */
	if (order <= PAGE_ALLOC_COSTLY_ORDER)
		return 1;

	/*
	 * For order > PAGE_ALLOC_COSTLY_ORDER, if __GFP_REPEAT is
	 * specified, then we retry until we no longer reclaim any pages
	 * (above), or we've reclaimed an order of pages at least as
	 * large as the allocation's order. In both cases, if the
	 * allocation still fails, we stop retrying.
	 */
	if (gfp_mask & __GFP_REPEAT && pages_reclaimed < (1 << order))
		return 1;

	return 0;
}

static inline struct page *
__alloc_pages_may_oom(gfp_t gfp_mask, unsigned int order,
	struct zonelist *zonelist, enum zone_type high_zoneidx,
	nodemask_t *nodemask, struct zone *preferred_zone,
	int classzone_idx, int migratetype)
{
	struct page *page;

	/* Acquire the per-zone oom lock for each zone */
	if (!oom_zonelist_trylock(zonelist, gfp_mask)) {
		schedule_timeout_uninterruptible(1);
		return NULL;
	}

	/*
	 * PM-freezer should be notified that there might be an OOM killer on
	 * its way to kill and wake somebody up. This is too early and we might
	 * end up not killing anything but false positives are acceptable.
	 * See freeze_processes.
	 */
	note_oom_kill();

	/*
	 * Go through the zonelist yet one more time, keep very high watermark
	 * here, this is only to catch a parallel oom killing, we must fail if
	 * we're still under heavy pressure.
	 */
	page = get_page_from_freelist(gfp_mask|__GFP_HARDWALL, nodemask,
		order, zonelist, high_zoneidx,
		ALLOC_WMARK_HIGH|ALLOC_CPUSET,
		preferred_zone, classzone_idx, migratetype);
	if (page)
		goto out;

	if (!(gfp_mask & __GFP_NOFAIL)) {
		/* The OOM killer will not help higher order allocs */
		if (order > PAGE_ALLOC_COSTLY_ORDER)
			goto out;
		/* The OOM killer does not needlessly kill tasks for lowmem */
		if (high_zoneidx < ZONE_NORMAL)
			goto out;
		/*
		 * GFP_THISNODE contains __GFP_NORETRY and we never hit this.
		 * Sanity check for bare calls of __GFP_THISNODE, not real OOM.
		 * The caller should handle page allocation failure by itself if
		 * it specifies __GFP_THISNODE.
		 * Note: Hugepage uses it but will hit PAGE_ALLOC_COSTLY_ORDER.
		 */
		if (gfp_mask & __GFP_THISNODE)
			goto out;
	}
	/* Exhausted what can be done so it's blamo time */
	out_of_memory(zonelist, gfp_mask, order, nodemask, false);

out:
	oom_zonelist_unlock(zonelist, gfp_mask);
	return page;
}

#ifdef CONFIG_COMPACTION
/* Try memory compaction for high-order allocations before reclaim */
/* 伙伴系统内存压缩函数 
 * order是本次分配时需要获取的页框数量
 * mode保存的是使用的模式，异步，同步，轻同步三种
 */
static struct page *
__alloc_pages_direct_compact(gfp_t gfp_mask, unsigned int order,
	struct zonelist *zonelist, enum zone_type high_zoneidx,
	nodemask_t *nodemask, int alloc_flags, struct zone *preferred_zone,
	int classzone_idx, int migratetype, enum migrate_mode mode,
	int *contended_compaction, bool *deferred_compaction)
{
	struct zone *last_compact_zone = NULL;
	unsigned long compact_result;
	struct page *page;

	if (!order)
		return NULL;

	current->flags |= PF_MEMALLOC;
	/* 尝试对zonelist中所有zone进行压缩内存 */
	compact_result = try_to_compact_pages(zonelist, order, gfp_mask,
						nodemask, mode,
						contended_compaction,
						&last_compact_zone);
	current->flags &= ~PF_MEMALLOC;

	switch (compact_result) {
	case COMPACT_DEFERRED:
		*deferred_compaction = true;
		/* fall-through */
	case COMPACT_SKIPPED:
		return NULL;
	default:
		break;
	}

	/*
	 * At least in one zone compaction wasn't deferred or skipped, so let's
	 * count a compaction stall
	 */
	count_vm_event(COMPACTSTALL);

	/* Page migration frees to the PCP lists but we want merging */
	drain_pages(get_cpu());
	put_cpu();

	/* 再次尝试获取连续页框 */
	page = get_page_from_freelist(gfp_mask, nodemask,
			order, zonelist, high_zoneidx,
			alloc_flags & ~ALLOC_NO_WATERMARKS,
			preferred_zone, classzone_idx, migratetype);

	/* 获取到了连续页框 */
	if (page) {
		/* 获取这段页框所在的zone，这里面主要是重置zone跟内存压缩推迟相关的变量 */
		struct zone *zone = page_zone(page);
		
		zone->compact_blockskip_flush = false;
		/* 因为这里是获取到了连续页框才会执行到的 
		 * zone->compact_considered = 0;
		 * zone->compact_defer_shift = 0;
		 * if (order >= zone->compact_order_failed)
		 *     zone->compact_order_failed = order + 1;
		 */
		compaction_defer_reset(zone, order, true);
		count_vm_event(COMPACTSUCCESS);
		return page;
	}

	/*
	 * last_compact_zone is where try_to_compact_pages thought allocation
	 * should succeed, so it did not defer compaction. But here we know
	 * that it didn't succeed, so we do the defer.
	 */
	/* 同步和轻同步的情况，并且在此zone压缩后内存足够进行分配了，但是又没有分配成功，则提高此zone的推迟计数器，让其每次推迟更多 */
	if (last_compact_zone && mode != MIGRATE_ASYNC)
		defer_compaction(last_compact_zone, order);

	/*
	 * It's bad if compaction run occurs and fails. The most likely reason
	 * is that pages exist, but not enough to satisfy watermarks.
	 */
	count_vm_event(COMPACTFAIL);

	cond_resched();

	return NULL;
}
#else
static inline struct page *
__alloc_pages_direct_compact(gfp_t gfp_mask, unsigned int order,
	struct zonelist *zonelist, enum zone_type high_zoneidx,
	nodemask_t *nodemask, int alloc_flags, struct zone *preferred_zone,
	int classzone_idx, int migratetype, enum migrate_mode mode,
	int *contended_compaction, bool *deferred_compaction)
{
	return NULL;
}
#endif /* CONFIG_COMPACTION */

/* Perform direct synchronous page reclaim */
/* 内存回收 */
static int
__perform_reclaim(gfp_t gfp_mask, unsigned int order, struct zonelist *zonelist,
		  nodemask_t *nodemask)
{
	struct reclaim_state reclaim_state;
	int progress;

	/* 检查是否需要调度，需要则调度 */
	cond_resched();

	/* We now go into synchronous reclaim */
	/* 这行暂时不清楚用途，用于cgroup的cpuset */
	cpuset_memory_pressure_bump();
	/* 标志此进程正在分配内存中 */
	current->flags |= PF_MEMALLOC;
	lockdep_set_current_reclaim_state(gfp_mask);
	reclaim_state.reclaimed_slab = 0;
	current->reclaim_state = &reclaim_state;

	/*  */
	progress = try_to_free_pages(zonelist, order, gfp_mask, nodemask);

	current->reclaim_state = NULL;
	lockdep_clear_current_reclaim_state();
	/* 取消标志此进程正在分配内存中 */
	current->flags &= ~PF_MEMALLOC;

	cond_resched();

	return progress;
}

/* The really slow allocator path where we enter direct reclaim */
/* 对所有zonelist中的zone进行一次直接内存回收 
 * 
 */
static inline struct page *
__alloc_pages_direct_reclaim(gfp_t gfp_mask, unsigned int order,
	struct zonelist *zonelist, enum zone_type high_zoneidx,
	nodemask_t *nodemask, int alloc_flags, struct zone *preferred_zone,
	int classzone_idx, int migratetype, unsigned long *did_some_progress)
{
	struct page *page = NULL;
	bool drained = false;

	/* 内存回收 */
	*did_some_progress = __perform_reclaim(gfp_mask, order, zonelist,
					       nodemask);
	if (unlikely(!(*did_some_progress)))
		return NULL;

	/* After successful reclaim, reconsider all zones for allocation */
	if (IS_ENABLED(CONFIG_NUMA))
		zlc_clear_zones_full(zonelist);

retry:
	page = get_page_from_freelist(gfp_mask, nodemask, order,
					zonelist, high_zoneidx,
					alloc_flags & ~ALLOC_NO_WATERMARKS,
					preferred_zone, classzone_idx,
					migratetype);

	/*
	 * If an allocation failed after direct reclaim, it could be because
	 * pages are pinned on the per-cpu lists. Drain them and try again
	 */
	if (!page && !drained) {
		drain_all_pages();
		drained = true;
		goto retry;
	}

	return page;
}

/*
 * This is called in the allocator slow-path if the allocation request is of
 * sufficient urgency to ignore watermarks and take other desperate measures
 */
static inline struct page *
__alloc_pages_high_priority(gfp_t gfp_mask, unsigned int order,
	struct zonelist *zonelist, enum zone_type high_zoneidx,
	nodemask_t *nodemask, struct zone *preferred_zone,
	int classzone_idx, int migratetype)
{
	struct page *page;

	do {
		page = get_page_from_freelist(gfp_mask, nodemask, order,
			zonelist, high_zoneidx, ALLOC_NO_WATERMARKS,
			preferred_zone, classzone_idx, migratetype);

		if (!page && gfp_mask & __GFP_NOFAIL)
			/* 等待一些页框的回收回写完成 */
			wait_iff_congested(preferred_zone, BLK_RW_ASYNC, HZ/50);
	} while (!page && (gfp_mask & __GFP_NOFAIL));

	return page;
}

static void wake_all_kswapds(unsigned int order,
			     struct zonelist *zonelist,
			     enum zone_type high_zoneidx,
			     struct zone *preferred_zone,
			     nodemask_t *nodemask)
{
	struct zoneref *z;
	struct zone *zone;

	/* 遍历所有zonelist的zone，检查是否需要唤醒对应的kswapd进程，不过切记一个node有一个kswapd进程，而不是一个zone
	 * 只有zone中空闲页框数量低于高警戒值才会唤醒对应的kswapd线程
	 */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
						high_zoneidx, nodemask)
		wakeup_kswapd(zone, order, zone_idx(preferred_zone));
}

static inline int
gfp_to_alloc_flags(gfp_t gfp_mask)
{
	int alloc_flags = ALLOC_WMARK_MIN | ALLOC_CPUSET;
	const bool atomic = !(gfp_mask & (__GFP_WAIT | __GFP_NO_KSWAPD));

	/* __GFP_HIGH is assumed to be the same as ALLOC_HIGH to save a branch. */
	BUILD_BUG_ON(__GFP_HIGH != (__force gfp_t) ALLOC_HIGH);

	/*
	 * The caller may dip into page reserves a bit more if the caller
	 * cannot run direct reclaim, or if the caller has realtime scheduling
	 * policy or is asking for __GFP_HIGH memory.  GFP_ATOMIC requests will
	 * set both ALLOC_HARDER (atomic == true) and ALLOC_HIGH (__GFP_HIGH).
	 */
	/* 如果是GFP_ATOMIC，那么设置分配标记应该是__GFP_HIGH和__GFP_HARDER */
	alloc_flags |= (__force int) (gfp_mask & __GFP_HIGH);

	if (atomic) {
		/*
		 * Not worth trying to allocate harder for __GFP_NOMEMALLOC even
		 * if it can't schedule.
		 */
		if (!(gfp_mask & __GFP_NOMEMALLOC))
			alloc_flags |= ALLOC_HARDER;
		/*
		 * Ignore cpuset mems for GFP_ATOMIC rather than fail, see the
		 * comment for __cpuset_node_allowed_softwall().
		 */
		alloc_flags &= ~ALLOC_CPUSET;
	} else if (unlikely(rt_task(current)) && !in_interrupt())
		alloc_flags |= ALLOC_HARDER;

	if (likely(!(gfp_mask & __GFP_NOMEMALLOC))) {
		/* 分配标志中包含__GFP_MEMALLOC */
		if (gfp_mask & __GFP_MEMALLOC)
			alloc_flags |= ALLOC_NO_WATERMARKS;
		/* 处于软中断中，并且当前进程被设为允许使用保留内存 */
		else if (in_serving_softirq() && (current->flags & PF_MEMALLOC))
			alloc_flags |= ALLOC_NO_WATERMARKS;
		/* 不在中断中，并且当前进程 被设置为允许使用保留内存 或者是正在被oom的进程 */
		else if (!in_interrupt() &&
				((current->flags & PF_MEMALLOC) ||
				 unlikely(test_thread_flag(TIF_MEMDIE))))
			alloc_flags |= ALLOC_NO_WATERMARKS;
	}
#ifdef CONFIG_CMA
	if (gfpflags_to_migratetype(gfp_mask) == MIGRATE_MOVABLE)
		alloc_flags |= ALLOC_CMA;
#endif
	return alloc_flags;
}

bool gfp_pfmemalloc_allowed(gfp_t gfp_mask)
{
	return !!(gfp_to_alloc_flags(gfp_mask) & ALLOC_NO_WATERMARKS);
}

/* 慢速分配页框 */
static inline struct page *
__alloc_pages_slowpath(gfp_t gfp_mask, unsigned int order,
	struct zonelist *zonelist, enum zone_type high_zoneidx,
	nodemask_t *nodemask, struct zone *preferred_zone,
	int classzone_idx, int migratetype)
{
	const gfp_t wait = gfp_mask & __GFP_WAIT;
	struct page *page = NULL;
	int alloc_flags;
	unsigned long pages_reclaimed = 0;
	unsigned long did_some_progress;
	enum migrate_mode migration_mode = MIGRATE_ASYNC;
	bool deferred_compaction = false;
	int contended_compaction = COMPACT_CONTENDED_NONE;

	/*
	 * In the slowpath, we sanity check order to avoid ever trying to
	 * reclaim >= MAX_ORDER areas which will never succeed. Callers may
	 * be using allocators in order of preference for an area that is
	 * too large.
	 */
	/* order不能大于10或11 */
	if (order >= MAX_ORDER) {
		WARN_ON_ONCE(!(gfp_mask & __GFP_NOWARN));
		return NULL;
	}

	/*
	 * GFP_THISNODE (meaning __GFP_THISNODE, __GFP_NORETRY and
	 * __GFP_NOWARN set) should not cause reclaim since the subsystem
	 * (f.e. slab) using GFP_THISNODE may choose to trigger reclaim
	 * using a larger set of nodes after it has established that the
	 * allowed per node queues are empty and that nodes are
	 * over allocated.
	 */
	/* 调用者指定了GFP_THISNODE标志，表示不能进行内存回收
	 * 上层调用者应当在指定了GFP_THISNODE失败后，使用其他标志进行分配
	 */
	if (IS_ENABLED(CONFIG_NUMA) &&
	    (gfp_mask & GFP_THISNODE) == GFP_THISNODE)
		goto nopage;

restart:
	/* 如果调用者的标志没有禁止kswapd线程标志，则会唤醒这个线程用于页框回收，这里会唤醒所有node结点中的kswap线程，每个node都有一个自己的kswap线程
	 * 里面会遍历zonelist链表的zone区域，只有zone区域的空闲页框数量低于高警戒值才会唤醒zone对应的node的kswapd线程
	 */
	if (!(gfp_mask & __GFP_NO_KSWAPD))
		wake_all_kswapds(order, zonelist, high_zoneidx,
				preferred_zone, nodemask);

	/*
	 * OK, we're below the kswapd watermark and have kicked background
	 * reclaim. Now things get more complex, so set up alloc_flags according
	 * to how we want to proceed.
	 */
	/* 根据传入标志确定其他的一些标志 
	 * 这里会默认使用min阀值进行内存分配
	 * 如果gfp_mask是GFP_ATOMIC，那么这个alloc_flags应该是__GFP_HIGH | __GFP_HARDER
	 *
	 * 如果标记有__GFP_MEMALLOC，或者
	 * 处于软中断中，并且当前进程被设为允许使用保留内存，或者
	 * 不在中断中，并且当前进程 被设置为允许使用保留内存 或者是正在被oom的进程
	 * 那么就会标记ALLOC_NO_WATERMARKS，表示忽略阀值进行分配
	 */
	alloc_flags = gfp_to_alloc_flags(gfp_mask);

	/*
	 * Find the true preferred zone if the allocation is unconstrained by
	 * cpusets.
	 */
	/* 如果不受CPUSET的限制，则找出优先用于分配的管理区 */
	if (!(alloc_flags & ALLOC_CPUSET) && !nodemask) {
		struct zoneref *preferred_zoneref;
		preferred_zoneref = first_zones_zonelist(zonelist, high_zoneidx,
				NULL, &preferred_zone);
		classzone_idx = zonelist_zone_idx(preferred_zoneref);
	}

rebalance:
	/* This is the last chance, in general, before the goto nopage. */
	/* 这里会用min阀值再次尝试获取页框，如果这次尝试还是没申请到页框，就要走漫长的步骤了 */
	page = get_page_from_freelist(gfp_mask, nodemask, order, zonelist,
			high_zoneidx, alloc_flags & ~ALLOC_NO_WATERMARKS,
			preferred_zone, classzone_idx, migratetype);
	
	if (page)
		goto got_pg;

	/* Allocate without watermarks if the context allows */
	/* 如果标记了不关注阀值进行分配，这样会有可能使用预留的内存进行分配 
	 * 如果标记有__GFP_MEMALLOC，或者
	 * 处于软中断中，并且当前进程被设为允许使用保留内存，或者
	 * 不在中断中，并且当前进程 被设置为允许使用保留内存 或者是正在被oom的进程
	 * 那么就会进行这种分配
	 * 而平常可能用到的GFP_ATOMIC，则不是这种分配，GFP_ATOMIC会在zone_watermark_ok()中通过降低阀值进行判断，它不会用到预留的内存
	 */
	if (alloc_flags & ALLOC_NO_WATERMARKS) {
		/*
		 * Ignore mempolicies if ALLOC_NO_WATERMARKS on the grounds
		 * the allocation is high priority and these type of
		 * allocations are system rather than user orientated
		 */
		/* 这里就是还是没有获取到，尝试忽略阀值再次进行获取页框 */
		zonelist = node_zonelist(numa_node_id(), gfp_mask);

		/* 尝试获取页框，这里不调用zone_watermark_ok()，也就是忽略了阀值，使用管理区预留的页框 
		 * 当没有获取到时，如果标记有__GFP_NOFAIL，则进行循环不停地分配，直到获取到页框
		 */
		page = __alloc_pages_high_priority(gfp_mask, order,
				zonelist, high_zoneidx, nodemask,
				preferred_zone, classzone_idx, migratetype);
		if (page) {
			goto got_pg;
		}
	}

	/* Atomic allocations - we can't balance anything */
	/* 还是没有分配到，如果调用者不希望等待获取内存，就返回退出 */
	if (!wait) {
		/*
		 * All existing users of the deprecated __GFP_NOFAIL are
		 * blockable, so warn of any new users that actually allow this
		 * type of allocation to fail.
		 */
		WARN_ON_ONCE(gfp_mask & __GFP_NOFAIL);
		goto nopage;
	}

	/* Avoid recursion of direct reclaim */
	/* 调用者本身就是内存回收进程，不能执行后面的内存回收流程，是为了防止死锁 */
	if (current->flags & PF_MEMALLOC)
		goto nopage;

	/* Avoid allocations with no watermarks from looping endlessly */
	if (test_thread_flag(TIF_MEMDIE) && !(gfp_mask & __GFP_NOFAIL))
		goto nopage;

	/*
	 * Try direct compaction. The first pass is asynchronous. Subsequent
	 * attempts after direct reclaim are synchronous
	 */
	/* 通过压缩看能否有多余的页框，通过页面迁移实现，这里的内存压缩是异步模式，要进入这里，有个前提就是分配内存的标志中必须允许阻塞(__GFP_WAIT)，大多数情况分配都允许阻塞
	 * 只会对MIRGATE_MOVABLE和MIGRATE_CMA类型的页进行移动，并且不允许阻塞
	 * 对zonelist的每个zone进行一次异步内存压缩
	 */
	page = __alloc_pages_direct_compact(gfp_mask, order, zonelist,
					high_zoneidx, nodemask, alloc_flags,
					preferred_zone,
					classzone_idx, migratetype,
					migration_mode, &contended_compaction,
					&deferred_compaction);
	if (page)
		goto got_pg;

	/* Checks for THP-specific high-order allocations */
	if ((gfp_mask & GFP_TRANSHUGE) == GFP_TRANSHUGE) {
		/*
		 * If compaction is deferred for high-order allocations, it is
		 * because sync compaction recently failed. If this is the case
		 * and the caller requested a THP allocation, we do not want
		 * to heavily disrupt the system, so we fail the allocation
		 * instead of entering direct reclaim.
		 */
		if (deferred_compaction)
			goto nopage;

		/*
		 * In all zones where compaction was attempted (and not
		 * deferred or skipped), lock contention has been detected.
		 * For THP allocation we do not want to disrupt the others
		 * so we fallback to base pages instead.
		 */
		if (contended_compaction == COMPACT_CONTENDED_LOCK)
			goto nopage;

		/*
		 * If compaction was aborted due to need_resched(), we do not
		 * want to further increase allocation latency, unless it is
		 * khugepaged trying to collapse.
		 */
		if (contended_compaction == COMPACT_CONTENDED_SCHED
			&& !(current->flags & PF_KTHREAD))
			goto nopage;
	}

	/*
	 * It can become very expensive to allocate transparent hugepages at
	 * fault, so use asynchronous memory compaction for THP unless it is
	 * khugepaged trying to collapse.
	 */
	/* 设置第二次内存压缩为轻同步模式，当第一次内存压缩后还是没有分配到足够页框时会使用
	 * 轻同步内存压缩两有一种情况会发生
	 * 在申请内存时内存不足，通过第一次异步内存压缩后，还是不足以分配连续页框后
	 * 1.明确禁止处理透明大页的时候，可以进行轻同步内存压缩
	 * 2.如果是内核线程，可以进行轻同步内存压缩(即使没有禁止处理透明大页的情况)
	 */
	if ((gfp_mask & GFP_TRANSHUGE) != GFP_TRANSHUGE ||
						(current->flags & PF_KTHREAD))
		migration_mode = MIGRATE_SYNC_LIGHT;

	/* Try direct reclaim and then allocating */
	/* 进行直接内存回收 */
	page = __alloc_pages_direct_reclaim(gfp_mask, order,
					zonelist, high_zoneidx,
					nodemask,
					alloc_flags, preferred_zone,
					classzone_idx, migratetype,
					&did_some_progress);
	if (page)
		goto got_pg;

	/*
	 * If we failed to make any progress reclaiming, then we are
	 * running out of options and have to consider going OOM
	 */
	/* 还是没有分配到内存 */
	if (!did_some_progress) {
		/* 如果分配标志中表示允许进行文件系统操作，并且允许重试，那么就允许进行OOM */
		if (oom_gfp_allowed(gfp_mask)) {
			if (oom_killer_disabled)
				goto nopage;
			/* Coredumps can quickly deplete all memory reserves */
			/* 分配标志有__GFP_NOFAIL的能够进行OOM */
			if ((current->flags & PF_DUMPCORE) &&
			    !(gfp_mask & __GFP_NOFAIL))
				goto nopage;
			/* 杀死其他进程后再尝试，里面会使用high阀值进行尝试分配
			 * 是希望通过杀死进程获取比较多的内存?
			 */
			page = __alloc_pages_may_oom(gfp_mask, order,
					zonelist, high_zoneidx,
					nodemask, preferred_zone,
					classzone_idx, migratetype);
			if (page)
				goto got_pg;

			/* 分配禁止失败 */
			if (!(gfp_mask & __GFP_NOFAIL)) {
				/*
				 * The oom killer is not called for high-order
				 * allocations that may fail, so if no progress
				 * is being made, there are no other options and
				 * retrying is unlikely to help.
				 */
				/* 要求的数量太多，没办法 */
				if (order > PAGE_ALLOC_COSTLY_ORDER)
					goto nopage;
				/*
				 * The oom killer is not called for lowmem
				 * allocations to prevent needlessly killing
				 * innocent tasks.
				 */
				/* 是从DMA区域要内存，实在没太多内存 */
				if (high_zoneidx < ZONE_NORMAL)
					goto nopage;
			}

			goto restart;
		}
	}

	/* Check if we should retry the allocation */

	/* 回收到了一部分，这里检查是否继续尝试回收 */
	pages_reclaimed += did_some_progress;
	if (should_alloc_retry(gfp_mask, order, did_some_progress,
						pages_reclaimed)) {
		/* 需要，这里会阻塞一段时间，然后重试 */
		/* Wait for some write requests to complete then retry */
		wait_iff_congested(preferred_zone, BLK_RW_ASYNC, HZ/50);
		goto rebalance;
	} else {
		/*
		 * High-order allocations do not necessarily loop after
		 * direct reclaim and reclaim/compaction depends on compaction
		 * being called after reclaim so call directly if necessary
		 */
		/* 如果需要分配的页不是透明大页，或者当前进程是内核线程的情况下，这里会进行轻同步模式的内存压缩，其他情况还是异步的内存压缩
		 * 如果是进程需要，并且分配的不是透明大页，则会使用轻同步模式
		 * 在轻同步内存压缩下允许进行大多数操作的阻塞，但不会对隔离出来需要移动的脏页进行回写操作，也不会等待正在回写的脏页回写完成，会阻塞去获取锁
		 * 回收的数量保存在did_some_progress中，有可能回收到了页框，但是并不够分配
		 */
		page = __alloc_pages_direct_compact(gfp_mask, order, zonelist,
					high_zoneidx, nodemask, alloc_flags,
					preferred_zone,
					classzone_idx, migratetype,
					migration_mode, &contended_compaction,
					&deferred_compaction);
		if (page)
			goto got_pg;
	}

nopage:
	/* 没有分配到内存 */
	warn_alloc_failed(gfp_mask, order, NULL);
	return page;
got_pg:
	/* 分配到了 */
	if (kmemcheck_enabled)
		kmemcheck_pagealloc_alloc(page, order, gfp_mask);

	return page;
}

/*
 * This is the 'heart' of the zoned buddy allocator.
 */
/* gfp_mask: 上层要求分配内存时使用的标志
 * order: 需要的连续页框的order值，如果是1个页框，则为0
 * zonelist: 合适的zone列表
 * nodemask: node结点掩码，用于判断允许从哪些node上分配
 */
struct page *
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,
			struct zonelist *zonelist, nodemask_t *nodemask)
{
	enum zone_type high_zoneidx = gfp_zone(gfp_mask);
	/* preferred_zone指向第一个合适的管理区 */	
	struct zone *preferred_zone;
	struct zoneref *preferred_zoneref;
	struct page *page = NULL;
	/* 从gfp_mask中获取选定的页框类型，当中只会检查__GFP_MOVABLE和__GFP_RECLAIMABLE */
	int migratetype = gfpflags_to_migratetype(gfp_mask);
	unsigned int cpuset_mems_cookie;
	/* 这个需要注意一下，之后分配是会根据这个flags进行一定的操作，默认是使用zone的低阀值判断是否需要进行内存回收 */
	int alloc_flags = ALLOC_WMARK_LOW|ALLOC_CPUSET|ALLOC_FAIR;
	int classzone_idx;

	gfp_mask &= gfp_allowed_mask;

	lockdep_trace_alloc(gfp_mask);

	/* 如果设置了__GFP_WAIT，就检查当前进程是否需要调度，如果要则会进行调度
	 * 大多数情况的分配都会有__GFP_WAIT标志
	 */
	might_sleep_if(gfp_mask & __GFP_WAIT);

	/* 检查gfp_mask和order是否符合要求，就是跟fail_page_alloc里面每一项对比检查 */
	if (should_fail_alloc_page(gfp_mask, order))
		return NULL;

	/*
	 * Check the zones suitable for the gfp_mask contain at least one
	 * valid zone. It's possible to have an empty zonelist as a result
	 * of GFP_THISNODE and a memoryless node
	 */
	/* 检查结点的管理区链表是否为空 */
	if (unlikely(!zonelist->_zonerefs->zone))
		return NULL;

	/* 如果使能了CMA，选定的页框类型是可迁移的页框，就在标志上加上ALLOC_CMA */
	if (IS_ENABLED(CONFIG_CMA) && migratetype == MIGRATE_MOVABLE)
		alloc_flags |= ALLOC_CMA;

retry_cpuset:
	/* 这里只是表明在这个顺序锁中是个读者 */
	cpuset_mems_cookie = read_mems_allowed_begin();

	/* The preferred zone is used for statistics later */
	/* 获取链表中第一个管理区，每一次retry_cpuset就是在一个管理区中进行分配 
	 * preferred_zone指向第一个合适的管理区
	 */
	preferred_zoneref = first_zones_zonelist(zonelist, high_zoneidx,
				nodemask ? : &cpuset_current_mems_allowed,
				&preferred_zone);
	if (!preferred_zone)
		goto out;
	
	/* 管理区的类型的偏移量，0是 ZONE_DMA , 1是 ZONE_NORMAL , 2是 ZONE_HIGHMEM , 3是 ZONE_MOVABLE */
	classzone_idx = zonelist_zone_idx(preferred_zoneref);

	/* 第一次尝试分配页框，这里是快速分配
	 * 快速分配时以low阀值为标准
	 * 遍历zonelist，尝试获取2的order次方个连续的页框 
	 * 在遍历zone时，如果此zone当前空闲内存减去需要申请的内存之后，空闲内存是低于low阀值，那么此zone会进行快速内存回收
	 */
	page = get_page_from_freelist(gfp_mask|__GFP_HARDWALL, nodemask, order,
			zonelist, high_zoneidx, alloc_flags,
			preferred_zone, classzone_idx, migratetype);

	
	if (unlikely(!page)) {
		/*
		 * Runtime PM, block IO and its error handling path
		 * can deadlock because I/O on the device might not
		 * complete.
		 */
		/* 如果没有分配到所需连续的页框，这里会尝试第二次分配，这次是慢速分配，并且同样分配时不允许进行IO操作 
		 * 如果当前进程current->flags标志了PF_MEMALLOC_NOIO标志，表示进程获取内存时禁止IO操作，则返回清除了__GFP_IO和__GFP_FS的gfp_mask
		 * 而gfp_mask绝大多数情况都是允许__GFP_IO和__GFP_FS标志的
		 */
		gfp_mask = memalloc_noio_flags(gfp_mask);
		/* 如果之前没有分配成功，这里尝试进入慢速分配，在这个函数中，会尝试唤醒页框回收线程，然后再进行分配 
		 * 慢速分配首先会唤醒kswapd线程进行内存回收
		 * 然后如果标记了忽略阀值，则从保留的内存里回收
		 * 然后进行内存压缩
		 * 最后再尝试直接内存回收
		 */
		page = __alloc_pages_slowpath(gfp_mask, order,
				zonelist, high_zoneidx, nodemask,
				preferred_zone, classzone_idx, migratetype);
	}

	trace_mm_page_alloc(page, order, gfp_mask, migratetype);

out:
	/*
	 * When updating a task's mems_allowed, it is possible to race with
	 * parallel threads in such a way that an allocation can fail while
	 * the mask is being updated. If a page allocation is about to fail,
	 * check if the cpuset changed during allocation and if so, retry.
	 */
	/* 如果都没有分配成功，这里会不停尝试重新分配，获取下一个zonelist的zone */
	if (unlikely(!page && read_mems_allowed_retry(cpuset_mems_cookie)))
		goto retry_cpuset;
	/* 返回第一个页描述符 */
	return page;
}
EXPORT_SYMBOL(__alloc_pages_nodemask);

/*
 * Common helper functions.
 */
unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
{
	struct page *page;

	/*
	 * __get_free_pages() returns a 32-bit address, which cannot represent
	 * a highmem page
	 */
	VM_BUG_ON((gfp_mask & __GFP_HIGHMEM) != 0);

	page = alloc_pages(gfp_mask, order);
	if (!page)
		return 0;
	return (unsigned long) page_address(page);
}
EXPORT_SYMBOL(__get_free_pages);

unsigned long get_zeroed_page(gfp_t gfp_mask)
{
	return __get_free_pages(gfp_mask | __GFP_ZERO, 0);
}
EXPORT_SYMBOL(get_zeroed_page);

/* 释放页框 */
void __free_pages(struct page *page, unsigned int order)
{
	/* 检查页框是否还有进程在使用，就是检查_count变量的值是否为0 */
	if (put_page_testzero(page)) {
		/* 如果是1个页框，则放回每CPU高速缓存中，如果是多个页框，则放回伙伴系统 */
		if (order == 0)
			free_hot_cold_page(page, false);
		else
			/* 释放连续页框，页框数量是从page开始的2^order个 */
			__free_pages_ok(page, order);
	}
}

EXPORT_SYMBOL(__free_pages);

void free_pages(unsigned long addr, unsigned int order)
{
	if (addr != 0) {
		VM_BUG_ON(!virt_addr_valid((void *)addr));
		__free_pages(virt_to_page((void *)addr), order);
	}
}

EXPORT_SYMBOL(free_pages);

/*
 * alloc_kmem_pages charges newly allocated pages to the kmem resource counter
 * of the current memory cgroup.
 *
 * It should be used when the caller would like to use kmalloc, but since the
 * allocation is large, it has to fall back to the page allocator.
 */
struct page *alloc_kmem_pages(gfp_t gfp_mask, unsigned int order)
{
	struct page *page;
	struct mem_cgroup *memcg = NULL;

	if (!memcg_kmem_newpage_charge(gfp_mask, &memcg, order))
		return NULL;
	page = alloc_pages(gfp_mask, order);
	memcg_kmem_commit_charge(page, memcg, order);
	return page;
}

struct page *alloc_kmem_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
{
	struct page *page;
	struct mem_cgroup *memcg = NULL;

	if (!memcg_kmem_newpage_charge(gfp_mask, &memcg, order))
		return NULL;
	page = alloc_pages_node(nid, gfp_mask, order);
	memcg_kmem_commit_charge(page, memcg, order);
	return page;
}

/*
 * __free_kmem_pages and free_kmem_pages will free pages allocated with
 * alloc_kmem_pages.
 */
void __free_kmem_pages(struct page *page, unsigned int order)
{
	memcg_kmem_uncharge_pages(page, order);
	__free_pages(page, order);
}

void free_kmem_pages(unsigned long addr, unsigned int order)
{
	if (addr != 0) {
		VM_BUG_ON(!virt_addr_valid((void *)addr));
		__free_kmem_pages(virt_to_page((void *)addr), order);
	}
}

static void *make_alloc_exact(unsigned long addr, unsigned order, size_t size)
{
	if (addr) {
		unsigned long alloc_end = addr + (PAGE_SIZE << order);
		unsigned long used = addr + PAGE_ALIGN(size);

		split_page(virt_to_page((void *)addr), order);
		while (used < alloc_end) {
			free_page(used);
			used += PAGE_SIZE;
		}
	}
	return (void *)addr;
}

/**
 * alloc_pages_exact - allocate an exact number physically-contiguous pages.
 * @size: the number of bytes to allocate
 * @gfp_mask: GFP flags for the allocation
 *
 * This function is similar to alloc_pages(), except that it allocates the
 * minimum number of pages to satisfy the request.  alloc_pages() can only
 * allocate memory in power-of-two pages.
 *
 * This function is also limited by MAX_ORDER.
 *
 * Memory allocated by this function must be released by free_pages_exact().
 */
void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
{
	unsigned int order = get_order(size);
	unsigned long addr;

	addr = __get_free_pages(gfp_mask, order);
	return make_alloc_exact(addr, order, size);
}
EXPORT_SYMBOL(alloc_pages_exact);

/**
 * alloc_pages_exact_nid - allocate an exact number of physically-contiguous
 *			   pages on a node.
 * @nid: the preferred node ID where memory should be allocated
 * @size: the number of bytes to allocate
 * @gfp_mask: GFP flags for the allocation
 *
 * Like alloc_pages_exact(), but try to allocate on node nid first before falling
 * back.
 * Note this is not alloc_pages_exact_node() which allocates on a specific node,
 * but is not exact.
 */
void * __meminit alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask)
{
	unsigned order = get_order(size);
	struct page *p = alloc_pages_node(nid, gfp_mask, order);
	if (!p)
		return NULL;
	return make_alloc_exact((unsigned long)page_address(p), order, size);
}

/**
 * free_pages_exact - release memory allocated via alloc_pages_exact()
 * @virt: the value returned by alloc_pages_exact.
 * @size: size of allocation, same value as passed to alloc_pages_exact().
 *
 * Release the memory allocated by a previous call to alloc_pages_exact.
 */
void free_pages_exact(void *virt, size_t size)
{
	unsigned long addr = (unsigned long)virt;
	unsigned long end = addr + PAGE_ALIGN(size);

	while (addr < end) {
		free_page(addr);
		addr += PAGE_SIZE;
	}
}
EXPORT_SYMBOL(free_pages_exact);

/**
 * nr_free_zone_pages - count number of pages beyond high watermark
 * @offset: The zone index of the highest zone
 *
 * nr_free_zone_pages() counts the number of counts pages which are beyond the
 * high watermark within all zones at or below a given zone index.  For each
 * zone, the number of pages is calculated as:
 *     managed_pages - high_pages
 */
/* 返回 所有管理区所管理的页框数量 - 管理区设定最高页框数量 的超出值 */
static unsigned long nr_free_zone_pages(int offset)
{
	struct zoneref *z;
	struct zone *zone;

	/* Just pick one node, since fallback list is circular */
	unsigned long sum = 0;

	struct zonelist *zonelist = node_zonelist(numa_node_id(), GFP_KERNEL);

	/* 遍历所有管理区，统计全部超出的页框数量 */
	for_each_zone_zonelist(zone, z, zonelist, offset) {
		/* 当前管理区管理的页框数量 */
		unsigned long size = zone->managed_pages;
		/* 当前管理区设定的页框数量最大值 */
		unsigned long high = high_wmark_pages(zone);
		if (size > high)
			sum += size - high;
	}

	return sum;
}

/**
 * nr_free_buffer_pages - count number of pages beyond high watermark
 *
 * nr_free_buffer_pages() counts the number of pages which are beyond the high
 * watermark within ZONE_DMA and ZONE_NORMAL.
 */
unsigned long nr_free_buffer_pages(void)
{
	return nr_free_zone_pages(gfp_zone(GFP_USER));
}
EXPORT_SYMBOL_GPL(nr_free_buffer_pages);

/**
 * nr_free_pagecache_pages - count number of pages beyond high watermark
 *
 * nr_free_pagecache_pages() counts the number of pages which are beyond the
 * high watermark within all zones.
 */
/* 统计返回 所有 超出管理区设定的页框最大数量的页框量 */
unsigned long nr_free_pagecache_pages(void)
{
	return nr_free_zone_pages(gfp_zone(GFP_HIGHUSER_MOVABLE));
}

static inline void show_node(struct zone *zone)
{
	if (IS_ENABLED(CONFIG_NUMA))
		printk("Node %d ", zone_to_nid(zone));
}

void si_meminfo(struct sysinfo *val)
{
	val->totalram = totalram_pages;
	val->sharedram = global_page_state(NR_SHMEM);
	val->freeram = global_page_state(NR_FREE_PAGES);
	val->bufferram = nr_blockdev_pages();
	val->totalhigh = totalhigh_pages;
	val->freehigh = nr_free_highpages();
	val->mem_unit = PAGE_SIZE;
}

EXPORT_SYMBOL(si_meminfo);

#ifdef CONFIG_NUMA
void si_meminfo_node(struct sysinfo *val, int nid)
{
	int zone_type;		/* needs to be signed */
	unsigned long managed_pages = 0;
	pg_data_t *pgdat = NODE_DATA(nid);

	for (zone_type = 0; zone_type < MAX_NR_ZONES; zone_type++)
		managed_pages += pgdat->node_zones[zone_type].managed_pages;
	val->totalram = managed_pages;
	val->sharedram = node_page_state(nid, NR_SHMEM);
	val->freeram = node_page_state(nid, NR_FREE_PAGES);
#ifdef CONFIG_HIGHMEM
	val->totalhigh = pgdat->node_zones[ZONE_HIGHMEM].managed_pages;
	val->freehigh = zone_page_state(&pgdat->node_zones[ZONE_HIGHMEM],
			NR_FREE_PAGES);
#else
	val->totalhigh = 0;
	val->freehigh = 0;
#endif
	val->mem_unit = PAGE_SIZE;
}
#endif

/*
 * Determine whether the node should be displayed or not, depending on whether
 * SHOW_MEM_FILTER_NODES was passed to show_free_areas().
 */
bool skip_free_areas_node(unsigned int flags, int nid)
{
	bool ret = false;
	unsigned int cpuset_mems_cookie;

	if (!(flags & SHOW_MEM_FILTER_NODES))
		goto out;

	do {
		cpuset_mems_cookie = read_mems_allowed_begin();
		ret = !node_isset(nid, cpuset_current_mems_allowed);
	} while (read_mems_allowed_retry(cpuset_mems_cookie));
out:
	return ret;
}

#define K(x) ((x) << (PAGE_SHIFT-10))

static void show_migration_types(unsigned char type)
{
	static const char types[MIGRATE_TYPES] = {
		[MIGRATE_UNMOVABLE]	= 'U',
		[MIGRATE_RECLAIMABLE]	= 'E',
		[MIGRATE_MOVABLE]	= 'M',
		[MIGRATE_RESERVE]	= 'R',
#ifdef CONFIG_CMA
		[MIGRATE_CMA]		= 'C',
#endif
#ifdef CONFIG_MEMORY_ISOLATION
		[MIGRATE_ISOLATE]	= 'I',
#endif
	};
	char tmp[MIGRATE_TYPES + 1];
	char *p = tmp;
	int i;

	for (i = 0; i < MIGRATE_TYPES; i++) {
		if (type & (1 << i))
			*p++ = types[i];
	}

	*p = '\0';
	printk("(%s) ", tmp);
}

/*
 * Show free area list (used inside shift_scroll-lock stuff)
 * We also calculate the percentage fragmentation. We do this by counting the
 * memory on each free list with the exception of the first item on the list.
 * Suppresses nodes that are not allowed by current's cpuset if
 * SHOW_MEM_FILTER_NODES is passed.
 */
void show_free_areas(unsigned int filter)
{
	int cpu;
	struct zone *zone;

	for_each_populated_zone(zone) {
		if (skip_free_areas_node(filter, zone_to_nid(zone)))
			continue;
		show_node(zone);
		printk("%s per-cpu:\n", zone->name);

		for_each_online_cpu(cpu) {
			struct per_cpu_pageset *pageset;

			pageset = per_cpu_ptr(zone->pageset, cpu);

			printk("CPU %4d: hi:%5d, btch:%4d usd:%4d\n",
			       cpu, pageset->pcp.high,
			       pageset->pcp.batch, pageset->pcp.count);
		}
	}

	printk("active_anon:%lu inactive_anon:%lu isolated_anon:%lu\n"
		" active_file:%lu inactive_file:%lu isolated_file:%lu\n"
		" unevictable:%lu"
		" dirty:%lu writeback:%lu unstable:%lu\n"
		" free:%lu slab_reclaimable:%lu slab_unreclaimable:%lu\n"
		" mapped:%lu shmem:%lu pagetables:%lu bounce:%lu\n"
		" free_cma:%lu\n",
		global_page_state(NR_ACTIVE_ANON),
		global_page_state(NR_INACTIVE_ANON),
		global_page_state(NR_ISOLATED_ANON),
		global_page_state(NR_ACTIVE_FILE),
		global_page_state(NR_INACTIVE_FILE),
		global_page_state(NR_ISOLATED_FILE),
		global_page_state(NR_UNEVICTABLE),
		global_page_state(NR_FILE_DIRTY),
		global_page_state(NR_WRITEBACK),
		global_page_state(NR_UNSTABLE_NFS),
		global_page_state(NR_FREE_PAGES),
		global_page_state(NR_SLAB_RECLAIMABLE),
		global_page_state(NR_SLAB_UNRECLAIMABLE),
		global_page_state(NR_FILE_MAPPED),
		global_page_state(NR_SHMEM),
		global_page_state(NR_PAGETABLE),
		global_page_state(NR_BOUNCE),
		global_page_state(NR_FREE_CMA_PAGES));

	for_each_populated_zone(zone) {
		int i;

		if (skip_free_areas_node(filter, zone_to_nid(zone)))
			continue;
		show_node(zone);
		printk("%s"
			" free:%lukB"
			" min:%lukB"
			" low:%lukB"
			" high:%lukB"
			" active_anon:%lukB"
			" inactive_anon:%lukB"
			" active_file:%lukB"
			" inactive_file:%lukB"
			" unevictable:%lukB"
			" isolated(anon):%lukB"
			" isolated(file):%lukB"
			" present:%lukB"
			" managed:%lukB"
			" mlocked:%lukB"
			" dirty:%lukB"
			" writeback:%lukB"
			" mapped:%lukB"
			" shmem:%lukB"
			" slab_reclaimable:%lukB"
			" slab_unreclaimable:%lukB"
			" kernel_stack:%lukB"
			" pagetables:%lukB"
			" unstable:%lukB"
			" bounce:%lukB"
			" free_cma:%lukB"
			" writeback_tmp:%lukB"
			" pages_scanned:%lu"
			" all_unreclaimable? %s"
			"\n",
			zone->name,
			K(zone_page_state(zone, NR_FREE_PAGES)),
			K(min_wmark_pages(zone)),
			K(low_wmark_pages(zone)),
			K(high_wmark_pages(zone)),
			K(zone_page_state(zone, NR_ACTIVE_ANON)),
			K(zone_page_state(zone, NR_INACTIVE_ANON)),
			K(zone_page_state(zone, NR_ACTIVE_FILE)),
			K(zone_page_state(zone, NR_INACTIVE_FILE)),
			K(zone_page_state(zone, NR_UNEVICTABLE)),
			K(zone_page_state(zone, NR_ISOLATED_ANON)),
			K(zone_page_state(zone, NR_ISOLATED_FILE)),
			K(zone->present_pages),
			K(zone->managed_pages),
			K(zone_page_state(zone, NR_MLOCK)),
			K(zone_page_state(zone, NR_FILE_DIRTY)),
			K(zone_page_state(zone, NR_WRITEBACK)),
			K(zone_page_state(zone, NR_FILE_MAPPED)),
			K(zone_page_state(zone, NR_SHMEM)),
			K(zone_page_state(zone, NR_SLAB_RECLAIMABLE)),
			K(zone_page_state(zone, NR_SLAB_UNRECLAIMABLE)),
			zone_page_state(zone, NR_KERNEL_STACK) *
				THREAD_SIZE / 1024,
			K(zone_page_state(zone, NR_PAGETABLE)),
			K(zone_page_state(zone, NR_UNSTABLE_NFS)),
			K(zone_page_state(zone, NR_BOUNCE)),
			K(zone_page_state(zone, NR_FREE_CMA_PAGES)),
			K(zone_page_state(zone, NR_WRITEBACK_TEMP)),
			K(zone_page_state(zone, NR_PAGES_SCANNED)),
			(!zone_reclaimable(zone) ? "yes" : "no")
			);
		printk("lowmem_reserve[]:");
		for (i = 0; i < MAX_NR_ZONES; i++)
			printk(" %ld", zone->lowmem_reserve[i]);
		printk("\n");
	}

	for_each_populated_zone(zone) {
		unsigned long nr[MAX_ORDER], flags, order, total = 0;
		unsigned char types[MAX_ORDER];

		if (skip_free_areas_node(filter, zone_to_nid(zone)))
			continue;
		show_node(zone);
		printk("%s: ", zone->name);

		spin_lock_irqsave(&zone->lock, flags);
		for (order = 0; order < MAX_ORDER; order++) {
			struct free_area *area = &zone->free_area[order];
			int type;

			nr[order] = area->nr_free;
			total += nr[order] << order;

			types[order] = 0;
			for (type = 0; type < MIGRATE_TYPES; type++) {
				if (!list_empty(&area->free_list[type]))
					types[order] |= 1 << type;
			}
		}
		spin_unlock_irqrestore(&zone->lock, flags);
		for (order = 0; order < MAX_ORDER; order++) {
			printk("%lu*%lukB ", nr[order], K(1UL) << order);
			if (nr[order])
				show_migration_types(types[order]);
		}
		printk("= %lukB\n", K(total));
	}

	hugetlb_show_meminfo();

	printk("%ld total pagecache pages\n", global_page_state(NR_FILE_PAGES));

	show_swap_cache_info();
}

static void zoneref_set_zone(struct zone *zone, struct zoneref *zoneref)
{
	zoneref->zone = zone;
	zoneref->zone_idx = zone_idx(zone);
}

/*
 * Builds allocation fallback zone lists.
 *
 * Add all populated zones of a node to the zonelist.
 */
 
/* 建立pgdat的zonelist，返回zone的值
 * 正常情况下，zonelist->_zonerefs[0]是ZONE_MOVABLE
 * zonelist->_zonerefs[1]是ZONE_HIGHMEM
 * zonelist->_zonerefs[2]是ZONE_NORMAL
 * zonelist->_zonerefs[3]是ZONE_DMA
 */
static int build_zonelists_node(pg_data_t *pgdat, struct zonelist *zonelist,
				int nr_zones)
{
	struct zone *zone;
	/* zone_type = 5 */
	enum zone_type zone_type = MAX_NR_ZONES;

	do {
		zone_type--;
		zone = pgdat->node_zones + zone_type;
		/* 如果管理区总大小不为0(不包括洞) */
		if (populated_zone(zone)) {
			/* zonelist->_zonerefs[nr_zones]->zone = zone;
			 * zonelist->_zonerefs[nr_zones]->zone_idx = zone_idx(zone);
			 */
			zoneref_set_zone(zone,
				&zonelist->_zonerefs[nr_zones++]);
			check_highest_zone(zone_type);
		}
	} while (zone_type);

	return nr_zones;
}


/*
 *  zonelist_order:
 *  0 = automatic detection of better ordering.
 *  1 = order by ([node] distance, -zonetype)
 *  2 = order by (-zonetype, [node] distance)
 *
 *  If not NUMA, ZONELIST_ORDER_ZONE and ZONELIST_ORDER_NODE will create
 *  the same zonelist. So only NUMA can configure this param.
 */
#define ZONELIST_ORDER_DEFAULT  0
#define ZONELIST_ORDER_NODE     1
#define ZONELIST_ORDER_ZONE     2

/* zonelist order in the kernel.
 * set_zonelist_order() will set this to NODE or ZONE.
 */
static int current_zonelist_order = ZONELIST_ORDER_DEFAULT;
static char zonelist_order_name[3][8] = {"Default", "Node", "Zone"};


#ifdef CONFIG_NUMA
/* The value user specified ....changed by config */
static int user_zonelist_order = ZONELIST_ORDER_DEFAULT;
/* string for sysctl */
#define NUMA_ZONELIST_ORDER_LEN	16
char numa_zonelist_order[16] = "default";

/*
 * interface for configure zonelist ordering.
 * command line option "numa_zonelist_order"
 *	= "[dD]efault	- default, automatic configuration.
 *	= "[nN]ode 	- order by node locality, then by zone within node
 *	= "[zZ]one      - order by zone, then by locality within zone
 */

static int __parse_numa_zonelist_order(char *s)
{
	if (*s == 'd' || *s == 'D') {
		user_zonelist_order = ZONELIST_ORDER_DEFAULT;
	} else if (*s == 'n' || *s == 'N') {
		user_zonelist_order = ZONELIST_ORDER_NODE;
	} else if (*s == 'z' || *s == 'Z') {
		user_zonelist_order = ZONELIST_ORDER_ZONE;
	} else {
		printk(KERN_WARNING
			"Ignoring invalid numa_zonelist_order value:  "
			"%s\n", s);
		return -EINVAL;
	}
	return 0;
}

static __init int setup_numa_zonelist_order(char *s)
{
	int ret;

	if (!s)
		return 0;

	ret = __parse_numa_zonelist_order(s);
	if (ret == 0)
		strlcpy(numa_zonelist_order, s, NUMA_ZONELIST_ORDER_LEN);

	return ret;
}
early_param("numa_zonelist_order", setup_numa_zonelist_order);

/*
 * sysctl handler for numa_zonelist_order
 */
int numa_zonelist_order_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *length,
		loff_t *ppos)
{
	char saved_string[NUMA_ZONELIST_ORDER_LEN];
	int ret;
	static DEFINE_MUTEX(zl_order_mutex);

	mutex_lock(&zl_order_mutex);
	if (write) {
		if (strlen((char *)table->data) >= NUMA_ZONELIST_ORDER_LEN) {
			ret = -EINVAL;
			goto out;
		}
		strcpy(saved_string, (char *)table->data);
	}
	ret = proc_dostring(table, write, buffer, length, ppos);
	if (ret)
		goto out;
	if (write) {
		int oldval = user_zonelist_order;

		ret = __parse_numa_zonelist_order((char *)table->data);
		if (ret) {
			/*
			 * bogus value.  restore saved string
			 */
			strncpy((char *)table->data, saved_string,
				NUMA_ZONELIST_ORDER_LEN);
			user_zonelist_order = oldval;
		} else if (oldval != user_zonelist_order) {
			mutex_lock(&zonelists_mutex);
			build_all_zonelists(NULL, NULL);
			mutex_unlock(&zonelists_mutex);
		}
	}
out:
	mutex_unlock(&zl_order_mutex);
	return ret;
}


#define MAX_NODE_LOAD (nr_online_nodes)
static int node_load[MAX_NUMNODES];

/**
 * find_next_best_node - find the next node that should appear in a given node's fallback list
 * @node: node whose fallback list we're appending
 * @used_node_mask: nodemask_t of already used nodes
 *
 * We use a number of factors to determine which is the next node that should
 * appear on a given node's fallback list.  The node should not have appeared
 * already in @node's fallback list, and it should be the next closest node
 * according to the distance array (which contains arbitrary distance values
 * from each node to each node in the system), and should also prefer nodes
 * with no CPUs, since presumably they'll have very little allocation pressure
 * on them otherwise.
 * It returns -1 if no node is found.
 */
static int find_next_best_node(int node, nodemask_t *used_node_mask)
{
	int n, val;
	int min_val = INT_MAX;
	int best_node = NUMA_NO_NODE;
	const struct cpumask *tmp = cpumask_of_node(0);

	/* Use the local node if we haven't already */
	if (!node_isset(node, *used_node_mask)) {
		node_set(node, *used_node_mask);
		return node;
	}

	for_each_node_state(n, N_MEMORY) {

		/* Don't want a node to appear more than once */
		if (node_isset(n, *used_node_mask))
			continue;

		/* Use the distance array to find the distance */
		val = node_distance(node, n);

		/* Penalize nodes under us ("prefer the next node") */
		val += (n < node);

		/* Give preference to headless and unused nodes */
		tmp = cpumask_of_node(n);
		if (!cpumask_empty(tmp))
			val += PENALTY_FOR_NODE_WITH_CPUS;

		/* Slight preference for less loaded node */
		val *= (MAX_NODE_LOAD*MAX_NUMNODES);
		val += node_load[n];

		if (val < min_val) {
			min_val = val;
			best_node = n;
		}
	}

	if (best_node >= 0)
		node_set(best_node, *used_node_mask);

	return best_node;
}


/*
 * Build zonelists ordered by node and zones within node.
 * This results in maximum locality--normal zone overflows into local
 * DMA zone, if any--but risks exhausting DMA zone.
 */
static void build_zonelists_in_node_order(pg_data_t *pgdat, int node)
{
	int j;
	struct zonelist *zonelist;

	zonelist = &pgdat->node_zonelists[0];
	for (j = 0; zonelist->_zonerefs[j].zone != NULL; j++)
		;
	j = build_zonelists_node(NODE_DATA(node), zonelist, j);
	zonelist->_zonerefs[j].zone = NULL;
	zonelist->_zonerefs[j].zone_idx = 0;
}

/*
 * Build gfp_thisnode zonelists
 */
static void build_thisnode_zonelists(pg_data_t *pgdat)
{
	int j;
	struct zonelist *zonelist;

	zonelist = &pgdat->node_zonelists[1];
	j = build_zonelists_node(pgdat, zonelist, 0);
	zonelist->_zonerefs[j].zone = NULL;
	zonelist->_zonerefs[j].zone_idx = 0;
}

/*
 * Build zonelists ordered by zone and nodes within zones.
 * This results in conserving DMA zone[s] until all Normal memory is
 * exhausted, but results in overflowing to remote node while memory
 * may still exist in local DMA zone.
 */
static int node_order[MAX_NUMNODES];

static void build_zonelists_in_zone_order(pg_data_t *pgdat, int nr_nodes)
{
	int pos, j, node;
	int zone_type;		/* needs to be signed */
	struct zone *z;
	struct zonelist *zonelist;

	zonelist = &pgdat->node_zonelists[0];
	pos = 0;
	for (zone_type = MAX_NR_ZONES - 1; zone_type >= 0; zone_type--) {
		for (j = 0; j < nr_nodes; j++) {
			node = node_order[j];
			z = &NODE_DATA(node)->node_zones[zone_type];
			if (populated_zone(z)) {
				zoneref_set_zone(z,
					&zonelist->_zonerefs[pos++]);
				check_highest_zone(zone_type);
			}
		}
	}
	zonelist->_zonerefs[pos].zone = NULL;
	zonelist->_zonerefs[pos].zone_idx = 0;
}

#if defined(CONFIG_64BIT)
/*
 * Devices that require DMA32/DMA are relatively rare and do not justify a
 * penalty to every machine in case the specialised case applies. Default
 * to Node-ordering on 64-bit NUMA machines
 */
static int default_zonelist_order(void)
{
	return ZONELIST_ORDER_NODE;
}
#else
/*
 * On 32-bit, the Normal zone needs to be preserved for allocations accessible
 * by the kernel. If processes running on node 0 deplete the low memory zone
 * then reclaim will occur more frequency increasing stalls and potentially
 * be easier to OOM if a large percentage of the zone is under writeback or
 * dirty. The problem is significantly worse if CONFIG_HIGHPTE is not set.
 * Hence, default to zone ordering on 32-bit.
 */
static int default_zonelist_order(void)
{
	return ZONELIST_ORDER_ZONE;
}
#endif /* CONFIG_64BIT */

static void set_zonelist_order(void)
{
	if (user_zonelist_order == ZONELIST_ORDER_DEFAULT)
		current_zonelist_order = default_zonelist_order();
	else
		current_zonelist_order = user_zonelist_order;
}

/* 建立node的zonelist */
static void build_zonelists(pg_data_t *pgdat)
{
	int j, node, load;
	enum zone_type i;
	nodemask_t used_mask;
	int local_node, prev_node;
	struct zonelist *zonelist;
	int order = current_zonelist_order;

	/* initialize zonelists */
	/* 清空zonlist结构 */
	for (i = 0; i < MAX_ZONELISTS; i++) {
		zonelist = pgdat->node_zonelists + i;
		zonelist->_zonerefs[0].zone = NULL;
		zonelist->_zonerefs[0].zone_idx = 0;
	}

	/* NUMA-aware ordering of nodes */
	local_node = pgdat->node_id;
	load = nr_online_nodes;
	prev_node = local_node;
	nodes_clear(used_mask);

	memset(node_order, 0, sizeof(node_order));
	j = 0;

	while ((node = find_next_best_node(local_node, &used_mask)) >= 0) {
		/*
		 * We don't want to pressure a particular node.
		 * So adding penalty to the first node in same
		 * distance group to make it round-robin.
		 */
		if (node_distance(local_node, node) !=
		    node_distance(local_node, prev_node))
			node_load[node] = load;

		prev_node = node;
		load--;
		if (order == ZONELIST_ORDER_NODE)
			build_zonelists_in_node_order(pgdat, node);
		else
			node_order[j++] = node;	/* remember order */
	}

	if (order == ZONELIST_ORDER_ZONE) {
		/* calculate node order -- i.e., DMA last! */
		build_zonelists_in_zone_order(pgdat, j);
	}

	build_thisnode_zonelists(pgdat);
}

/* 初始化pgdat的pgdat->node_zonelists[0].zlcache结构中的z_to_n位图，主要保存 pgdat->node_zonelists[0]._zoneref 数组中各个zone的ID */
static void build_zonelist_cache(pg_data_t *pgdat)
{
	struct zonelist *zonelist;
	struct zonelist_cache *zlc;
	struct zoneref *z;

	zonelist = &pgdat->node_zonelists[0];
	zonelist->zlcache_ptr = zlc = &zonelist->zlcache;
	/* 清零zonelist->zlcache.fullzones这个位图 */
	bitmap_zero(zlc->fullzones, MAX_ZONES_PER_ZONELIST);
	for (z = zonelist->_zonerefs; z->zone; z++)
		/* 根据 pgdat->node_zonelists[0]._zonerefs 这里数组，依次将zone的ID保存到 pgdat->node_zonelists[0].zlcache.z_to_n 这个位图中 */
		zlc->z_to_n[z - zonelist->_zonerefs] = zonelist_node_idx(z);
}

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
/*
 * Return node id of node used for "local" allocations.
 * I.e., first node id of first zone in arg node's generic zonelist.
 * Used for initializing percpu 'numa_mem', which is used primarily
 * for kernel allocations, so use GFP_KERNEL flags to locate zonelist.
 */
int local_memory_node(int node)
{
	struct zone *zone;

	(void)first_zones_zonelist(node_zonelist(node, GFP_KERNEL),
				   gfp_zone(GFP_KERNEL),
				   NULL,
				   &zone);
	return zone->node;
}
#endif

#else	/* CONFIG_NUMA */

static void set_zonelist_order(void)
{
	current_zonelist_order = ZONELIST_ORDER_ZONE;
}

/* 建立pgdat描述的node的zonelists */
/* 最后建立结果是:
 *
 * pgdat->node_zonelists[0]._zonerefs[]       当前node的ZONE(MOVALBE,HIGHMEM,NORMAL,DMA)             排在此node之后的node的所有zone                       排在此node之前的node的所有zone
 *                                       |    _zonerefs[0]          ~      _zonerefs[3]     |     _zonerefs[4]         ~  _zonerefs[X]   |    _zonerefs[X + 1]           ~       _zonerefs[XX]       |
 *
 */
static void build_zonelists(pg_data_t *pgdat)
{
	int node, local_node;
	enum zone_type j;
	struct zonelist *zonelist;

	/* 获取node的ID */
	local_node = pgdat->node_id;

	/* 获取node的zonelist */
	zonelist = &pgdat->node_zonelists[0];
	/* 建立pgdat这个node内部自己的zonelist，j保存了这个node所包含的zone个数 */
	j = build_zonelists_node(pgdat, zonelist, 0);


	/* 遍历此node之后的node(以ID号为判断)，将之后的node的zone加入到当前node的zonelist中 */
	for (node = local_node + 1; node < MAX_NUMNODES; node++) {
		/* 如果当前node不在系统上，则继续下一个 */
		if (!node_online(node))
			continue;
		j = build_zonelists_node(NODE_DATA(node), zonelist, j);
	}
	/* 遍历此node之前的node(从ID为0的node开始)，将这些node的zone加入到当前node的zonelist中 */
	for (node = 0; node < local_node; node++) {
		/* 如果当前node不在系统上，则继续下一个 */
		if (!node_online(node))
			continue;
		j = build_zonelists_node(NODE_DATA(node), zonelist, j);
	}

	/* 设置末尾为空 */
	zonelist->_zonerefs[j].zone = NULL;
	zonelist->_zonerefs[j].zone_idx = 0;
}

/* non-NUMA variant of zonelist performance cache - just NULL zlcache_ptr */
static void build_zonelist_cache(pg_data_t *pgdat)
{
	pgdat->node_zonelists[0].zlcache_ptr = NULL;
}

#endif	/* CONFIG_NUMA */

/*
 * Boot pageset table. One per cpu which is going to be used for all
 * zones and all nodes. The parameters will be set in such a way
 * that an item put on a list will immediately be handed over to
 * the buddy list. This is safe since pageset manipulation is done
 * with interrupts disabled.
 *
 * The boot_pagesets must be kept even after bootup is complete for
 * unused processors and/or zones. They do play a role for bootstrapping
 * hotplugged processors.
 *
 * zoneinfo_show() and maybe other functions do
 * not check if the processor is online before following the pageset pointer.
 * Other parts of the kernel may not check if the zone is available.
 */
static void setup_pageset(struct per_cpu_pageset *p, unsigned long batch);
static DEFINE_PER_CPU(struct per_cpu_pageset, boot_pageset);
static void setup_zone_pageset(struct zone *zone);

/*
 * Global mutex to protect against size modification of zonelists
 * as well as to serialize pageset setup for the new populated zone.
 */
DEFINE_MUTEX(zonelists_mutex);

/* return values int ....just for stop_machine() */
/* 建立每个node的zonelist，将初始化阶段使用的每CPU页框高速缓存清空，之后不再使用 */
static int __build_all_zonelists(void *data)
{
	int nid;
	int cpu;
	pg_data_t *self = data;

#ifdef CONFIG_NUMA
	memset(node_load, 0, sizeof(node_load));
#endif
	/* 如果self不为空，并且self所表示的node不在系统上 */
	if (self && !node_online(self->node_id)) {
		/* 设置这个node的node_zonelists[0]表，这个链表用于保存有其他node区相对于此node的热度关系，当此node没有办法分配内存时，系统会根据这个表从最邻近的node分配内存 */
		build_zonelists(self);
		/* 初始化pgdat的pgdat->node_zonelists[0].zlcache结构中的z_to_n位图，主要保存 pgdat->node_zonelists[0]._zoneref 数组中各个zone的ID */
		build_zonelist_cache(self);
	}

	/* 遍历所有在系统上的node，初始化它们的 node_zonelists[0] 表和 node_zonelists[0].zlcache 结构中的z_to_n位图 */
	for_each_online_node(nid) {
		pg_data_t *pgdat = NODE_DATA(nid);

		build_zonelists(pgdat);
		build_zonelist_cache(pgdat);
	}

	/*
	 * Initialize the boot_pagesets that are going to be used
	 * for bootstrapping processors. The real pagesets for
	 * each zone will be allocated later when the per cpu
	 * allocator is available.
	 *
	 * boot_pagesets are used also for bootstrapping offline
	 * cpus if the system is already booted because the pagesets
	 * are needed to initialize allocators on a specific cpu too.
	 * F.e. the percpu allocator needs the page allocator which
	 * needs the percpu allocator in order to allocate its pagesets
	 * (a chicken-egg dilemma).
	 */
	/* 将初始化阶段使用的每CPU页框高速缓存清空，之后并不使用 */
	for_each_possible_cpu(cpu) {
		setup_pageset(&per_cpu(boot_pageset, cpu), 0);

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
		/*
		 * We now know the "local memory node" for each node--
		 * i.e., the node of the first zone in the generic zonelist.
		 * Set up numa_mem percpu variable for on-line cpus.  During
		 * boot, only the boot cpu should be on-line;  we'll init the
		 * secondary cpus' numa_mem as they come on-line.  During
		 * node/memory hotplug, we'll fixup all on-line cpus.
		 */
		/* 设置CPU所使用的node */
		if (cpu_online(cpu))
			set_cpu_numa_mem(cpu, local_memory_node(cpu_to_node(cpu)));
#endif
	}

	return 0;
}

/*
 * Called with zonelists_mutex held always
 * unless system_state == SYSTEM_BOOTING.
 */
/* 建立所有node的zonelist */
void __ref build_all_zonelists(pg_data_t *pgdat, struct zone *zone)
{
	/* 设置 current_zonelist_order 的值， */
	set_zonelist_order();

	if (system_state == SYSTEM_BOOTING) {
		/* 系统在引导阶段时做的处理 */
		/* 建立每个node的zonelist，将初始化阶段使用的每CPU页框高速缓存清空，之后不再使用 */
		__build_all_zonelists(NULL);
		/* 检查各个node的zonelist */
		mminit_verify_zonelist();
		/* 设置当前进程可以使用所有内存(当前进程为init)，设置current->mems_allowed这个位图 */
		cpuset_init_current_mems_allowed();
	} else {
		/* 系统在非引导阶段做的处理 */
		
#ifdef CONFIG_MEMORY_HOTPLUG
		/* 支持内存热插拔的情况下，重新设置这个管理区的每CPU页框高速缓存 */
		if (zone)
			setup_zone_pageset(zone);
#endif
		/* we have to stop all cpus to guarantee there is no user
		   of zonelist */
		/* 让单独一个CPU运行 __build_all_zonelists ，其他CPU暂停 */
		stop_machine(__build_all_zonelists, pgdat, NULL);
		/* cpuset refresh routine should be here */
	}
	/* 超出的页框数量(ALL_ZONE的managed_pages - ALL_ZONE设定的量) */
	vm_total_pages = nr_free_pagecache_pages();
	/*
	 * Disable grouping by mobility if the number of pages in the
	 * system is too low to allow the mechanism to work. It would be
	 * more accurate, but expensive to check per-zone. This check is
	 * made on memory-hotadd so a system can start with mobility
	 * disabled and enable it later
	 */
	/* vm_total_pages < 1024 * 5 */
	if (vm_total_pages < (pageblock_nr_pages * MIGRATE_TYPES))
		page_group_by_mobility_disabled = 1;
	else
		page_group_by_mobility_disabled = 0;

	printk("Built %i zonelists in %s order, mobility grouping %s.  "
		"Total pages: %ld\n",
			nr_online_nodes,
			zonelist_order_name[current_zonelist_order],
			page_group_by_mobility_disabled ? "off" : "on",
			vm_total_pages);
#ifdef CONFIG_NUMA
	printk("Policy zone: %s\n", zone_names[policy_zone]);
#endif
}

/*
 * Helper functions to size the waitqueue hash table.
 * Essentially these want to choose hash table sizes sufficiently
 * large so that collisions trying to wait on pages are rare.
 * But in fact, the number of active page waitqueues on typical
 * systems is ridiculously low, less than 200. So this is even
 * conservative, even though it seems large.
 *
 * The constant PAGES_PER_WAITQUEUE specifies the ratio of pages to
 * waitqueues, i.e. the size of the waitq table given the number of pages.
 */
#define PAGES_PER_WAITQUEUE	256

#ifndef CONFIG_MEMORY_HOTPLUG
static inline unsigned long wait_table_hash_nr_entries(unsigned long pages)
{
	unsigned long size = 1;

	pages /= PAGES_PER_WAITQUEUE;

	while (size < pages)
		size <<= 1;

	/*
	 * Once we have dozens or even hundreds of threads sleeping
	 * on IO we've got bigger problems than wait queue collision.
	 * Limit the size of the wait table to a reasonable size.
	 */
	size = min(size, 4096UL);

	return max(size, 4UL);
}
#else
/*
 * A zone's size might be changed by hot-add, so it is not possible to determine
 * a suitable size for its wait_table.  So we use the maximum size now.
 *
 * The max wait table size = 4096 x sizeof(wait_queue_head_t).   ie:
 *
 *    i386 (preemption config)    : 4096 x 16 = 64Kbyte.
 *    ia64, x86-64 (no preemption): 4096 x 20 = 80Kbyte.
 *    ia64, x86-64 (preemption)   : 4096 x 24 = 96Kbyte.
 *
 * The maximum entries are prepared when a zone's memory is (512K + 256) pages
 * or more by the traditional way. (See above).  It equals:
 *
 *    i386, x86-64, powerpc(4K page size) : =  ( 2G + 1M)byte.
 *    ia64(16K page size)                 : =  ( 8G + 4M)byte.
 *    powerpc (64K page size)             : =  (32G +16M)byte.
 */
static inline unsigned long wait_table_hash_nr_entries(unsigned long pages)
{
	return 4096UL;
}
#endif

/*
 * This is an integer logarithm so that shifts can be used later
 * to extract the more random high bits from the multiplicative
 * hash function before the remainder is taken.
 */
static inline unsigned long wait_table_bits(unsigned long size)
{
	return ffz(~size);
}

/*
 * Check if a pageblock contains reserved pages
 */
static int pageblock_is_reserved(unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long pfn;

	for (pfn = start_pfn; pfn < end_pfn; pfn++) {
		if (!pfn_valid_within(pfn) || PageReserved(pfn_to_page(pfn)))
			return 1;
	}
	return 0;
}

/*
 * Mark a number of pageblocks as MIGRATE_RESERVE. The number
 * of blocks reserved is based on min_wmark_pages(zone). The memory within
 * the reserve will tend to store contiguous free pages. Setting min_free_kbytes
 * higher will lead to a bigger reserve which will get freed as contiguous
 * blocks as reclaim kicks in
 */
static void setup_zone_migrate_reserve(struct zone *zone)
{
	unsigned long start_pfn, pfn, end_pfn, block_end_pfn;
	struct page *page;
	unsigned long block_migratetype;
	int reserve;
	int old_reserve;

	/*
	 * Get the start pfn, end pfn and the number of blocks to reserve
	 * We have to be careful to be aligned to pageblock_nr_pages to
	 * make sure that we always check pfn_valid for the first page in
	 * the block.
	 */
	start_pfn = zone->zone_start_pfn;
	end_pfn = zone_end_pfn(zone);
	start_pfn = roundup(start_pfn, pageblock_nr_pages);
	reserve = roundup(min_wmark_pages(zone), pageblock_nr_pages) >>
							pageblock_order;

	/*
	 * Reserve blocks are generally in place to help high-order atomic
	 * allocations that are short-lived. A min_free_kbytes value that
	 * would result in more than 2 reserve blocks for atomic allocations
	 * is assumed to be in place to help anti-fragmentation for the
	 * future allocation of hugepages at runtime.
	 */
	reserve = min(2, reserve);
	old_reserve = zone->nr_migrate_reserve_block;

	/* When memory hot-add, we almost always need to do nothing */
	if (reserve == old_reserve)
		return;
	zone->nr_migrate_reserve_block = reserve;

	for (pfn = start_pfn; pfn < end_pfn; pfn += pageblock_nr_pages) {
		if (!pfn_valid(pfn))
			continue;
		page = pfn_to_page(pfn);

		/* Watch out for overlapping nodes */
		if (page_to_nid(page) != zone_to_nid(zone))
			continue;

		block_migratetype = get_pageblock_migratetype(page);

		/* Only test what is necessary when the reserves are not met */
		if (reserve > 0) {
			/*
			 * Blocks with reserved pages will never free, skip
			 * them.
			 */
			block_end_pfn = min(pfn + pageblock_nr_pages, end_pfn);
			if (pageblock_is_reserved(pfn, block_end_pfn))
				continue;

			/* If this block is reserved, account for it */
			if (block_migratetype == MIGRATE_RESERVE) {
				reserve--;
				continue;
			}

			/* Suitable for reserving if this block is movable */
			if (block_migratetype == MIGRATE_MOVABLE) {
				set_pageblock_migratetype(page,
							MIGRATE_RESERVE);
				move_freepages_block(zone, page,
							MIGRATE_RESERVE);
				reserve--;
				continue;
			}
		} else if (!old_reserve) {
			/*
			 * At boot time we don't need to scan the whole zone
			 * for turning off MIGRATE_RESERVE.
			 */
			break;
		}

		/*
		 * If the reserve is met and this is a previous reserved block,
		 * take it back
		 */
		if (block_migratetype == MIGRATE_RESERVE) {
			set_pageblock_migratetype(page, MIGRATE_MOVABLE);
			move_freepages_block(zone, page, MIGRATE_MOVABLE);
		}
	}
}

/*
 * Initially all pages are reserved - free ones are freed
 * up by free_all_bootmem() once the early boot process is
 * done. Non-atomic initialization, single-pass.
 */
void __meminit memmap_init_zone(unsigned long size, int nid, unsigned long zone,
		unsigned long start_pfn, enum memmap_context context)
{
	struct page *page;
	unsigned long end_pfn = start_pfn + size;
	unsigned long pfn;
	struct zone *z;

	if (highest_memmap_pfn < end_pfn - 1)
		highest_memmap_pfn = end_pfn - 1;

	z = &NODE_DATA(nid)->node_zones[zone];
	for (pfn = start_pfn; pfn < end_pfn; pfn++) {
		/*
		 * There can be holes in boot-time mem_map[]s
		 * handed to this function.  They do not
		 * exist on hotplugged memory.
		 */
		if (context == MEMMAP_EARLY) {
			if (!early_pfn_valid(pfn))
				continue;
			if (!early_pfn_in_nid(pfn, nid))
				continue;
		}
		page = pfn_to_page(pfn);
		set_page_links(page, zone, nid, pfn);
		mminit_verify_page_links(page, zone, nid, pfn);
		init_page_count(page);
		page_mapcount_reset(page);
		page_cpupid_reset_last(page);
		SetPageReserved(page);
		/*
		 * Mark the block movable so that blocks are reserved for
		 * movable at startup. This will force kernel allocations
		 * to reserve their blocks rather than leaking throughout
		 * the address space during boot when many long-lived
		 * kernel allocations are made. Later some blocks near
		 * the start are marked MIGRATE_RESERVE by
		 * setup_zone_migrate_reserve()
		 *
		 * bitmap is created for zone's valid pfn range. but memmap
		 * can be created for invalid pages (for alignment)
		 * check here not to call set_pageblock_migratetype() against
		 * pfn out of zone.
		 */
		/* 该区所有页都设置为MIGRATE_MOVABLE */
		if ((z->zone_start_pfn <= pfn) && (pfn < zone_end_pfn(z)) && !(pfn & (pageblock_nr_pages - 1)))
			set_pageblock_migratetype(page, MIGRATE_MOVABLE);

		INIT_LIST_HEAD(&page->lru);
#ifdef WANT_PAGE_VIRTUAL
		/* The shift won't overflow because ZONE_NORMAL is below 4G. */
		/* 低端内存的虚拟地址 = 0xC0000000 + (pfn << PAGE_SHIFT) */
		if (!is_highmem_idx(zone))
			set_page_address(page, __va(pfn << PAGE_SHIFT));
#endif
	}
}

static void __meminit zone_init_free_lists(struct zone *zone)
{
	unsigned int order, t;
	for_each_migratetype_order(order, t) {
		INIT_LIST_HEAD(&zone->free_area[order].free_list[t]);
		zone->free_area[order].nr_free = 0;
	}
}

#ifndef __HAVE_ARCH_MEMMAP_INIT
#define memmap_init(size, nid, zone, start_pfn) \
	memmap_init_zone((size), (nid), (zone), (start_pfn), MEMMAP_EARLY)
#endif

/* 计算这个zone中batch的值 */
static int zone_batchsize(struct zone *zone)
{
#ifdef CONFIG_MMU
	int batch;

	/*
	 * The per-cpu-pages pools are set to around 1000th of the
	 * size of the zone.  But no more than 1/2 of a meg.
	 *
	 * OK, so we don't know how big the cache is.  So guess.
	 */
	/* batch最大是32个页框 */
	batch = zone->managed_pages / 1024;
	if (batch * PAGE_SIZE > 512 * 1024)
		batch = (512 * 1024) / PAGE_SIZE;
	batch /= 4;		/* We effectively *= 4 below */
	if (batch < 1)
		batch = 1;

	/*
	 * Clamp the batch to a 2^n - 1 value. Having a power
	 * of 2 value was found to be more likely to have
	 * suboptimal cache aliasing properties in some cases.
	 *
	 * For example if 2 tasks are alternately allocating
	 * batches of pages, one task can end up with a lot
	 * of pages of one half of the possible page colors
	 * and the other with pages of the other colors.
	 */
	batch = rounddown_pow_of_two(batch + batch/2) - 1;

	return batch;

#else
	/* The deferral and batching of frees should be suppressed under NOMMU
	 * conditions.
	 *
	 * The problem is that NOMMU needs to be able to allocate large chunks
	 * of contiguous memory as there's no hardware page translation to
	 * assemble apparent contiguous memory from discontiguous pages.
	 *
	 * Queueing large contiguous runs of pages for batching, however,
	 * causes the pages to actually be freed in smaller chunks.  As there
	 * can be a significant delay between the individual batches being
	 * recycled, this leads to the once large chunks of space being
	 * fragmented and becoming unavailable for high-order allocations.
	 */
	return 0;
#endif
}

/*
 * pcp->high and pcp->batch values are related and dependent on one another:
 * ->batch must never be higher then ->high.
 * The following function updates them in a safe manner without read side
 * locking.
 *
 * Any new users of pcp->batch and pcp->high should ensure they can cope with
 * those fields changing asynchronously (acording the the above rule).
 *
 * mutex_is_locked(&pcp_batch_high_lock) required when calling this function
 * outside of boot time (or some other assurance that no concurrent updaters
 * exist).
 */
static void pageset_update(struct per_cpu_pages *pcp, unsigned long high,
		unsigned long batch)
{
       /* start with a fail safe value for batch */
	pcp->batch = 1;
	smp_wmb();

       /* Update high, then batch, in order */
	pcp->high = high;
	smp_wmb();

	pcp->batch = batch;
}

/* a companion to pageset_set_high() */
static void pageset_set_batch(struct per_cpu_pageset *p, unsigned long batch)
{
	pageset_update(&p->pcp, 6 * batch, max(1UL, 1 * batch));
}

/* 初始化每CPU页框高速缓存 */
static void pageset_init(struct per_cpu_pageset *p)
{
	struct per_cpu_pages *pcp;
	int migratetype;

	/* 结构体清零 */
	memset(p, 0, sizeof(*p));

	pcp = &p->pcp;
	/* 页框数量为0 */
	pcp->count = 0;
	/* 初始化各个链的链表头 */
	for (migratetype = 0; migratetype < MIGRATE_PCPTYPES; migratetype++)
		INIT_LIST_HEAD(&pcp->lists[migratetype]);
}

static void setup_pageset(struct per_cpu_pageset *p, unsigned long batch)
{
	/* 初始化每CPU页框高速缓存，初始化各个链的链表头及设置页框数量为0 */
	pageset_init(p);
	pageset_set_batch(p, batch);
}

/*
 * pageset_set_high() sets the high water mark for hot per_cpu_pagelist
 * to the value high for the pageset p.
 */
static void pageset_set_high(struct per_cpu_pageset *p,
				unsigned long high)
{
	unsigned long batch = max(1UL, high / 4);
	if ((high / 4) > (PAGE_SHIFT * 8))
		batch = PAGE_SHIFT * 8;

	pageset_update(&p->pcp, high, batch);
}

/* 根据zone描述符设置每CPU页框高速缓存中high和batch的值 */
static void pageset_set_high_and_batch(struct zone *zone,
				       struct per_cpu_pageset *pcp)
{
	if (percpu_pagelist_fraction)
		pageset_set_high(pcp,
			(zone->managed_pages /
				percpu_pagelist_fraction));
	else
		pageset_set_batch(pcp, zone_batchsize(zone));
}

static void __meminit zone_pageset_init(struct zone *zone, int cpu)
{
	struct per_cpu_pageset *pcp = per_cpu_ptr(zone->pageset, cpu);

	pageset_init(pcp);
	pageset_set_high_and_batch(zone, pcp);
}

/* 为当前zone的每CPU页框高速缓存描述符分配空间，并设置当中的几个类型的链表为空以及batch和high */
static void __meminit setup_zone_pageset(struct zone *zone)
{
	int cpu;
	/* 为当前zone的每CPU页框高速缓存描述符分配空间 */
	zone->pageset = alloc_percpu(struct per_cpu_pageset);
	for_each_possible_cpu(cpu)
		zone_pageset_init(zone, cpu);
}

/*
 * Allocate per cpu pagesets and initialize them.
 * Before this call only boot pagesets were available.
 */
void __init setup_per_cpu_pageset(void)
{
	struct zone *zone;

	for_each_populated_zone(zone)
		setup_zone_pageset(zone);
}

static noinline __init_refok
int zone_wait_table_init(struct zone *zone, unsigned long zone_size_pages)
{
	int i;
	size_t alloc_size;

	/*
	 * The per-page waitqueue mechanism uses hashed waitqueues
	 * per zone.
	 */
	zone->wait_table_hash_nr_entries =
		 wait_table_hash_nr_entries(zone_size_pages);
	zone->wait_table_bits =
		wait_table_bits(zone->wait_table_hash_nr_entries);
	alloc_size = zone->wait_table_hash_nr_entries
					* sizeof(wait_queue_head_t);

	if (!slab_is_available()) {
		zone->wait_table = (wait_queue_head_t *)
			memblock_virt_alloc_node_nopanic(
				alloc_size, zone->zone_pgdat->node_id);
	} else {
		/*
		 * This case means that a zone whose size was 0 gets new memory
		 * via memory hot-add.
		 * But it may be the case that a new node was hot-added.  In
		 * this case vmalloc() will not be able to use this new node's
		 * memory - this wait_table must be initialized to use this new
		 * node itself as well.
		 * To use this new node's memory, further consideration will be
		 * necessary.
		 */
		zone->wait_table = vmalloc(alloc_size);
	}
	if (!zone->wait_table)
		return -ENOMEM;

	for (i = 0; i < zone->wait_table_hash_nr_entries; ++i)
		init_waitqueue_head(zone->wait_table + i);

	return 0;
}

static __meminit void zone_pcp_init(struct zone *zone)
{
	/*
	 * per cpu subsystem is not up at this point. The following code
	 * relies on the ability of the linker to provide the
	 * offset of a (static) per cpu variable into the per cpu area.
	 */
	zone->pageset = &boot_pageset;

	if (populated_zone(zone))
		printk(KERN_DEBUG "  %s zone: %lu pages, LIFO batch:%u\n",
			zone->name, zone->present_pages,
					 zone_batchsize(zone));
}

int __meminit init_currently_empty_zone(struct zone *zone,
					unsigned long zone_start_pfn,
					unsigned long size,
					enum memmap_context context)
{
	struct pglist_data *pgdat = zone->zone_pgdat;
	int ret;
	ret = zone_wait_table_init(zone, size);
	if (ret)
		return ret;
	pgdat->nr_zones = zone_idx(zone) + 1;

	zone->zone_start_pfn = zone_start_pfn;

	mminit_dprintk(MMINIT_TRACE, "memmap_init",
			"Initialising map node %d zone %lu pfns %lu -> %lu\n",
			pgdat->node_id,
			(unsigned long)zone_idx(zone),
			zone_start_pfn, (zone_start_pfn + size));

	zone_init_free_lists(zone);

	return 0;
}

#ifdef CONFIG_HAVE_MEMBLOCK_NODE_MAP
#ifndef CONFIG_HAVE_ARCH_EARLY_PFN_TO_NID
/*
 * Required by SPARSEMEM. Given a PFN, return what node the PFN is on.
 */
int __meminit __early_pfn_to_nid(unsigned long pfn)
{
	unsigned long start_pfn, end_pfn;
	int nid;
	/*
	 * NOTE: The following SMP-unsafe globals are only used early in boot
	 * when the kernel is running single-threaded.
	 */
	static unsigned long __meminitdata last_start_pfn, last_end_pfn;
	static int __meminitdata last_nid;

	if (last_start_pfn <= pfn && pfn < last_end_pfn)
		return last_nid;

	nid = memblock_search_pfn_nid(pfn, &start_pfn, &end_pfn);
	if (nid != -1) {
		last_start_pfn = start_pfn;
		last_end_pfn = end_pfn;
		last_nid = nid;
	}

	return nid;
}
#endif /* CONFIG_HAVE_ARCH_EARLY_PFN_TO_NID */

int __meminit early_pfn_to_nid(unsigned long pfn)
{
	int nid;

	nid = __early_pfn_to_nid(pfn);
	if (nid >= 0)
		return nid;
	/* just returns 0 */
	return 0;
}

#ifdef CONFIG_NODES_SPAN_OTHER_NODES
bool __meminit early_pfn_in_nid(unsigned long pfn, int node)
{
	int nid;

	nid = __early_pfn_to_nid(pfn);
	if (nid >= 0 && nid != node)
		return false;
	return true;
}
#endif

/**
 * free_bootmem_with_active_regions - Call memblock_free_early_nid for each active range
 * @nid: The node to free memory on. If MAX_NUMNODES, all nodes are freed.
 * @max_low_pfn: The highest PFN that will be passed to memblock_free_early_nid
 *
 * If an architecture guarantees that all ranges registered contain no holes
 * and may be freed, this this function may be used instead of calling
 * memblock_free_early_nid() manually.
 */
void __init free_bootmem_with_active_regions(int nid, unsigned long max_low_pfn)
{
	unsigned long start_pfn, end_pfn;
	int i, this_nid;

	for_each_mem_pfn_range(i, nid, &start_pfn, &end_pfn, &this_nid) {
		start_pfn = min(start_pfn, max_low_pfn);
		end_pfn = min(end_pfn, max_low_pfn);

		if (start_pfn < end_pfn)
			memblock_free_early_nid(PFN_PHYS(start_pfn),
					(end_pfn - start_pfn) << PAGE_SHIFT,
					this_nid);
	}
}

/**
 * sparse_memory_present_with_active_regions - Call memory_present for each active range
 * @nid: The node to call memory_present for. If MAX_NUMNODES, all nodes will be used.
 *
 * If an architecture guarantees that all ranges registered contain no holes and may
 * be freed, this function may be used instead of calling memory_present() manually.
 */
void __init sparse_memory_present_with_active_regions(int nid)
{
	unsigned long start_pfn, end_pfn;
	int i, this_nid;

	for_each_mem_pfn_range(i, nid, &start_pfn, &end_pfn, &this_nid)
		memory_present(this_nid, start_pfn, end_pfn);
}

/**
 * get_pfn_range_for_nid - Return the start and end page frames for a node
 * @nid: The nid to return the range for. If MAX_NUMNODES, the min and max PFN are returned.
 * @start_pfn: Passed by reference. On return, it will have the node start_pfn.
 * @end_pfn: Passed by reference. On return, it will have the node end_pfn.
 *
 * It returns the start and end page frame of a node based on information
 * provided by memblock_set_node(). If called for a node
 * with no available memory, a warning is printed and the start and end
 * PFNs will be 0.
 */
void __meminit get_pfn_range_for_nid(unsigned int nid,
			unsigned long *start_pfn, unsigned long *end_pfn)
{
	unsigned long this_start_pfn, this_end_pfn;
	int i;

	*start_pfn = -1UL;
	*end_pfn = 0;

	for_each_mem_pfn_range(i, nid, &this_start_pfn, &this_end_pfn, NULL) {
		*start_pfn = min(*start_pfn, this_start_pfn);
		*end_pfn = max(*end_pfn, this_end_pfn);
	}

	if (*start_pfn == -1UL)
		*start_pfn = 0;
}

/*
 * This finds a zone that can be used for ZONE_MOVABLE pages. The
 * assumption is made that zones within a node are ordered in monotonic
 * increasing memory addresses so that the "highest" populated zone is used
 */
/* 以ZONE ID 从大往小数第一个包含多个页框的管理区为movable_zone */
static void __init find_usable_zone_for_movable(void)
{
	int zone_index;
	for (zone_index = MAX_NR_ZONES - 1; zone_index >= 0; zone_index--) {
		if (zone_index == ZONE_MOVABLE)
			continue;

		if (arch_zone_highest_possible_pfn[zone_index] >
				arch_zone_lowest_possible_pfn[zone_index])
			break;
	}

	VM_BUG_ON(zone_index == -1);
	movable_zone = zone_index;
}

/*
 * The zone ranges provided by the architecture do not include ZONE_MOVABLE
 * because it is sized independent of architecture. Unlike the other zones,
 * the starting point for ZONE_MOVABLE is not fixed. It may be different
 * in each node depending on the size of each node and how evenly kernelcore
 * is distributed. This helper function adjusts the zone ranges
 * provided by the architecture for a given node by using the end of the
 * highest usable zone for ZONE_MOVABLE. This preserves the assumption that
 * zones within a node are in order of monotonic increases memory addresses
 */
static void __meminit adjust_zone_range_for_zone_movable(int nid,
					unsigned long zone_type,
					unsigned long node_start_pfn,
					unsigned long node_end_pfn,
					unsigned long *zone_start_pfn,
					unsigned long *zone_end_pfn)
{
	/* Only adjust if ZONE_MOVABLE is on this node */
	if (zone_movable_pfn[nid]) {
		/* Size ZONE_MOVABLE */
		if (zone_type == ZONE_MOVABLE) {
			*zone_start_pfn = zone_movable_pfn[nid];
			*zone_end_pfn = min(node_end_pfn,
				arch_zone_highest_possible_pfn[movable_zone]);

		/* Adjust for ZONE_MOVABLE starting within this range */
		} else if (*zone_start_pfn < zone_movable_pfn[nid] &&
				*zone_end_pfn > zone_movable_pfn[nid]) {
			*zone_end_pfn = zone_movable_pfn[nid];

		/* Check if this whole range is within ZONE_MOVABLE */
		} else if (*zone_start_pfn >= zone_movable_pfn[nid])
			*zone_start_pfn = *zone_end_pfn;
	}
}

/*
 * Return the number of pages a zone spans in a node, including holes
 * present_pages = zone_spanned_pages_in_node() - zone_absent_pages_in_node()
 */
static unsigned long __meminit zone_spanned_pages_in_node(int nid,
					unsigned long zone_type,
					unsigned long node_start_pfn,
					unsigned long node_end_pfn,
					unsigned long *ignored)
{
	unsigned long zone_start_pfn, zone_end_pfn;

	/* Get the start and end of the zone */
	zone_start_pfn = arch_zone_lowest_possible_pfn[zone_type];
	zone_end_pfn = arch_zone_highest_possible_pfn[zone_type];
	adjust_zone_range_for_zone_movable(nid, zone_type,
				node_start_pfn, node_end_pfn,
				&zone_start_pfn, &zone_end_pfn);

	/* Check that this node has pages within the zone's required range */
	if (zone_end_pfn < node_start_pfn || zone_start_pfn > node_end_pfn)
		return 0;

	/* Move the zone boundaries inside the node if necessary */
	zone_end_pfn = min(zone_end_pfn, node_end_pfn);
	zone_start_pfn = max(zone_start_pfn, node_start_pfn);

	/* Return the spanned pages */
	return zone_end_pfn - zone_start_pfn;
}

/*
 * Return the number of holes in a range on a node. If nid is MAX_NUMNODES,
 * then all holes in the requested range will be accounted for.
 */
unsigned long __meminit __absent_pages_in_range(int nid,
				unsigned long range_start_pfn,
				unsigned long range_end_pfn)
{
	unsigned long nr_absent = range_end_pfn - range_start_pfn;
	unsigned long start_pfn, end_pfn;
	int i;

	for_each_mem_pfn_range(i, nid, &start_pfn, &end_pfn, NULL) {
		start_pfn = clamp(start_pfn, range_start_pfn, range_end_pfn);
		end_pfn = clamp(end_pfn, range_start_pfn, range_end_pfn);
		nr_absent -= end_pfn - start_pfn;
	}
	return nr_absent;
}

/**
 * absent_pages_in_range - Return number of page frames in holes within a range
 * @start_pfn: The start PFN to start searching for holes
 * @end_pfn: The end PFN to stop searching for holes
 *
 * It returns the number of pages frames in memory holes within a range.
 */
unsigned long __init absent_pages_in_range(unsigned long start_pfn,
							unsigned long end_pfn)
{
	return __absent_pages_in_range(MAX_NUMNODES, start_pfn, end_pfn);
}

/* Return the number of page frames in holes in a zone on a node */
static unsigned long __meminit zone_absent_pages_in_node(int nid,
					unsigned long zone_type,
					unsigned long node_start_pfn,
					unsigned long node_end_pfn,
					unsigned long *ignored)
{
	unsigned long zone_low = arch_zone_lowest_possible_pfn[zone_type];
	unsigned long zone_high = arch_zone_highest_possible_pfn[zone_type];
	unsigned long zone_start_pfn, zone_end_pfn;

	zone_start_pfn = clamp(node_start_pfn, zone_low, zone_high);
	zone_end_pfn = clamp(node_end_pfn, zone_low, zone_high);

	adjust_zone_range_for_zone_movable(nid, zone_type,
			node_start_pfn, node_end_pfn,
			&zone_start_pfn, &zone_end_pfn);
	return __absent_pages_in_range(nid, zone_start_pfn, zone_end_pfn);
}

#else /* CONFIG_HAVE_MEMBLOCK_NODE_MAP */
static inline unsigned long __meminit zone_spanned_pages_in_node(int nid,
					unsigned long zone_type,
					unsigned long node_start_pfn,
					unsigned long node_end_pfn,
					unsigned long *zones_size)
{
	return zones_size[zone_type];
}

static inline unsigned long __meminit zone_absent_pages_in_node(int nid,
						unsigned long zone_type,
						unsigned long node_start_pfn,
						unsigned long node_end_pfn,
						unsigned long *zholes_size)
{
	if (!zholes_size)
		return 0;

	return zholes_size[zone_type];
}

#endif /* CONFIG_HAVE_MEMBLOCK_NODE_MAP */

static void __meminit calculate_node_totalpages(struct pglist_data *pgdat,
						unsigned long node_start_pfn,
						unsigned long node_end_pfn,
						unsigned long *zones_size,
						unsigned long *zholes_size)
{
	unsigned long realtotalpages, totalpages = 0;
	enum zone_type i;

	for (i = 0; i < MAX_NR_ZONES; i++)
		totalpages += zone_spanned_pages_in_node(pgdat->node_id, i,
							 node_start_pfn,
							 node_end_pfn,
							 zones_size);
	pgdat->node_spanned_pages = totalpages;

	realtotalpages = totalpages;
	for (i = 0; i < MAX_NR_ZONES; i++)
		realtotalpages -=
			zone_absent_pages_in_node(pgdat->node_id, i,
						  node_start_pfn, node_end_pfn,
						  zholes_size);
	pgdat->node_present_pages = realtotalpages;
	printk(KERN_DEBUG "On node %d totalpages: %lu\n", pgdat->node_id,
							realtotalpages);
}

#ifndef CONFIG_SPARSEMEM
/*
 * Calculate the size of the zone->blockflags rounded to an unsigned long
 * Start by making sure zonesize is a multiple of pageblock_order by rounding
 * up. Then use 1 NR_PAGEBLOCK_BITS worth of bits per pageblock, finally
 * round what is now in bits to nearest long in bits, then return it in
 * bytes.
 */
static unsigned long __init usemap_size(unsigned long zone_start_pfn, unsigned long zonesize)
{
	unsigned long usemapsize;

	zonesize += zone_start_pfn & (pageblock_nr_pages-1);
	usemapsize = roundup(zonesize, pageblock_nr_pages);
	usemapsize = usemapsize >> pageblock_order;
	usemapsize *= NR_PAGEBLOCK_BITS;
	usemapsize = roundup(usemapsize, 8 * sizeof(unsigned long));

	return usemapsize / 8;
}

static void __init setup_usemap(struct pglist_data *pgdat,
				struct zone *zone,
				unsigned long zone_start_pfn,
				unsigned long zonesize)
{
	unsigned long usemapsize = usemap_size(zone_start_pfn, zonesize);
	zone->pageblock_flags = NULL;
	if (usemapsize)
		zone->pageblock_flags =
			memblock_virt_alloc_node_nopanic(usemapsize,
							 pgdat->node_id);
}
#else
static inline void setup_usemap(struct pglist_data *pgdat, struct zone *zone,
				unsigned long zone_start_pfn, unsigned long zonesize) {}
#endif /* CONFIG_SPARSEMEM */

#ifdef CONFIG_HUGETLB_PAGE_SIZE_VARIABLE

/* Initialise the number of pages represented by NR_PAGEBLOCK_BITS */
void __paginginit set_pageblock_order(void)
{
	unsigned int order;

	/* Check that pageblock_nr_pages has not already been setup */
	if (pageblock_order)
		return;

	if (HPAGE_SHIFT > PAGE_SHIFT)
		order = HUGETLB_PAGE_ORDER;
	else
		order = MAX_ORDER - 1;

	/*
	 * Assume the largest contiguous order of interest is a huge page.
	 * This value may be variable depending on boot parameters on IA64 and
	 * powerpc.
	 */
	pageblock_order = order;
}
#else /* CONFIG_HUGETLB_PAGE_SIZE_VARIABLE */

/*
 * When CONFIG_HUGETLB_PAGE_SIZE_VARIABLE is not set, set_pageblock_order()
 * is unused as pageblock_order is set at compile-time. See
 * include/linux/pageblock-flags.h for the values of pageblock_order based on
 * the kernel config
 */
void __paginginit set_pageblock_order(void)
{
}

#endif /* CONFIG_HUGETLB_PAGE_SIZE_VARIABLE */

static unsigned long __paginginit calc_memmap_size(unsigned long spanned_pages,
						   unsigned long present_pages)
{
	unsigned long pages = spanned_pages;

	/*
	 * Provide a more accurate estimation if there are holes within
	 * the zone and SPARSEMEM is in use. If there are holes within the
	 * zone, each populated memory region may cost us one or two extra
	 * memmap pages due to alignment because memmap pages for each
	 * populated regions may not naturally algined on page boundary.
	 * So the (present_pages >> 4) heuristic is a tradeoff for that.
	 */
	if (spanned_pages > present_pages + (present_pages >> 4) &&
	    IS_ENABLED(CONFIG_SPARSEMEM))
		pages = present_pages;

	return PAGE_ALIGN(pages * sizeof(struct page)) >> PAGE_SHIFT;
}

/*
 * Set up the zone data structures:
 *   - mark all pages reserved
 *   - mark all memory queues empty
 *   - clear the memory bitmaps
 *
 * NOTE: pgdat should get zeroed by caller.
 */
static void __paginginit free_area_init_core(struct pglist_data *pgdat,
		unsigned long node_start_pfn, unsigned long node_end_pfn,
		unsigned long *zones_size, unsigned long *zholes_size)
{
	enum zone_type j;
	int nid = pgdat->node_id;
	unsigned long zone_start_pfn = pgdat->node_start_pfn;
	int ret;

	pgdat_resize_init(pgdat);
#ifdef CONFIG_NUMA_BALANCING
	spin_lock_init(&pgdat->numabalancing_migrate_lock);
	pgdat->numabalancing_migrate_nr_pages = 0;
	pgdat->numabalancing_migrate_next_window = jiffies;
#endif
	init_waitqueue_head(&pgdat->kswapd_wait);
	init_waitqueue_head(&pgdat->pfmemalloc_wait);
	pgdat_page_cgroup_init(pgdat);

	for (j = 0; j < MAX_NR_ZONES; j++) {
		struct zone *zone = pgdat->node_zones + j;
		unsigned long size, realsize, freesize, memmap_pages;

		size = zone_spanned_pages_in_node(nid, j, node_start_pfn,
						  node_end_pfn, zones_size);
		realsize = freesize = size - zone_absent_pages_in_node(nid, j,
								node_start_pfn,
								node_end_pfn,
								zholes_size);

		/*
		 * Adjust freesize so that it accounts for how much memory
		 * is used by this zone for memmap. This affects the watermark
		 * and per-cpu initialisations
		 */
		memmap_pages = calc_memmap_size(size, realsize);
		if (freesize >= memmap_pages) {
			freesize -= memmap_pages;
			if (memmap_pages)
				printk(KERN_DEBUG
				       "  %s zone: %lu pages used for memmap\n",
				       zone_names[j], memmap_pages);
		} else
			printk(KERN_WARNING
				"  %s zone: %lu pages exceeds freesize %lu\n",
				zone_names[j], memmap_pages, freesize);

		/* Account for reserved pages */
		if (j == 0 && freesize > dma_reserve) {
			freesize -= dma_reserve;
			printk(KERN_DEBUG "  %s zone: %lu pages reserved\n",
					zone_names[0], dma_reserve);
		}

		if (!is_highmem_idx(j))
			nr_kernel_pages += freesize;
		/* Charge for highmem memmap if there are enough kernel pages */
		else if (nr_kernel_pages > memmap_pages * 2)
			nr_kernel_pages -= memmap_pages;
		nr_all_pages += freesize;

		zone->spanned_pages = size;
		zone->present_pages = realsize;
		/*
		 * Set an approximate value for lowmem here, it will be adjusted
		 * when the bootmem allocator frees pages into the buddy system.
		 * And all highmem pages will be managed by the buddy system.
		 */
		zone->managed_pages = is_highmem_idx(j) ? realsize : freesize;
#ifdef CONFIG_NUMA
		zone->node = nid;
		zone->min_unmapped_pages = (freesize*sysctl_min_unmapped_ratio)
						/ 100;
		zone->min_slab_pages = (freesize * sysctl_min_slab_ratio) / 100;
#endif
		zone->name = zone_names[j];
		spin_lock_init(&zone->lock);
		spin_lock_init(&zone->lru_lock);
		zone_seqlock_init(zone);
		zone->zone_pgdat = pgdat;
		zone_pcp_init(zone);

		/* For bootup, initialized properly in watermark setup */
		mod_zone_page_state(zone, NR_ALLOC_BATCH, zone->managed_pages);

		lruvec_init(&zone->lruvec);
		if (!size)
			continue;

		set_pageblock_order();
		setup_usemap(pgdat, zone, zone_start_pfn, size);
		ret = init_currently_empty_zone(zone, zone_start_pfn,
						size, MEMMAP_EARLY);
		BUG_ON(ret);
		/* 初始化这个管理区中的所有页描述符 */
		memmap_init(size, nid, j, zone_start_pfn);
		zone_start_pfn += size;
	}
}

static void __init_refok alloc_node_mem_map(struct pglist_data *pgdat)
{
	/* Skip empty nodes */
	if (!pgdat->node_spanned_pages)
		return;

#ifdef CONFIG_FLAT_NODE_MEM_MAP
	/* ia64 gets its own node_mem_map, before this, without bootmem */
	if (!pgdat->node_mem_map) {
		unsigned long size, start, end;
		struct page *map;

		/*
		 * The zone's endpoints aren't required to be MAX_ORDER
		 * aligned but the node_mem_map endpoints must be in order
		 * for the buddy allocator to function correctly.
		 */
		start = pgdat->node_start_pfn & ~(MAX_ORDER_NR_PAGES - 1);
		end = pgdat_end_pfn(pgdat);
		end = ALIGN(end, MAX_ORDER_NR_PAGES);
		size =  (end - start) * sizeof(struct page);
		map = alloc_remap(pgdat->node_id, size);
		if (!map)
			map = memblock_virt_alloc_node_nopanic(size,
							       pgdat->node_id);
		pgdat->node_mem_map = map + (pgdat->node_start_pfn - start);
	}
#ifndef CONFIG_NEED_MULTIPLE_NODES
	/*
	 * With no DISCONTIG, the global mem_map is just set as node 0's
	 */
	if (pgdat == NODE_DATA(0)) {
		mem_map = NODE_DATA(0)->node_mem_map;
#ifdef CONFIG_HAVE_MEMBLOCK_NODE_MAP
		if (page_to_pfn(mem_map) != pgdat->node_start_pfn)
			mem_map -= (pgdat->node_start_pfn - ARCH_PFN_OFFSET);
#endif /* CONFIG_HAVE_MEMBLOCK_NODE_MAP */
	}
#endif
#endif /* CONFIG_FLAT_NODE_MEM_MAP */
}

void __paginginit free_area_init_node(int nid, unsigned long *zones_size,
		unsigned long node_start_pfn, unsigned long *zholes_size)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	unsigned long start_pfn = 0;
	unsigned long end_pfn = 0;

	/* pg_data_t should be reset to zero when it's allocated */
	WARN_ON(pgdat->nr_zones || pgdat->classzone_idx);

	pgdat->node_id = nid;
	pgdat->node_start_pfn = node_start_pfn;
#ifdef CONFIG_HAVE_MEMBLOCK_NODE_MAP
	get_pfn_range_for_nid(nid, &start_pfn, &end_pfn);
	printk(KERN_INFO "Initmem setup node %d [mem %#010Lx-%#010Lx]\n", nid,
			(u64) start_pfn << PAGE_SHIFT, (u64) (end_pfn << PAGE_SHIFT) - 1);
#endif
	calculate_node_totalpages(pgdat, start_pfn, end_pfn,
				  zones_size, zholes_size);

	alloc_node_mem_map(pgdat);
#ifdef CONFIG_FLAT_NODE_MEM_MAP
	printk(KERN_DEBUG "free_area_init_node: node %d, pgdat %08lx, node_mem_map %08lx\n",
		nid, (unsigned long)pgdat,
		(unsigned long)pgdat->node_mem_map);
#endif

	free_area_init_core(pgdat, start_pfn, end_pfn,
			    zones_size, zholes_size);
}

#ifdef CONFIG_HAVE_MEMBLOCK_NODE_MAP

#if MAX_NUMNODES > 1
/*
 * Figure out the number of possible node ids.
 */
void __init setup_nr_node_ids(void)
{
	unsigned int node;
	unsigned int highest = 0;

	for_each_node_mask(node, node_possible_map)
		highest = node;
	nr_node_ids = highest + 1;
}
#endif

/**
 * node_map_pfn_alignment - determine the maximum internode alignment
 *
 * This function should be called after node map is populated and sorted.
 * It calculates the maximum power of two alignment which can distinguish
 * all the nodes.
 *
 * For example, if all nodes are 1GiB and aligned to 1GiB, the return value
 * would indicate 1GiB alignment with (1 << (30 - PAGE_SHIFT)).  If the
 * nodes are shifted by 256MiB, 256MiB.  Note that if only the last node is
 * shifted, 1GiB is enough and this function will indicate so.
 *
 * This is used to test whether pfn -> nid mapping of the chosen memory
 * model has fine enough granularity to avoid incorrect mapping for the
 * populated node map.
 *
 * Returns the determined alignment in pfn's.  0 if there is no alignment
 * requirement (single node).
 */
unsigned long __init node_map_pfn_alignment(void)
{
	unsigned long accl_mask = 0, last_end = 0;
	unsigned long start, end, mask;
	int last_nid = -1;
	int i, nid;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start, &end, &nid) {
		if (!start || last_nid < 0 || last_nid == nid) {
			last_nid = nid;
			last_end = end;
			continue;
		}

		/*
		 * Start with a mask granular enough to pin-point to the
		 * start pfn and tick off bits one-by-one until it becomes
		 * too coarse to separate the current node from the last.
		 */
		mask = ~((1 << __ffs(start)) - 1);
		while (mask && last_end <= (start & (mask << 1)))
			mask <<= 1;

		/* accumulate all internode masks */
		accl_mask |= mask;
	}

	/* convert mask to number of pages */
	return ~accl_mask + 1;
}

/* Find the lowest pfn for a node */
static unsigned long __init find_min_pfn_for_node(int nid)
{
	unsigned long min_pfn = ULONG_MAX;
	unsigned long start_pfn;
	int i;

	for_each_mem_pfn_range(i, nid, &start_pfn, NULL, NULL)
		min_pfn = min(min_pfn, start_pfn);

	if (min_pfn == ULONG_MAX) {
		printk(KERN_WARNING
			"Could not find start_pfn for node %d\n", nid);
		return 0;
	}

	return min_pfn;
}

/**
 * find_min_pfn_with_active_regions - Find the minimum PFN registered
 *
 * It returns the minimum PFN based on information provided via
 * memblock_set_node().
 */
unsigned long __init find_min_pfn_with_active_regions(void)
{
	return find_min_pfn_for_node(MAX_NUMNODES);
}

/*
 * early_calculate_totalpages()
 * Sum pages in active regions for movable zone.
 * Populate N_MEMORY for calculating usable_nodes.
 */
/* 计算了所有node的页框数量，一般用于计算可迁移区页框数量，是否node中所有页框都可以作为可迁移区页框 */
static unsigned long __init early_calculate_totalpages(void)
{
	unsigned long totalpages = 0;
	unsigned long start_pfn, end_pfn;
	int i, nid;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid) {
		unsigned long pages = end_pfn - start_pfn;

		totalpages += pages;
		if (pages)
			node_set_state(nid, N_MEMORY);
	}
	return totalpages;
}

/*
 * Find the PFN the Movable zone begins in each node. Kernel memory
 * is spread evenly between nodes as long as the nodes have enough
 * memory. When they don't, some nodes will have more kernelcore than
 * others
 */
static void __init find_zone_movable_pfns_for_nodes(void)
{
	int i, nid;
	unsigned long usable_startpfn;
	unsigned long kernelcore_node, kernelcore_remaining;
	/* save the state before borrow the nodemask */
	nodemask_t saved_node_state = node_states[N_MEMORY];
	/* 所有node的页框数量，是否node中所有页框都可以作为可迁移区页框 */
	unsigned long totalpages = early_calculate_totalpages();
	int usable_nodes = nodes_weight(node_states[N_MEMORY]);
	struct memblock_region *r;

	/* Need to find movable_zone earlier when movable_node is specified. */
	find_usable_zone_for_movable();

	/*
	 * If movable_node is specified, ignore kernelcore and movablecore
	 * options.
	 */
	if (movable_node_is_enabled()) {
		/* 遍历每一个memblock */
		for_each_memblock(memory, r) {
			/* 当前结点不支持热插拔的情况下直接下一个 */
			if (!memblock_is_hotpluggable(r))
				continue;

			nid = r->nid;

			/* 此结点第一个页框号 */
			usable_startpfn = PFN_DOWN(r->base);
			/* zone_movable_pfn[nid] = zone_movable_pfn[nid]和usable_startpfn当中最小值 */
			zone_movable_pfn[nid] = zone_movable_pfn[nid] ?
				min(usable_startpfn, zone_movable_pfn[nid]) :
				usable_startpfn;
		}

		goto out2;
	}

	/*
	 * If movablecore=nn[KMG] was specified, calculate what size of
	 * kernelcore that corresponds so that memory usable for
	 * any allocation type is evenly spread. If both kernelcore
	 * and movablecore are specified, then the value of kernelcore
	 * will be used for required_kernelcore if it's greater than
	 * what movablecore would have allowed.
	 */
	if (required_movablecore) {
		unsigned long corepages;

		/*
		 * Round-up so that ZONE_MOVABLE is at least as large as what
		 * was requested by the user
		 */
		required_movablecore =
			roundup(required_movablecore, MAX_ORDER_NR_PAGES);
		corepages = totalpages - required_movablecore;

		required_kernelcore = max(required_kernelcore, corepages);
	}

	/* If kernelcore was not specified, there is no ZONE_MOVABLE */
	if (!required_kernelcore)
		goto out;

	/* usable_startpfn is the lowest possible pfn ZONE_MOVABLE can be at */
	usable_startpfn = arch_zone_lowest_possible_pfn[movable_zone];

restart:
	/* Spread kernelcore memory as evenly as possible throughout nodes */
	kernelcore_node = required_kernelcore / usable_nodes;
	for_each_node_state(nid, N_MEMORY) {
		unsigned long start_pfn, end_pfn;

		/*
		 * Recalculate kernelcore_node if the division per node
		 * now exceeds what is necessary to satisfy the requested
		 * amount of memory for the kernel
		 */
		if (required_kernelcore < kernelcore_node)
			kernelcore_node = required_kernelcore / usable_nodes;

		/*
		 * As the map is walked, we track how much memory is usable
		 * by the kernel using kernelcore_remaining. When it is
		 * 0, the rest of the node is usable by ZONE_MOVABLE
		 */
		kernelcore_remaining = kernelcore_node;

		/* Go through each range of PFNs within this node */
		for_each_mem_pfn_range(i, nid, &start_pfn, &end_pfn, NULL) {
			unsigned long size_pages;

			start_pfn = max(start_pfn, zone_movable_pfn[nid]);
			if (start_pfn >= end_pfn)
				continue;

			/* Account for what is only usable for kernelcore */
			if (start_pfn < usable_startpfn) {
				unsigned long kernel_pages;
				kernel_pages = min(end_pfn, usable_startpfn)
								- start_pfn;

				kernelcore_remaining -= min(kernel_pages,
							kernelcore_remaining);
				required_kernelcore -= min(kernel_pages,
							required_kernelcore);

				/* Continue if range is now fully accounted */
				if (end_pfn <= usable_startpfn) {

					/*
					 * Push zone_movable_pfn to the end so
					 * that if we have to rebalance
					 * kernelcore across nodes, we will
					 * not double account here
					 */
					zone_movable_pfn[nid] = end_pfn;
					continue;
				}
				start_pfn = usable_startpfn;
			}

			/*
			 * The usable PFN range for ZONE_MOVABLE is from
			 * start_pfn->end_pfn. Calculate size_pages as the
			 * number of pages used as kernelcore
			 */
			size_pages = end_pfn - start_pfn;
			if (size_pages > kernelcore_remaining)
				size_pages = kernelcore_remaining;
			zone_movable_pfn[nid] = start_pfn + size_pages;

			/*
			 * Some kernelcore has been met, update counts and
			 * break if the kernelcore for this node has been
			 * satisfied
			 */
			required_kernelcore -= min(required_kernelcore,
								size_pages);
			kernelcore_remaining -= size_pages;
			if (!kernelcore_remaining)
				break;
		}
	}

	/*
	 * If there is still required_kernelcore, we do another pass with one
	 * less node in the count. This will push zone_movable_pfn[nid] further
	 * along on the nodes that still have memory until kernelcore is
	 * satisfied
	 */
	usable_nodes--;
	if (usable_nodes && required_kernelcore > usable_nodes)
		goto restart;

out2:
	/* Align start of ZONE_MOVABLE on all nids to MAX_ORDER_NR_PAGES */
	for (nid = 0; nid < MAX_NUMNODES; nid++)
		zone_movable_pfn[nid] =
			roundup(zone_movable_pfn[nid], MAX_ORDER_NR_PAGES);

out:
	/* restore the node_state */
	node_states[N_MEMORY] = saved_node_state;
}

/* Any regular or high memory on that node ? */
static void check_for_memory(pg_data_t *pgdat, int nid)
{
	enum zone_type zone_type;

	if (N_MEMORY == N_NORMAL_MEMORY)
		return;

	for (zone_type = 0; zone_type <= ZONE_MOVABLE - 1; zone_type++) {
		struct zone *zone = &pgdat->node_zones[zone_type];
		if (populated_zone(zone)) {
			node_set_state(nid, N_HIGH_MEMORY);
			if (N_NORMAL_MEMORY != N_HIGH_MEMORY &&
			    zone_type <= ZONE_NORMAL)
				node_set_state(nid, N_NORMAL_MEMORY);
			break;
		}
	}
}

/**
 * free_area_init_nodes - Initialise all pg_data_t and zone data
 * @max_zone_pfn: an array of max PFNs for each zone
 *
 * This will call free_area_init_node() for each active node in the system.
 * Using the page ranges provided by memblock_set_node(), the size of each
 * zone in each node and their holes is calculated. If the maximum PFN
 * between two adjacent zones match, it is assumed that the zone is empty.
 * For example, if arch_max_dma_pfn == arch_max_dma32_pfn, it is assumed
 * that arch_max_dma32_pfn has no pages. It is also assumed that a zone
 * starts where the previous one ended. For example, ZONE_DMA32 starts
 * at arch_max_dma_pfn.
 */
/* 初始化各个node和zone */
void __init free_area_init_nodes(unsigned long *max_zone_pfn)
{
	unsigned long start_pfn, end_pfn;
	int i, nid;

	/* Record where the zone boundaries are */
	/* 清空 arch_zone_lowest_possible_pfn 和 arch_zone_highest_possible_pfn，这两个是数组，长度为MAX_NR_ZONES，也就是每个管理区都有对应的这两个数 */
	memset(arch_zone_lowest_possible_pfn, 0,
				sizeof(arch_zone_lowest_possible_pfn));
	memset(arch_zone_highest_possible_pfn, 0,
				sizeof(arch_zone_highest_possible_pfn));

	/* 在所有node中找出最小的页框号 */
	arch_zone_lowest_possible_pfn[0] = find_min_pfn_with_active_regions();
	/* 这个应该是等于 MAX_DMA_PFN */
	arch_zone_highest_possible_pfn[0] = max_zone_pfn[0];

	/* 初始化除了 ZONE_MOVABLE 区的其他管理区的arch_zone_lowest_possible_pfn和arch_zone_highest_possible_pfn */
	for (i = 1; i < MAX_NR_ZONES; i++) {
		if (i == ZONE_MOVABLE)
			continue;
		arch_zone_lowest_possible_pfn[i] =
			arch_zone_highest_possible_pfn[i-1];
		arch_zone_highest_possible_pfn[i] =
			max(max_zone_pfn[i], arch_zone_lowest_possible_pfn[i]);
	}
	/* ZONE_MOVABLE区的 arch_zone_lowest_possible_pfn 和 arch_zone_highest_possible_pfn 为0 */
	arch_zone_lowest_possible_pfn[ZONE_MOVABLE] = 0;
	arch_zone_highest_possible_pfn[ZONE_MOVABLE] = 0;

	/* Find the PFNs that ZONE_MOVABLE begins at in each node */
	/* 将每个node的movable区的页框数设置为0 */
	memset(zone_movable_pfn, 0, sizeof(zone_movable_pfn));
	/**/
	find_zone_movable_pfns_for_nodes();

	/* Print out the zone ranges */
	printk("Zone ranges:\n");
	for (i = 0; i < MAX_NR_ZONES; i++) {
		if (i == ZONE_MOVABLE)
			continue;
		printk(KERN_CONT "  %-8s ", zone_names[i]);
		if (arch_zone_lowest_possible_pfn[i] ==
				arch_zone_highest_possible_pfn[i])
			printk(KERN_CONT "empty\n");
		else
			printk(KERN_CONT "[mem %0#10lx-%0#10lx]\n",
				arch_zone_lowest_possible_pfn[i] << PAGE_SHIFT,
				(arch_zone_highest_possible_pfn[i]
					<< PAGE_SHIFT) - 1);
	}

	/* Print out the PFNs ZONE_MOVABLE begins at in each node */
	printk("Movable zone start for each node\n");
	for (i = 0; i < MAX_NUMNODES; i++) {
		if (zone_movable_pfn[i])
			printk("  Node %d: %#010lx\n", i,
			       zone_movable_pfn[i] << PAGE_SHIFT);
	}

	/* Print out the early node map */
	printk("Early memory node ranges\n");
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid)
		printk("  node %3d: [mem %#010lx-%#010lx]\n", nid,
		       start_pfn << PAGE_SHIFT, (end_pfn << PAGE_SHIFT) - 1);

	/* Initialise every node */
	mminit_verify_pageflags_layout();
	setup_nr_node_ids();
	for_each_online_node(nid) {
		pg_data_t *pgdat = NODE_DATA(nid);
		free_area_init_node(nid, NULL,
				find_min_pfn_for_node(nid), NULL);

		/* Any memory on that node */
		if (pgdat->node_present_pages)
			node_set_state(nid, N_MEMORY);
		check_for_memory(pgdat, nid);
	}
}

static int __init cmdline_parse_core(char *p, unsigned long *core)
{
	unsigned long long coremem;
	if (!p)
		return -EINVAL;

	coremem = memparse(p, &p);
	*core = coremem >> PAGE_SHIFT;

	/* Paranoid check that UL is enough for the coremem value */
	WARN_ON((coremem >> PAGE_SHIFT) > ULONG_MAX);

	return 0;
}

/*
 * kernelcore=size sets the amount of memory for use for allocations that
 * cannot be reclaimed or migrated.
 */
static int __init cmdline_parse_kernelcore(char *p)
{
	return cmdline_parse_core(p, &required_kernelcore);
}

/*
 * movablecore=size sets the amount of memory for use for allocations that
 * can be reclaimed or migrated.
 */
static int __init cmdline_parse_movablecore(char *p)
{
	return cmdline_parse_core(p, &required_movablecore);
}

early_param("kernelcore", cmdline_parse_kernelcore);
early_param("movablecore", cmdline_parse_movablecore);

#endif /* CONFIG_HAVE_MEMBLOCK_NODE_MAP */

void adjust_managed_page_count(struct page *page, long count)
{
	spin_lock(&managed_page_count_lock);
	page_zone(page)->managed_pages += count;
	totalram_pages += count;
#ifdef CONFIG_HIGHMEM
	if (PageHighMem(page))
		totalhigh_pages += count;
#endif
	spin_unlock(&managed_page_count_lock);
}
EXPORT_SYMBOL(adjust_managed_page_count);

unsigned long free_reserved_area(void *start, void *end, int poison, char *s)
{
	void *pos;
	unsigned long pages = 0;

	start = (void *)PAGE_ALIGN((unsigned long)start);
	end = (void *)((unsigned long)end & PAGE_MASK);
	for (pos = start; pos < end; pos += PAGE_SIZE, pages++) {
		if ((unsigned int)poison <= 0xFF)
			memset(pos, poison, PAGE_SIZE);
		free_reserved_page(virt_to_page(pos));
	}

	if (pages && s)
		pr_info("Freeing %s memory: %ldK (%p - %p)\n",
			s, pages << (PAGE_SHIFT - 10), start, end);

	return pages;
}
EXPORT_SYMBOL(free_reserved_area);

#ifdef	CONFIG_HIGHMEM
void free_highmem_page(struct page *page)
{
	
	__free_reserved_page(page);
	/* 系统中总页数量++ */
	totalram_pages++;
	/* 页所属的管理区的managed_pages++ */
	page_zone(page)->managed_pages++;
	/* 高端内存页数量++ */
	totalhigh_pages++;
}
#endif


void __init mem_init_print_info(const char *str)
{
	unsigned long physpages, codesize, datasize, rosize, bss_size;
	unsigned long init_code_size, init_data_size;

	physpages = get_num_physpages();
	codesize = _etext - _stext;
	datasize = _edata - _sdata;
	rosize = __end_rodata - __start_rodata;
	bss_size = __bss_stop - __bss_start;
	init_data_size = __init_end - __init_begin;
	init_code_size = _einittext - _sinittext;

	/*
	 * Detect special cases and adjust section sizes accordingly:
	 * 1) .init.* may be embedded into .data sections
	 * 2) .init.text.* may be out of [__init_begin, __init_end],
	 *    please refer to arch/tile/kernel/vmlinux.lds.S.
	 * 3) .rodata.* may be embedded into .text or .data sections.
	 */
#define adj_init_size(start, end, size, pos, adj) \
	do { \
		if (start <= pos && pos < end && size > adj) \
			size -= adj; \
	} while (0)

	adj_init_size(__init_begin, __init_end, init_data_size,
		     _sinittext, init_code_size);
	adj_init_size(_stext, _etext, codesize, _sinittext, init_code_size);
	adj_init_size(_sdata, _edata, datasize, __init_begin, init_data_size);
	adj_init_size(_stext, _etext, codesize, __start_rodata, rosize);
	adj_init_size(_sdata, _edata, datasize, __start_rodata, rosize);

#undef	adj_init_size

	printk("Memory: %luK/%luK available "
	       "(%luK kernel code, %luK rwdata, %luK rodata, "
	       "%luK init, %luK bss, %luK reserved"
#ifdef	CONFIG_HIGHMEM
	       ", %luK highmem"
#endif
	       "%s%s)\n",
	       nr_free_pages() << (PAGE_SHIFT-10), physpages << (PAGE_SHIFT-10),
	       codesize >> 10, datasize >> 10, rosize >> 10,
	       (init_data_size + init_code_size) >> 10, bss_size >> 10,
	       (physpages - totalram_pages) << (PAGE_SHIFT-10),
#ifdef	CONFIG_HIGHMEM
	       totalhigh_pages << (PAGE_SHIFT-10),
#endif
	       str ? ", " : "", str ? str : "");
}

/**
 * set_dma_reserve - set the specified number of pages reserved in the first zone
 * @new_dma_reserve: The number of pages to mark reserved
 *
 * The per-cpu batchsize and zone watermarks are determined by present_pages.
 * In the DMA zone, a significant percentage may be consumed by kernel image
 * and other unfreeable allocations which can skew the watermarks badly. This
 * function may optionally be used to account for unfreeable pages in the
 * first zone (e.g., ZONE_DMA). The effect will be lower watermarks and
 * smaller per-cpu batchsize.
 */
void __init set_dma_reserve(unsigned long new_dma_reserve)
{
	dma_reserve = new_dma_reserve;
}

void __init free_area_init(unsigned long *zones_size)
{
	free_area_init_node(0, zones_size,
			__pa(PAGE_OFFSET) >> PAGE_SHIFT, NULL);
}

static int page_alloc_cpu_notify(struct notifier_block *self,
				 unsigned long action, void *hcpu)
{
	int cpu = (unsigned long)hcpu;

	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
		lru_add_drain_cpu(cpu);
		drain_pages(cpu);

		/*
		 * Spill the event counters of the dead processor
		 * into the current processors event counters.
		 * This artificially elevates the count of the current
		 * processor.
		 */
		vm_events_fold_cpu(cpu);

		/*
		 * Zero the differential counters of the dead processor
		 * so that the vm statistics are consistent.
		 *
		 * This is only okay since the processor is dead and cannot
		 * race with what we are doing.
		 */
		cpu_vm_stats_fold(cpu);
	}
	return NOTIFY_OK;
}

void __init page_alloc_init(void)
{
	hotcpu_notifier(page_alloc_cpu_notify, 0);
}

/*
 * calculate_totalreserve_pages - called when sysctl_lower_zone_reserve_ratio
 *	or min_free_kbytes changes.
 */
static void calculate_totalreserve_pages(void)
{
	struct pglist_data *pgdat;
	unsigned long reserve_pages = 0;
	enum zone_type i, j;

	for_each_online_pgdat(pgdat) {
		for (i = 0; i < MAX_NR_ZONES; i++) {
			struct zone *zone = pgdat->node_zones + i;
			long max = 0;

			/* Find valid and maximum lowmem_reserve in the zone */
			for (j = i; j < MAX_NR_ZONES; j++) {
				if (zone->lowmem_reserve[j] > max)
					max = zone->lowmem_reserve[j];
			}

			/* we treat the high watermark as reserved pages. */
			max += high_wmark_pages(zone);

			if (max > zone->managed_pages)
				max = zone->managed_pages;
			reserve_pages += max;
			/*
			 * Lowmem reserves are not available to
			 * GFP_HIGHUSER page cache allocations and
			 * kswapd tries to balance zones to their high
			 * watermark.  As a result, neither should be
			 * regarded as dirtyable memory, to prevent a
			 * situation where reclaim has to clean pages
			 * in order to balance the zones.
			 */
			zone->dirty_balance_reserve = max;
		}
	}
	dirty_balance_reserve = reserve_pages;
	totalreserve_pages = reserve_pages;
}

/*
 * setup_per_zone_lowmem_reserve - called whenever
 *	sysctl_lower_zone_reserve_ratio changes.  Ensures that each zone
 *	has a correct pages reserved value, so an adequate number of
 *	pages are left in the zone after a successful __alloc_pages().
 */
static void setup_per_zone_lowmem_reserve(void)
{
	struct pglist_data *pgdat;
	enum zone_type j, idx;

	for_each_online_pgdat(pgdat) {
		for (j = 0; j < MAX_NR_ZONES; j++) {
			struct zone *zone = pgdat->node_zones + j;
			unsigned long managed_pages = zone->managed_pages;

			zone->lowmem_reserve[j] = 0;

			idx = j;
			while (idx) {
				struct zone *lower_zone;

				idx--;

				if (sysctl_lowmem_reserve_ratio[idx] < 1)
					sysctl_lowmem_reserve_ratio[idx] = 1;

				lower_zone = pgdat->node_zones + idx;
				lower_zone->lowmem_reserve[j] = managed_pages /
					sysctl_lowmem_reserve_ratio[idx];
				managed_pages += lower_zone->managed_pages;
			}
		}
	}

	/* update totalreserve_pages */
	calculate_totalreserve_pages();
}

/* 设置每个zone的阀值 */
static void __setup_per_zone_wmarks(void)
{
	/* 一个zone允许管理的最小页框值，如果是常规的PAGE_SHIFT(12)，那么这里为256  */
	unsigned long pages_min = min_free_kbytes >> (PAGE_SHIFT - 10);
	/* 除了高端内存区，所有页框数量 */
	unsigned long lowmem_pages = 0;
	struct zone *zone;
	unsigned long flags;

	/* Calculate total number of !ZONE_HIGHMEM pages */
	/* 计算所有node中除了高端内存区其他所有的页框总数量 
	 * 保存到lowmem_pages中
	 */
	for_each_zone(zone) {
		if (!is_highmem(zone))
			lowmem_pages += zone->managed_pages;
	}

	/* 遍历所有node的所有zone */
	for_each_zone(zone) {
		u64 tmp;

		/* 上锁，会禁止中断 */
		spin_lock_irqsave(&zone->lock, flags);

		/* tmp等于此管理区管理的页框数量 * 256 */
		tmp = (u64)pages_min * zone->managed_pages;
		/* tmp = tmp / lowmem_pages */
		do_div(tmp, lowmem_pages);
		if (is_highmem(zone)) {
			/*
			 * __GFP_HIGH and PF_MEMALLOC allocations usually don't
			 * need highmem pages, so cap pages_min to a small
			 * value here.
			 *
			 * The WMARK_HIGH-WMARK_LOW and (WMARK_LOW-WMARK_MIN)
			 * deltas controls asynch page reclaim, and so should
			 * not be capped for highmem.
			 */
			/* 如果是高端内存管理区 */
			
			unsigned long min_pages;

			/* 高端内存管理区最小空闲页框范围在32~128之间，如果 zone->managed_pages / 1024 在这之间那么就是这个 zone->managed_pages / 1024 */
			min_pages = zone->managed_pages / 1024;
			min_pages = clamp(min_pages, SWAP_CLUSTER_MAX, 128UL);
			zone->watermark[WMARK_MIN] = min_pages;
		} else {
			/*
			 * If it's a lowmem zone, reserve a number of pages
			 * proportionate to the zone's size.
			 */
			/* 非高端内存管理区 */

			 /*  */
			zone->watermark[WMARK_MIN] = tmp;
		}

		zone->watermark[WMARK_LOW]  = min_wmark_pages(zone) + (tmp >> 2);
		zone->watermark[WMARK_HIGH] = min_wmark_pages(zone) + (tmp >> 1);

		__mod_zone_page_state(zone, NR_ALLOC_BATCH,
			high_wmark_pages(zone) - low_wmark_pages(zone) -
			atomic_long_read(&zone->vm_stat[NR_ALLOC_BATCH]));

		setup_zone_migrate_reserve(zone);
		spin_unlock_irqrestore(&zone->lock, flags);
	}

	/* update totalreserve_pages */
	calculate_totalreserve_pages();
}

/**
 * setup_per_zone_wmarks - called when min_free_kbytes changes
 * or when memory is hot-{added|removed}
 *
 * Ensures that the watermark[min,low,high] values for each zone are set
 * correctly with respect to min_free_kbytes.
 */
void setup_per_zone_wmarks(void)
{
	mutex_lock(&zonelists_mutex);
	__setup_per_zone_wmarks();
	mutex_unlock(&zonelists_mutex);
}

/*
 * The inactive anon list should be small enough that the VM never has to
 * do too much work, but large enough that each inactive page has a chance
 * to be referenced again before it is swapped out.
 *
 * The inactive_anon ratio is the target ratio of ACTIVE_ANON to
 * INACTIVE_ANON pages on this zone's LRU, maintained by the
 * pageout code. A zone->inactive_ratio of 3 means 3:1 or 25% of
 * the anonymous pages are kept on the inactive list.
 *
 * total     target    max
 * memory    ratio     inactive anon
 * -------------------------------------
 *   10MB       1         5MB
 *  100MB       1        50MB
 *    1GB       3       250MB
 *   10GB      10       0.9GB
 *  100GB      31         3GB
 *    1TB     101        10GB
 *   10TB     320        32GB
 */
static void __meminit calculate_zone_inactive_ratio(struct zone *zone)
{
	unsigned int gb, ratio;

	/* Zone size in gigabytes */
	/* zone管理的内存的GB大小 */
	gb = zone->managed_pages >> (30 - PAGE_SHIFT);
	if (gb)
		/* ratio等于 根号(10 * 管理区GB数) */
		ratio = int_sqrt(10 * gb);
	else
		ratio = 1;

	zone->inactive_ratio = ratio;
}

static void __meminit setup_per_zone_inactive_ratio(void)
{
	struct zone *zone;

	for_each_zone(zone)
		calculate_zone_inactive_ratio(zone);
}

/*
 * Initialise min_free_kbytes.
 *
 * For small machines we want it small (128k min).  For large machines
 * we want it large (64MB max).  But it is not linear, because network
 * bandwidth does not increase linearly with machine size.  We use
 *
 *	min_free_kbytes = 4 * sqrt(lowmem_kbytes), for better accuracy:
 *	min_free_kbytes = sqrt(lowmem_kbytes * 16)
 *
 * which yields
 *
 * 16MB:	512k
 * 32MB:	724k
 * 64MB:	1024k
 * 128MB:	1448k
 * 256MB:	2048k
 * 512MB:	2896k
 * 1024MB:	4096k
 * 2048MB:	5792k
 * 4096MB:	8192k
 * 8192MB:	11584k
 * 16384MB:	16384k
 */
int __meminit init_per_zone_wmark_min(void)
{
	unsigned long lowmem_kbytes;
	int new_min_free_kbytes;

	lowmem_kbytes = nr_free_buffer_pages() * (PAGE_SIZE >> 10);
	new_min_free_kbytes = int_sqrt(lowmem_kbytes * 16);

	if (new_min_free_kbytes > user_min_free_kbytes) {
		min_free_kbytes = new_min_free_kbytes;
		if (min_free_kbytes < 128)
			min_free_kbytes = 128;
		if (min_free_kbytes > 65536)
			min_free_kbytes = 65536;
	} else {
		pr_warn("min_free_kbytes is not updated to %d because user defined value %d is preferred\n",
				new_min_free_kbytes, user_min_free_kbytes);
	}
	setup_per_zone_wmarks();
	refresh_zone_stat_thresholds();
	setup_per_zone_lowmem_reserve();
	setup_per_zone_inactive_ratio();
	return 0;
}
module_init(init_per_zone_wmark_min)

/*
 * min_free_kbytes_sysctl_handler - just a wrapper around proc_dointvec() so
 *	that we can call two helper functions whenever min_free_kbytes
 *	changes.
 */
int min_free_kbytes_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	if (write) {
		user_min_free_kbytes = min_free_kbytes;
		setup_per_zone_wmarks();
	}
	return 0;
}

#ifdef CONFIG_NUMA
int sysctl_min_unmapped_ratio_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	struct zone *zone;
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	for_each_zone(zone)
		zone->min_unmapped_pages = (zone->managed_pages *
				sysctl_min_unmapped_ratio) / 100;
	return 0;
}

int sysctl_min_slab_ratio_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	struct zone *zone;
	int rc;

	rc = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (rc)
		return rc;

	for_each_zone(zone)
		zone->min_slab_pages = (zone->managed_pages *
				sysctl_min_slab_ratio) / 100;
	return 0;
}
#endif

/*
 * lowmem_reserve_ratio_sysctl_handler - just a wrapper around
 *	proc_dointvec() so that we can call setup_per_zone_lowmem_reserve()
 *	whenever sysctl_lowmem_reserve_ratio changes.
 *
 * The reserve ratio obviously has absolutely no relation with the
 * minimum watermarks. The lowmem reserve ratio can only make sense
 * if in function of the boot time zone sizes.
 */
int lowmem_reserve_ratio_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec_minmax(table, write, buffer, length, ppos);
	setup_per_zone_lowmem_reserve();
	return 0;
}

/*
 * percpu_pagelist_fraction - changes the pcp->high for each zone on each
 * cpu.  It is the fraction of total pages in each zone that a hot per cpu
 * pagelist can have before it gets flushed back to buddy allocator.
 */
int percpu_pagelist_fraction_sysctl_handler(struct ctl_table *table, int write,
	void __user *buffer, size_t *length, loff_t *ppos)
{
	struct zone *zone;
	int old_percpu_pagelist_fraction;
	int ret;

	mutex_lock(&pcp_batch_high_lock);
	old_percpu_pagelist_fraction = percpu_pagelist_fraction;

	ret = proc_dointvec_minmax(table, write, buffer, length, ppos);
	if (!write || ret < 0)
		goto out;

	/* Sanity checking to avoid pcp imbalance */
	if (percpu_pagelist_fraction &&
	    percpu_pagelist_fraction < MIN_PERCPU_PAGELIST_FRACTION) {
		percpu_pagelist_fraction = old_percpu_pagelist_fraction;
		ret = -EINVAL;
		goto out;
	}

	/* No change? */
	if (percpu_pagelist_fraction == old_percpu_pagelist_fraction)
		goto out;

	for_each_populated_zone(zone) {
		unsigned int cpu;

		for_each_possible_cpu(cpu)
			pageset_set_high_and_batch(zone,
					per_cpu_ptr(zone->pageset, cpu));
	}
out:
	mutex_unlock(&pcp_batch_high_lock);
	return ret;
}

int hashdist = HASHDIST_DEFAULT;

#ifdef CONFIG_NUMA
static int __init set_hashdist(char *str)
{
	if (!str)
		return 0;
	hashdist = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("hashdist=", set_hashdist);
#endif

/*
 * allocate a large system hash table from bootmem
 * - it is assumed that the hash table must contain an exact power-of-2
 *   quantity of entries
 * - limit is the number of hash buckets, not the total allocation size
 */
void *__init alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit)
{
	unsigned long long max = high_limit;
	unsigned long log2qty, size;
	void *table = NULL;

	/* allow the kernel cmdline to have a say */
	if (!numentries) {
		/* round applicable memory size up to nearest megabyte */
		numentries = nr_kernel_pages;

		/* It isn't necessary when PAGE_SIZE >= 1MB */
		if (PAGE_SHIFT < 20)
			numentries = round_up(numentries, (1<<20)/PAGE_SIZE);

		/* limit to 1 bucket per 2^scale bytes of low memory */
		if (scale > PAGE_SHIFT)
			numentries >>= (scale - PAGE_SHIFT);
		else
			numentries <<= (PAGE_SHIFT - scale);

		/* Make sure we've got at least a 0-order allocation.. */
		if (unlikely(flags & HASH_SMALL)) {
			/* Makes no sense without HASH_EARLY */
			WARN_ON(!(flags & HASH_EARLY));
			if (!(numentries >> *_hash_shift)) {
				numentries = 1UL << *_hash_shift;
				BUG_ON(!numentries);
			}
		} else if (unlikely((numentries * bucketsize) < PAGE_SIZE))
			numentries = PAGE_SIZE / bucketsize;
	}
	numentries = roundup_pow_of_two(numentries);

	/* limit allocation size to 1/16 total memory by default */
	if (max == 0) {
		max = ((unsigned long long)nr_all_pages << PAGE_SHIFT) >> 4;
		do_div(max, bucketsize);
	}
	max = min(max, 0x80000000ULL);

	if (numentries < low_limit)
		numentries = low_limit;
	if (numentries > max)
		numentries = max;

	log2qty = ilog2(numentries);

	do {
		size = bucketsize << log2qty;
		if (flags & HASH_EARLY)
			table = memblock_virt_alloc_nopanic(size, 0);
		else if (hashdist)
			table = __vmalloc(size, GFP_ATOMIC, PAGE_KERNEL);
		else {
			/*
			 * If bucketsize is not a power-of-two, we may free
			 * some pages at the end of hash table which
			 * alloc_pages_exact() automatically does
			 */
			if (get_order(size) < MAX_ORDER) {
				table = alloc_pages_exact(size, GFP_ATOMIC);
				kmemleak_alloc(table, size, 1, GFP_ATOMIC);
			}
		}
	} while (!table && size > PAGE_SIZE && --log2qty);

	if (!table)
		panic("Failed to allocate %s hash table\n", tablename);

	printk(KERN_INFO "%s hash table entries: %ld (order: %d, %lu bytes)\n",
	       tablename,
	       (1UL << log2qty),
	       ilog2(size) - PAGE_SHIFT,
	       size);

	if (_hash_shift)
		*_hash_shift = log2qty;
	if (_hash_mask)
		*_hash_mask = (1 << log2qty) - 1;

	return table;
}

/* Return a pointer to the bitmap storing bits affecting a block of pages */
static inline unsigned long *get_pageblock_bitmap(struct zone *zone,
							unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
	return __pfn_to_section(pfn)->pageblock_flags;
#else
	return zone->pageblock_flags;
#endif /* CONFIG_SPARSEMEM */
}

static inline int pfn_to_bitidx(struct zone *zone, unsigned long pfn)
{
#ifdef CONFIG_SPARSEMEM
	pfn &= (PAGES_PER_SECTION-1);
	return (pfn >> pageblock_order) * NR_PAGEBLOCK_BITS;
#else
	pfn = pfn - round_down(zone->zone_start_pfn, pageblock_nr_pages);
	return (pfn >> pageblock_order) * NR_PAGEBLOCK_BITS;
#endif /* CONFIG_SPARSEMEM */
}

/**
 * get_pfnblock_flags_mask - Return the requested group of flags for the pageblock_nr_pages block of pages
 * @page: The page within the block of interest
 * @pfn: The target page frame number
 * @end_bitidx: The last bit of interest to retrieve
 * @mask: mask of bits that the caller is interested in
 *
 * Return: pageblock_bits flags
 */
unsigned long get_pfnblock_flags_mask(struct page *page, unsigned long pfn,
					unsigned long end_bitidx,
					unsigned long mask)
{
	struct zone *zone;
	unsigned long *bitmap;
	unsigned long bitidx, word_bitidx;
	unsigned long word;

	zone = page_zone(page);
	bitmap = get_pageblock_bitmap(zone, pfn);
	bitidx = pfn_to_bitidx(zone, pfn);
	word_bitidx = bitidx / BITS_PER_LONG;
	bitidx &= (BITS_PER_LONG-1);

	word = bitmap[word_bitidx];
	bitidx += end_bitidx;
	return (word >> (BITS_PER_LONG - bitidx - 1)) & mask;
}

/**
 * set_pfnblock_flags_mask - Set the requested group of flags for a pageblock_nr_pages block of pages
 * @page: The page within the block of interest
 * @flags: The flags to set
 * @pfn: The target page frame number
 * @end_bitidx: The last bit of interest
 * @mask: mask of bits that the caller is interested in
 */
void set_pfnblock_flags_mask(struct page *page, unsigned long flags,
					unsigned long pfn,
					unsigned long end_bitidx,
					unsigned long mask)
{
	struct zone *zone;
	unsigned long *bitmap;
	unsigned long bitidx, word_bitidx;
	unsigned long old_word, word;

	BUILD_BUG_ON(NR_PAGEBLOCK_BITS != 4);

	/* 获取页所在的内存管理区 */
	zone = page_zone(page);
	/* 获取zone->pageblock_flags指向的此zone的pageblock位图 */
	bitmap = get_pageblock_bitmap(zone, pfn);
	/* 根据pfn获取pfn所在的pageblock的位图(占4位) */
	bitidx = pfn_to_bitidx(zone, pfn);
	word_bitidx = bitidx / BITS_PER_LONG;
	bitidx &= (BITS_PER_LONG-1);

	VM_BUG_ON_PAGE(!zone_spans_pfn(zone, pfn), page);

	bitidx += end_bitidx;
	mask <<= (BITS_PER_LONG - bitidx - 1);
	flags <<= (BITS_PER_LONG - bitidx - 1);

	word = ACCESS_ONCE(bitmap[word_bitidx]);
	for (;;) {
		old_word = cmpxchg(&bitmap[word_bitidx], word, (word & ~mask) | flags);
		if (word == old_word)
			break;
		word = old_word;
	}
}

/*
 * This function checks whether pageblock includes unmovable pages or not.
 * If @count is not zero, it is okay to include less @count unmovable pages
 *
 * PageLRU check without isolation or lru_lock could race so that
 * MIGRATE_MOVABLE block might include unmovable pages. It means you can't
 * expect this function should be exact.
 */
bool has_unmovable_pages(struct zone *zone, struct page *page, int count,
			 bool skip_hwpoisoned_pages)
{
	unsigned long pfn, iter, found;
	int mt;

	/*
	 * For avoiding noise data, lru_add_drain_all() should be called
	 * If ZONE_MOVABLE, the zone never contains unmovable pages
	 */
	if (zone_idx(zone) == ZONE_MOVABLE)
		return false;
	mt = get_pageblock_migratetype(page);
	if (mt == MIGRATE_MOVABLE || is_migrate_cma(mt))
		return false;

	pfn = page_to_pfn(page);
	for (found = 0, iter = 0; iter < pageblock_nr_pages; iter++) {
		unsigned long check = pfn + iter;

		if (!pfn_valid_within(check))
			continue;

		page = pfn_to_page(check);

		/*
		 * Hugepages are not in LRU lists, but they're movable.
		 * We need not scan over tail pages bacause we don't
		 * handle each tail page individually in migration.
		 */
		if (PageHuge(page)) {
			iter = round_up(iter + 1, 1<<compound_order(page)) - 1;
			continue;
		}

		/*
		 * We can't use page_count without pin a page
		 * because another CPU can free compound page.
		 * This check already skips compound tails of THP
		 * because their page->_count is zero at all time.
		 */
		if (!atomic_read(&page->_count)) {
			if (PageBuddy(page))
				iter += (1 << page_order(page)) - 1;
			continue;
		}

		/*
		 * The HWPoisoned page may be not in buddy system, and
		 * page_count() is not 0.
		 */
		if (skip_hwpoisoned_pages && PageHWPoison(page))
			continue;

		if (!PageLRU(page))
			found++;
		/*
		 * If there are RECLAIMABLE pages, we need to check it.
		 * But now, memory offline itself doesn't call shrink_slab()
		 * and it still to be fixed.
		 */
		/*
		 * If the page is not RAM, page_count()should be 0.
		 * we don't need more check. This is an _used_ not-movable page.
		 *
		 * The problematic thing here is PG_reserved pages. PG_reserved
		 * is set to both of a memory hole page and a _used_ kernel
		 * page at boot.
		 */
		if (found > count)
			return true;
	}
	return false;
}

bool is_pageblock_removable_nolock(struct page *page)
{
	struct zone *zone;
	unsigned long pfn;

	/*
	 * We have to be careful here because we are iterating over memory
	 * sections which are not zone aware so we might end up outside of
	 * the zone but still within the section.
	 * We have to take care about the node as well. If the node is offline
	 * its NODE_DATA will be NULL - see page_zone.
	 */
	if (!node_online(page_to_nid(page)))
		return false;

	zone = page_zone(page);
	pfn = page_to_pfn(page);
	if (!zone_spans_pfn(zone, pfn))
		return false;

	return !has_unmovable_pages(zone, page, 0, true);
}

#ifdef CONFIG_CMA

static unsigned long pfn_max_align_down(unsigned long pfn)
{
	return pfn & ~(max_t(unsigned long, MAX_ORDER_NR_PAGES,
			     pageblock_nr_pages) - 1);
}

static unsigned long pfn_max_align_up(unsigned long pfn)
{
	return ALIGN(pfn, max_t(unsigned long, MAX_ORDER_NR_PAGES,
				pageblock_nr_pages));
}

/* [start, end) must belong to a single zone. */
static int __alloc_contig_migrate_range(struct compact_control *cc,
					unsigned long start, unsigned long end)
{
	/* This function is based on compact_zone() from compaction.c. */
	unsigned long nr_reclaimed;
	unsigned long pfn = start;
	unsigned int tries = 0;
	int ret = 0;

	migrate_prep();

	while (pfn < end || !list_empty(&cc->migratepages)) {
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		if (list_empty(&cc->migratepages)) {
			cc->nr_migratepages = 0;
			pfn = isolate_migratepages_range(cc, pfn, end);
			if (!pfn) {
				ret = -EINTR;
				break;
			}
			tries = 0;
		} else if (++tries == 5) {
			ret = ret < 0 ? ret : -EBUSY;
			break;
		}

		nr_reclaimed = reclaim_clean_pages_from_list(cc->zone,
							&cc->migratepages);
		cc->nr_migratepages -= nr_reclaimed;

		ret = migrate_pages(&cc->migratepages, alloc_migrate_target,
				    NULL, 0, cc->mode, MR_CMA);
	}
	if (ret < 0) {
		putback_movable_pages(&cc->migratepages);
		return ret;
	}
	return 0;
}

/**
 * alloc_contig_range() -- tries to allocate given range of pages
 * @start:	start PFN to allocate
 * @end:	one-past-the-last PFN to allocate
 * @migratetype:	migratetype of the underlaying pageblocks (either
 *			#MIGRATE_MOVABLE or #MIGRATE_CMA).  All pageblocks
 *			in range must have the same migratetype and it must
 *			be either of the two.
 *
 * The PFN range does not have to be pageblock or MAX_ORDER_NR_PAGES
 * aligned, however it's the caller's responsibility to guarantee that
 * we are the only thread that changes migrate type of pageblocks the
 * pages fall in.
 *
 * The PFN range must belong to a single zone.
 *
 * Returns zero on success or negative error code.  On success all
 * pages which PFN is in [start, end) are allocated for the caller and
 * need to be freed with free_contig_range().
 */
int alloc_contig_range(unsigned long start, unsigned long end,
		       unsigned migratetype)
{
	unsigned long outer_start, outer_end;
	int ret = 0, order;

	struct compact_control cc = {
		.nr_migratepages = 0,
		.order = -1,
		.zone = page_zone(pfn_to_page(start)),
		.mode = MIGRATE_SYNC,
		.ignore_skip_hint = true,
	};
	INIT_LIST_HEAD(&cc.migratepages);

	/*
	 * What we do here is we mark all pageblocks in range as
	 * MIGRATE_ISOLATE.  Because pageblock and max order pages may
	 * have different sizes, and due to the way page allocator
	 * work, we align the range to biggest of the two pages so
	 * that page allocator won't try to merge buddies from
	 * different pageblocks and change MIGRATE_ISOLATE to some
	 * other migration type.
	 *
	 * Once the pageblocks are marked as MIGRATE_ISOLATE, we
	 * migrate the pages from an unaligned range (ie. pages that
	 * we are interested in).  This will put all the pages in
	 * range back to page allocator as MIGRATE_ISOLATE.
	 *
	 * When this is done, we take the pages in range from page
	 * allocator removing them from the buddy system.  This way
	 * page allocator will never consider using them.
	 *
	 * This lets us mark the pageblocks back as
	 * MIGRATE_CMA/MIGRATE_MOVABLE so that free pages in the
	 * aligned range but not in the unaligned, original range are
	 * put back to page allocator so that buddy can use them.
	 */

	ret = start_isolate_page_range(pfn_max_align_down(start),
				       pfn_max_align_up(end), migratetype,
				       false);
	if (ret)
		return ret;

	ret = __alloc_contig_migrate_range(&cc, start, end);
	if (ret)
		goto done;

	/*
	 * Pages from [start, end) are within a MAX_ORDER_NR_PAGES
	 * aligned blocks that are marked as MIGRATE_ISOLATE.  What's
	 * more, all pages in [start, end) are free in page allocator.
	 * What we are going to do is to allocate all pages from
	 * [start, end) (that is remove them from page allocator).
	 *
	 * The only problem is that pages at the beginning and at the
	 * end of interesting range may be not aligned with pages that
	 * page allocator holds, ie. they can be part of higher order
	 * pages.  Because of this, we reserve the bigger range and
	 * once this is done free the pages we are not interested in.
	 *
	 * We don't have to hold zone->lock here because the pages are
	 * isolated thus they won't get removed from buddy.
	 */

	lru_add_drain_all();
	drain_all_pages();

	order = 0;
	outer_start = start;
	while (!PageBuddy(pfn_to_page(outer_start))) {
		if (++order >= MAX_ORDER) {
			ret = -EBUSY;
			goto done;
		}
		outer_start &= ~0UL << order;
	}

	/* Make sure the range is really isolated. */
	if (test_pages_isolated(outer_start, end, false)) {
		pr_info("%s: [%lx, %lx) PFNs busy\n",
			__func__, outer_start, end);
		ret = -EBUSY;
		goto done;
	}

	/* Grab isolated pages from freelists. */
	outer_end = isolate_freepages_range(&cc, outer_start, end);
	if (!outer_end) {
		ret = -EBUSY;
		goto done;
	}

	/* Free head and tail (if any) */
	if (start != outer_start)
		free_contig_range(outer_start, start - outer_start);
	if (end != outer_end)
		free_contig_range(end, outer_end - end);

done:
	undo_isolate_page_range(pfn_max_align_down(start),
				pfn_max_align_up(end), migratetype);
	return ret;
}

void free_contig_range(unsigned long pfn, unsigned nr_pages)
{
	unsigned int count = 0;

	for (; nr_pages--; pfn++) {
		struct page *page = pfn_to_page(pfn);

		count += page_count(page) != 1;
		__free_page(page);
	}
	WARN(count != 0, "%d pages are still in use!\n", count);
}
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
/*
 * The zone indicated has a new number of managed_pages; batch sizes and percpu
 * page high values need to be recalulated.
 */
void __meminit zone_pcp_update(struct zone *zone)
{
	unsigned cpu;
	mutex_lock(&pcp_batch_high_lock);
	for_each_possible_cpu(cpu)
		pageset_set_high_and_batch(zone,
				per_cpu_ptr(zone->pageset, cpu));
	mutex_unlock(&pcp_batch_high_lock);
}
#endif

void zone_pcp_reset(struct zone *zone)
{
	unsigned long flags;
	int cpu;
	struct per_cpu_pageset *pset;

	/* avoid races with drain_pages()  */
	local_irq_save(flags);
	if (zone->pageset != &boot_pageset) {
		for_each_online_cpu(cpu) {
			pset = per_cpu_ptr(zone->pageset, cpu);
			drain_zonestat(zone, pset);
		}
		free_percpu(zone->pageset);
		zone->pageset = &boot_pageset;
	}
	local_irq_restore(flags);
}

#ifdef CONFIG_MEMORY_HOTREMOVE
/*
 * All pages in the range must be isolated before calling this.
 */
void
__offline_isolated_pages(unsigned long start_pfn, unsigned long end_pfn)
{
	struct page *page;
	struct zone *zone;
	unsigned int order, i;
	unsigned long pfn;
	unsigned long flags;
	/* find the first valid pfn */
	for (pfn = start_pfn; pfn < end_pfn; pfn++)
		if (pfn_valid(pfn))
			break;
	if (pfn == end_pfn)
		return;
	zone = page_zone(pfn_to_page(pfn));
	spin_lock_irqsave(&zone->lock, flags);
	pfn = start_pfn;
	while (pfn < end_pfn) {
		if (!pfn_valid(pfn)) {
			pfn++;
			continue;
		}
		page = pfn_to_page(pfn);
		/*
		 * The HWPoisoned page may be not in buddy system, and
		 * page_count() is not 0.
		 */
		if (unlikely(!PageBuddy(page) && PageHWPoison(page))) {
			pfn++;
			SetPageReserved(page);
			continue;
		}

		BUG_ON(page_count(page));
		BUG_ON(!PageBuddy(page));
		order = page_order(page);
#ifdef CONFIG_DEBUG_VM
		printk(KERN_INFO "remove from free list %lx %d %lx\n",
		       pfn, 1 << order, end_pfn);
#endif
		list_del(&page->lru);
		rmv_page_order(page);
		zone->free_area[order].nr_free--;
		for (i = 0; i < (1 << order); i++)
			SetPageReserved((page+i));
		pfn += (1 << order);
	}
	spin_unlock_irqrestore(&zone->lock, flags);
}
#endif

#ifdef CONFIG_MEMORY_FAILURE
bool is_free_buddy_page(struct page *page)
{
	struct zone *zone = page_zone(page);
	unsigned long pfn = page_to_pfn(page);
	unsigned long flags;
	unsigned int order;

	spin_lock_irqsave(&zone->lock, flags);
	for (order = 0; order < MAX_ORDER; order++) {
		struct page *page_head = page - (pfn & ((1 << order) - 1));

		if (PageBuddy(page_head) && page_order(page_head) >= order)
			break;
	}
	spin_unlock_irqrestore(&zone->lock, flags);

	return order < MAX_ORDER;
}
#endif
