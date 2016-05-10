#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifndef __ASSEMBLY__
#ifndef __GENERATING_BOUNDS_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/numa.h>
#include <linux/init.h>
#include <linux/seqlock.h>
#include <linux/nodemask.h>
#include <linux/pageblock-flags.h>
#include <linux/page-flags-layout.h>
#include <linux/atomic.h>
#include <asm/page.h>

/* Free memory management - zoned buddy allocator.  */
#ifndef CONFIG_FORCE_MAX_ZONEORDER
#define MAX_ORDER 11
#else
#define MAX_ORDER CONFIG_FORCE_MAX_ZONEORDER
#endif
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))

/*
 * PAGE_ALLOC_COSTLY_ORDER is the order at which allocations are deemed
 * costly to service.  That is between allocation orders which should
 * coalesce naturally under reasonable reclaim pressure and those which
 * will not.
 */
#define PAGE_ALLOC_COSTLY_ORDER 3

/* 这几个链表主要用于反内存碎片 */
enum {
	MIGRATE_UNMOVABLE, 		/* 页框内容不可移动,在内存中位置必须固定，无法移动到其他地方，核心内核分配的大部分页面都属于这一类。 */
	MIGRATE_RECLAIMABLE, 		/* 页框内容可回收,不能直接移动，但是可以回收，因为还可以从某些源重建页面，比如映射文件的数据属于这种类别，kswapd会按照一定的规则，周期性的回收这类页面。 */
	MIGRATE_MOVABLE, 			/* 页框内容可移动，属于用户空间应用程序的页属于此类页面，它们是通过页表映射的，因此我们只需要更新页表项，并把数据复制到新位置就可以了
								 * 当然要注意，一个页面可能被多个进程共享，对应着多个页表项。 
								 */
	MIGRATE_PCPTYPES,	 		/* 用来表示每CPU页框高速缓存的数据结构中的链表的迁移类型数目 */
	MIGRATE_RESERVE = MIGRATE_PCPTYPES, 	
#ifdef CONFIG_CMA
	/*
	 * MIGRATE_CMA migration type is designed to mimic the way
	 * ZONE_MOVABLE works.  Only movable pages can be allocated
	 * from MIGRATE_CMA pageblocks and page allocator never
	 * implicitly change migration type of MIGRATE_CMA pageblock.
	 *
	 * The way to use it is to change migratetype of a range of
	 * pageblocks to MIGRATE_CMA which can be done by
	 * __free_pageblock_cma() function.  What is important though
	 * is that a range of pageblocks must be aligned to
	 * MAX_ORDER_NR_PAGES should biggest page be bigger then
	 * a single pageblock.
	 */
	MIGRATE_CMA,   				/* 预留一段的内存给驱动使用，但当驱动不用的时候，伙伴系统可以分配给用户进程用作匿名内存或者页缓存。而当驱动需要使用时，就将进程占用的内存通过回收或者迁移的方式将之前占用的预留内存腾出来，供驱动使用。 */
#endif   
#ifdef CONFIG_MEMORY_ISOLATION
	MIGRATE_ISOLATE,			/* 不能从这个链表分配页框，因为这个链表专门用于NUMA结点移动物理内存页，将物理内存页内容移动到使用这个页最频繁的CPU */
#endif
	MIGRATE_TYPES
};

#ifdef CONFIG_CMA
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#else
#  define is_migrate_cma(migratetype) false
#endif

#define for_each_migratetype_order(order, type) \
	for (order = 0; order < MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)

/* 内核是否关闭了页可迁移特性 */
extern int page_group_by_mobility_disabled;

#define NR_MIGRATETYPE_BITS (PB_migrate_end - PB_migrate + 1)
#define MIGRATETYPE_MASK ((1UL << NR_MIGRATETYPE_BITS) - 1)

#define get_pageblock_migratetype(page)					\
	get_pfnblock_flags_mask(page, page_to_pfn(page),		\
			PB_migrate_end, MIGRATETYPE_MASK)

static inline int get_pfnblock_migratetype(struct page *page, unsigned long pfn)
{
	BUILD_BUG_ON(PB_migrate_end - PB_migrate != 2);
	return get_pfnblock_flags_mask(page, pfn, PB_migrate_end,
					MIGRATETYPE_MASK);
}

/* 伙伴系统的一个块，描述1,2,4,8,16,32,64,128,256,512或1024个连续页框的块 */
struct free_area {
	/* 指向这个块中所有空闲小块的第一个页描述符，这些小块会按照MIGRATE_TYPES类型存放在不同指针里 */
	struct list_head	free_list[MIGRATE_TYPES];
	/* 空闲小块的个数 */
	unsigned long		nr_free;
};

struct pglist_data;

/*
 * zone->lock and zone->lru_lock are two of the hottest locks in the kernel.
 * So add a wild amount of padding here to ensure that they fall into separate
 * cachelines.  There are very few zone structures in the machine, so space
 * consumption is not a concern here.
 */
#if defined(CONFIG_SMP)
struct zone_padding {
	char x[0];
} ____cacheline_internodealigned_in_smp;
#define ZONE_PADDING(name)	struct zone_padding name;
#else
#define ZONE_PADDING(name)
#endif

enum zone_stat_item {
	/* First 128 byte cacheline (assuming 64 bit words) */
	NR_FREE_PAGES,
	/* 可用于分配给，这个意思是分配是内存分配本来打算从另一个zone分配的，但是那个zone内存不足以分配，所以在这个zone分配了内存 
	 * 但是这个zone也不能你们其他zone没内存了，就都来我这里分配，这个值就是允许进行这种分配的页数量
	 * 当此值为0时，会增加 zone的high阀值 - zone的low阀值 数量的页给它
	 */
	NR_ALLOC_BATCH,
	NR_LRU_BASE,
	/* 非活动匿名页lru链表，会加入的除了匿名页还有shmem用的页 */
	NR_INACTIVE_ANON = NR_LRU_BASE, /* must match order of LRU_[IN]ACTIVE */
	/* 非活动匿名页lru链表，会加入的除了匿名页还有shmem用的页 */
	NR_ACTIVE_ANON,		/*  "     "     "   "       "         */
	NR_INACTIVE_FILE,	/*  "     "     "   "       "         */
	NR_ACTIVE_FILE,		/*  "     "     "   "       "         */
	NR_UNEVICTABLE,		/*  "     "     "   "       "         */
	NR_MLOCK,		/* mlock()ed pages found and moved off LRU */
	/* 已经映射的匿名页 */
	NR_ANON_PAGES,	/* Mapped anonymous pages */
	NR_FILE_MAPPED,	/* pagecache pages mapped into pagetables.
			   only modified from process context */
	NR_FILE_PAGES,	/* zone中加入到page cache中的页数量，当一个页准备要被换到swap中时，会先加入swapcache(swap的address_space)，这时候这个统计会++ */
	/* 脏页数量 */
	NR_FILE_DIRTY,
	NR_WRITEBACK,
	/* 可回收slab占用的页数量 */
	NR_SLAB_RECLAIMABLE,
	/* 不可回收slab占用的页数量 */
	NR_SLAB_UNRECLAIMABLE,
	NR_PAGETABLE,		/* used for pagetables */
	NR_KERNEL_STACK,
	/* Second 128 byte cacheline */
	NR_UNSTABLE_NFS,	/* NFS unstable pages */
	NR_BOUNCE,
	NR_VMSCAN_WRITE,
	NR_VMSCAN_IMMEDIATE,	/* Prioritise for reclaim when writeback ends */
	NR_WRITEBACK_TEMP,	/* Writeback using temporary buffers */
	NR_ISOLATED_ANON,	/* Temporary isolated pages from anon lru */
	NR_ISOLATED_FILE,	/* Temporary isolated pages from file lru */
	NR_SHMEM,		/* shmem pages (included tmpfs/GEM pages) */
	NR_DIRTIED,		/* page dirtyings since bootup */
	NR_WRITTEN,		/* page writings since bootup */
	NR_PAGES_SCANNED,	/* pages scanned since last reclaim */
#ifdef CONFIG_NUMA
	/* 分配的页框所在zone在期望的node上的计数，这个计数会记在分配了页框的zone中 */
	NUMA_HIT,		/* allocated in intended node */
	/* 分配的页框所在zone在不在期望的node上的计数，这个miss计数会记在期望的zone中 */
	NUMA_MISS,		/* allocated in non intended node */
	/* 期待在此zone分配，然后没办法，在其他node的zone中分配到了内存，这里记次数 */
	NUMA_FOREIGN,		/* was intended here, hit elsewhere */
	NUMA_INTERLEAVE_HIT,	/* interleaver preferred this zone */
	NUMA_LOCAL,		/* allocation from local node */
	NUMA_OTHER,		/* allocation from other node */
#endif
	WORKINGSET_REFAULT,
	WORKINGSET_ACTIVATE,
	WORKINGSET_NODERECLAIM,
	NR_ANON_TRANSPARENT_HUGEPAGES,
	/* 空闲的CMA页框数量 */
	NR_FREE_CMA_PAGES,
	NR_VM_ZONE_STAT_ITEMS };

/*
 * We do arithmetic on the LRU lists in various places in the code,
 * so it is important to keep the active lists LRU_ACTIVE higher in
 * the array than the corresponding inactive lists, and to keep
 * the *_FILE lists LRU_FILE higher than the corresponding _ANON lists.
 *
 * This has to be kept in sync with the statistics in zone_stat_item
 * above and the descriptions in vmstat_text in mm/vmstat.c
 */
#define LRU_BASE 0
#define LRU_ACTIVE 1
#define LRU_FILE 2

enum lru_list {
	LRU_INACTIVE_ANON = LRU_BASE,
	LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
	LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
	LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
	/* 不可回收页链表，里面的页不能交换出去，这里面的页有三种可能性
	 * 1.属于ramfs的页
	 * 2.共享内存时使用了SHM_LOCK标志
	 * 3.映射时使用了mlock()
	 */
	LRU_UNEVICTABLE,
	NR_LRU_LISTS
};

#define for_each_lru(lru) for (lru = 0; lru < NR_LRU_LISTS; lru++)

#define for_each_evictable_lru(lru) for (lru = 0; lru <= LRU_ACTIVE_FILE; lru++)

static inline int is_file_lru(enum lru_list lru)
{
	return (lru == LRU_INACTIVE_FILE || lru == LRU_ACTIVE_FILE);
}

static inline int is_active_lru(enum lru_list lru)
{
	return (lru == LRU_ACTIVE_ANON || lru == LRU_ACTIVE_FILE);
}

static inline int is_unevictable_lru(enum lru_list lru)
{
	return (lru == LRU_UNEVICTABLE);
}

struct zone_reclaim_stat {
	/*
	 * The pageout code in vmscan.c keeps track of how many of the
	 * mem/swap backed and file backed pages are referenced.
	 * The higher the rotated/scanned ratio, the more valuable
	 * that cache is.
	 *
	 * The anon LRU stats live in [0], file LRU stats in [1]
	 */
	 /* 
	  * 以下两个数组中，匿名页lru统计保存在[0]，文件页lru统计保存在[1]
	  */
	/* 最近加入到活动lru链表的页数量
	 * 从非活动lru链表中重新加入活动lru链表的页数量
	 * 从活动lru链表中移动到活动lru链表头部的页(代码段的页)
	 * 新加入到活动lru链表中的页
	 */
	unsigned long		recent_rotated[2];
	/* 
	 * 最近扫描过的页数量
	 * 在mark_page_accessed()中将页加入到活动页lru链表时此值会++
	 * 当从inactive_lru中隔离出一些页用于释放时，此值会加上这些隔离出来的页的数量
	 */
	unsigned long		recent_scanned[2];
};

/* lru链表描述符，主要有5个链表
 * LRU_INACTIVE_ANON = LRU_BASE,
 * LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
 * LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
 * LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
 * LRU_UNEVICTABLE,
 */
struct lruvec {
	/* 5个lru链表头 */
	struct list_head lists[NR_LRU_LISTS];
	struct zone_reclaim_stat reclaim_stat;
#ifdef CONFIG_MEMCG
	/* 所属zone */
	struct zone *zone;
#endif
};

/* Mask used at gathering information at once (see memcontrol.c) */
#define LRU_ALL_FILE (BIT(LRU_INACTIVE_FILE) | BIT(LRU_ACTIVE_FILE))
#define LRU_ALL_ANON (BIT(LRU_INACTIVE_ANON) | BIT(LRU_ACTIVE_ANON))
#define LRU_ALL	     ((1 << NR_LRU_LISTS) - 1)

/* Isolate clean file */
/* 只隔离干净的页 */
#define ISOLATE_CLEAN		((__force isolate_mode_t)0x1)
/* Isolate unmapped file */
/* 隔离未映射页 */
#define ISOLATE_UNMAPPED	((__force isolate_mode_t)0x2)
/* Isolate for asynchronous migration */
/* 隔离用于异步内存迁移 */
#define ISOLATE_ASYNC_MIGRATE	((__force isolate_mode_t)0x4)
/* Isolate unevictable pages */
#define ISOLATE_UNEVICTABLE	((__force isolate_mode_t)0x8)

/* LRU Isolation modes. */
typedef unsigned __bitwise__ isolate_mode_t;

enum zone_watermarks {
	WMARK_MIN,
	WMARK_LOW,
	WMARK_HIGH,
	NR_WMARK
};

#define min_wmark_pages(z) (z->watermark[WMARK_MIN])
#define low_wmark_pages(z) (z->watermark[WMARK_LOW])
#define high_wmark_pages(z) (z->watermark[WMARK_HIGH])

struct per_cpu_pages {
	/* 当前CPU高速缓存中页框个数 */
	int count;		/* number of pages in the list */
	/* 上界，当此CPU高速缓存中页框个数大于high，则会将batch个页框放回伙伴系统 */
	int high;		/* high watermark, emptying needed */
	/* 在高速缓存中将要添加或被删去的页框个数，当链表中页框数量多个上界时会将batch个页框放回伙伴系统，当链表中页框数量为0时则从伙伴系统中获取batch个页框 */
	int batch;		/* chunk size for buddy add/remove */

	/* Lists of pages, one per migrate type stored on the pcp-lists */
	/* 页框的链表，如果需要冷高速缓存，从链表尾开始获取页框，如果需要热高速缓存，从链表头开始获取页框 */
	struct list_head lists[MIGRATE_PCPTYPES];
};

struct per_cpu_pageset {
	/* 高速缓存页框结构 */
	struct per_cpu_pages pcp;
#ifdef CONFIG_NUMA
	s8 expire;
#endif
#ifdef CONFIG_SMP
	s8 stat_threshold;
	s8 vm_stat_diff[NR_VM_ZONE_STAT_ITEMS];
#endif
};

#endif /* !__GENERATING_BOUNDS.H */

enum zone_type {
#ifdef CONFIG_ZONE_DMA
	/*
	 * ZONE_DMA is used when there are devices that are not able
	 * to do DMA to all of addressable memory (ZONE_NORMAL). Then we
	 * carve out the portion of memory that is needed for these devices.
	 * The range is arch specific.
	 *
	 * Some examples
	 *
	 * Architecture		Limit
	 * ---------------------------
	 * parisc, ia64, sparc	<4G
	 * s390			<2G
	 * arm			Various
	 * alpha		Unlimited or 0-16MB.
	 *
	 * i386, x86_64 and multiple other arches
	 * 			<16M.
	 */
	ZONE_DMA,
#endif
#ifdef CONFIG_ZONE_DMA32
	/*
	 * x86_64 needs two ZONE_DMAs because it supports devices that are
	 * only able to do DMA to the lower 16M but also 32 bit devices that
	 * can only do DMA areas below 4G.
	 */
	ZONE_DMA32,
#endif
	/*
	 * Normal addressable memory is in ZONE_NORMAL. DMA operations can be
	 * performed on pages in ZONE_NORMAL if the DMA devices support
	 * transfers to all addressable memory.
	 */
	ZONE_NORMAL,
#ifdef CONFIG_HIGHMEM
	/*
	 * A memory area that is only addressable by the kernel through
	 * mapping portions into its own address space. This is for example
	 * used by i386 to allow the kernel to address the memory beyond
	 * 900MB. The kernel will set up special mappings (page
	 * table entries on i386) for each page that the kernel needs to
	 * access.
	 */
	ZONE_HIGHMEM,
#endif
	ZONE_MOVABLE,
	__MAX_NR_ZONES
};

#ifndef __GENERATING_BOUNDS_H

/* 内存管理区描述符 */
struct zone {
	/* Read-mostly fields */

	/* zone watermarks, access with *_wmark_pages(zone) macros */
	/* 包括pages_min,pages_low,pages_high
	 * pages_min: 管理区中保留页的数目
	 * pages_low: 回收页框使用的下界，同时也被管理区分配器作为阀值使用，一般这个数字是pages_min的5/4
	 * pages_high: 回收页框使用的上界，同时也被管理区分配器作为阀值使用，一般这个数字是pages_min的3/2
	 */
	/* pages_min < page_low < page_high
	 * 快速内存分配期间，会用low
	 * 慢速内存分配期间，会用min
	 * 当可用页框数量小于pages_high时会调用kswapd
	 */
	unsigned long watermark[NR_WMARK];

	/*
	 * We don't know if the memory that we're going to allocate will be freeable
	 * or/and it will be released eventually, so to avoid totally wasting several
	 * GB of ram we must reserve some of the lower zone memory (otherwise we risk
	 * to run OOM on the lower zones despite there's tons of freeable ram
	 * on the higher zones). This array is recalculated at runtime if the
	 * sysctl_lowmem_reserve_ratio sysctl changes.
	 */
	/* 指明在处理内存不足的临界情况下管理区必须保留的页框数目，同时也用于在中断或临界区发出的原子内存分配请求(就是禁止阻塞的内存分配请求)
	 * 有ALLOC_NO_WATERMARKS标志才可以使用的内存
	 */
	long lowmem_reserve[MAX_NR_ZONES];

#ifdef CONFIG_NUMA
	/* 在NUMA中才使用，ZONE的node结点ID号 */
	int node;
#endif

	/*
	 * The target ratio of ACTIVE_ANON to INACTIVE_ANON pages on
	 * this zone's LRU.  Maintained by the pageout code.
	 */
	/* 在swap时用于zone判断非活动匿名页是否处于低阀值，inactive * zone->inactive_ratio < active，如果成立，那么zone的非活动匿名页属于low水平
	 */
	/* 经验公式ratio等于 根号(10 * 管理区内存以GB为大小的数量): 
	 * total 	target	  max
	 * memory 	ratio	  inactive anon
	 * -------------------------------------
	 *	10MB	   1		 5MB
	 *  100MB	   1		50MB
	 *	 1GB	   3	   250MB
	 *	10GB	  10	   0.9GB
	 *  100GB	  31		 3GB
	 *	 1TB	 101		10GB
	 *	10TB	 320		32GB
	 */
	unsigned int inactive_ratio;

	/* 指向此管理区属于的结点 */
	struct pglist_data	*zone_pgdat;
	/* 实现每CPU页框高速缓存，里面包含每个CPU的单页框的链表 */
	struct per_cpu_pageset __percpu *pageset;

	/*
	 * This is a per-zone reserve of pages that should not be
	 * considered dirtyable memory.
	 */
	unsigned long		dirty_balance_reserve;

#ifndef CONFIG_SPARSEMEM
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
	/* 会指向一个位图，每2^pageblock_order个页框为一个pageblock，每2^pageblock_order个页框占4位，设置此组页框的类型(MIGRATE_MOVABLE,MIGRATE_UNMOVABLE等) */
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */

#ifdef CONFIG_NUMA
	/*
	 * zone reclaim becomes active if more unmapped pages exist.
	 */
	/* 此zone的可回收内存页数量必须要超过此值，才能进行内存回收 */
	unsigned long		min_unmapped_pages;
	/* 此zone可回收slab页数量大于此数，才能进行slab回收 */
	unsigned long		min_slab_pages;
#endif /* CONFIG_NUMA */

	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	/* 管理区第一个页框下标 */
	unsigned long		zone_start_pfn;

	/*
	 * spanned_pages is the total pages spanned by the zone, including
	 * holes, which is calculated as:
	 * 	spanned_pages = zone_end_pfn - zone_start_pfn;
	 *
	 * present_pages is physical pages existing within the zone, which
	 * is calculated as:
	 *	present_pages = spanned_pages - absent_pages(pages in holes);
	 *
	 * managed_pages is present pages managed by the buddy system, which
	 * is calculated as (reserved_pages includes pages allocated by the
	 * bootmem allocator):
	 *	managed_pages = present_pages - reserved_pages;
	 *
	 * So present_pages may be used by memory hotplug or memory power
	 * management logic to figure out unmanaged pages by checking
	 * (present_pages - managed_pages). And managed_pages should be used
	 * by page allocator and vm scanner to calculate all kinds of watermarks
	 * and thresholds.
	 *
	 * Locking rules:
	 *
	 * zone_start_pfn and spanned_pages are protected by span_seqlock.
	 * It is a seqlock because it has to be read outside of zone->lock,
	 * and it is done in the main allocator path.  But, it is written
	 * quite infrequently.
	 *
	 * The span_seq lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 *
	 * Write access to present_pages at runtime should be protected by
	 * mem_hotplug_begin/end(). Any reader who can't tolerant drift of
	 * present_pages should get_online_mems() to get a stable value.
	 *
	 * Read access to managed_pages should be safe because it's unsigned
	 * long. Write access to zone->managed_pages and totalram_pages are
	 * protected by managed_page_count_lock at runtime. Idealy only
	 * adjust_managed_page_count() should be used instead of directly
	 * touching zone->managed_pages and totalram_pages.
	 */
	/* 所有正常情况下可用的页，总页数(不包括洞)减去保留的页数 */
	unsigned long		managed_pages;
	/* 管理区总大小(页为单位)，包括洞 */
	unsigned long		spanned_pages;
	/* 管理区总大小(页为单位)，不包括洞 */
	unsigned long		present_pages;
	/* 指向管理区的传统名称，"DMA" "NORMAL" "HighMem" */
	const char		*name;

	/*
	 * Number of MIGRATE_RESEVE page block. To maintain for just
	 * optimization. Protected by zone->lock.
	 */
	/* 对应于伙伴系统中MIGRATE_RESEVE链的页块的数量 */
	int			nr_migrate_reserve_block;

#ifdef CONFIG_MEMORY_ISOLATION
	/*
	 * Number of isolated pageblock. It is used to solve incorrect
	 * freepage counting problem due to racy retrieving migratetype
	 * of pageblock. Protected by zone->lock.
	 */
	/* 在内存隔离中表示隔离的页框块数量 */
	unsigned long		nr_isolate_pageblock;
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
	/* see spanned/present_pages for more description */
	seqlock_t		span_seqlock;
#endif

	/*
	 * wait_table		-- the array holding the hash table
	 * wait_table_hash_nr_entries	-- the size of the hash table array
	 * wait_table_bits	-- wait_table_size == (1 << wait_table_bits)
	 *
	 * The purpose of all these is to keep track of the people
	 * waiting for a page to become available and make them
	 * runnable again when possible. The trouble is that this
	 * consumes a lot of space, especially when so few things
	 * wait on pages at a given time. So instead of using
	 * per-page waitqueues, we use a waitqueue hash table.
	 *
	 * The bucket discipline is to sleep on the same queue when
	 * colliding and wake all in that wait queue when removing.
	 * When something wakes, it must check to be sure its page is
	 * truly available, a la thundering herd. The cost of a
	 * collision is great, but given the expected load of the
	 * table, they should be so rare as to be outweighed by the
	 * benefits from the saved space.
	 *
	 * __wait_on_page_locked() and unlock_page() in mm/filemap.c, are the
	 * primary users of these fields, and in mm/page_alloc.c
	 * free_area_init_core() performs the initialization of them.
	 */
	/* 进程等待队列的hash表，这些进程在等待管理区中的某页 */
	wait_queue_head_t	*wait_table;
	/* 等待队列散列表的大小 */
	unsigned long		wait_table_hash_nr_entries;
	/* 等待队列散列表数组大小 */
	unsigned long		wait_table_bits;

	ZONE_PADDING(_pad1_)

	/* Write-intensive fields used from the page allocator */
	/* 保护该描述符的自旋锁 */
	spinlock_t		lock;

	/* free areas of different sizes */
	/* 标识出管理区中的空闲页框块，用于伙伴系统 */
	/* MAX_ORDER为11，分别代表包含大小为1,2,4,8,16,32,64,128,256,512,1024个连续页框的链表 */
	struct free_area	free_area[MAX_ORDER];

	/* zone flags, see below */
	/* 管理区标识 */
	unsigned long		flags;

	ZONE_PADDING(_pad2_)

	/* Write-intensive fields used by page reclaim */

	/* Fields commonly accessed by the page reclaim scanner */
	/* lru链表使用的自旋锁 
	 * 当需要修改lru链表描述符中任何一个链表时，都需要持有此锁，也就是说，不会有两个不同的lru链表同时进行修改
	 */
	spinlock_t		lru_lock;
	/* lru链表描述符 */
	struct lruvec		lruvec;

	/* Evictions & activations on the inactive file list */
	/* 在lru_inacitve_file链表上的页移动到lru_activate_file或者回收时需要的访问次数 */
	atomic_long_t		inactive_age;

	/*
	 * When free pages are below this point, additional steps are taken
	 * when reading the number of free pages to avoid per-cpu counter
	 * drift allowing watermarks to be breached
	 */
	unsigned long percpu_drift_mark;

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* 以下两个参数保存的是内存压缩的两个扫描的起始位置 */

	/* 空闲页框扫描起始位置，开始设置时是管理区的最后一个页框
	 * 在内存压缩扫描可以移动的页时，从本次内存压缩开始到此pageblock结束都没有隔离出可移动页时，会将此值设置为pageblock的最后一页
	 * 此值默认是zone的结束页框
	 */
	unsigned long		compact_cached_free_pfn;
	/* pfn where async and sync compaction migration scanner should start */
	/* 0用于异步，1用于同步，用于保存管理区可移动页框扫描起始位置 
	 * 在内存压缩扫描空闲页时，从本次内存压缩开始到此pageblock结束都没有隔离出空闲页时，会将此值设置为pageblock的最后一页
	 * 此值默认是zone的开始页框
	 */
	unsigned long		compact_cached_migrate_pfn[2];
#endif

#ifdef CONFIG_COMPACTION
	/*
	 * On compaction failure, 1<<compact_defer_shift compactions
	 * are skipped before trying again. The number attempted since
	 * last failure is tracked with compact_considered.
	 */
	/* 这两个用于推迟内存压缩处理，只有当内存压缩时使用的order大于compact_order_failed才会推迟 
	 * 只有一种情况会重置这两个值:在zone执行内存压缩后，从此zone中分配到了内存，会重置
	 */
	/* 用于判断是否需要推迟，每次推迟会++，然后判断是否超过 1UL << compact_defer_shift，超过了则要进行内存压缩
	 */
	unsigned int		compact_considered;
	/* 用于保存最大推迟次数，当次管理区的内存压缩成功后被置0，不会大于COMPACT_MAX_DEFER_SHIFT
	 * 只有在同步和轻同步模式下进行内存压缩后，zone的空闲页框数量没达到 (low阀值 + 1<<order + 保留内存) 时，才会增加此值
	 */
	unsigned int		compact_defer_shift;
	/* 
	 * 表示zone内存压缩失败时使用的最大order值，此值会影响是否推迟内存压缩
	 * 当进行内存压缩时，使用的order小于此值，则允许进行内存压缩，否则记一次推迟
	 * 当内存压缩完成时，此值为使用的order值+1，意思是假设大一级的order在压缩中会失败
	 * 当内存压缩失败时，此值则是等于order值，表示使用此大小的order值，有可能会导致失败
	 */
	int			compact_order_failed;
#endif

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* Set to true when the PG_migrate_skip bits should be cleared */
	/* 如果为真，则清除页描述符的PG_migrate_skip标志，此标志用于表示此页是否可以进行内存压缩扫描
	 * 在完全扫描完一次后(cc->free_pfn <= cc->migrate_pfn)，如果不是kswapd完成的，那就对此设置为真
	 */
	bool			compact_blockskip_flush;
#endif

	ZONE_PADDING(_pad3_)
	/* 管理区的一些统计数据 
	 * isolated 应该小于 (inactive + active) / 2
	 */
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];
} ____cacheline_internodealigned_in_smp;

enum zone_flags {
	ZONE_RECLAIM_LOCKED,		/* prevents concurrent reclaim */
	ZONE_OOM_LOCKED,		/* zone is in OOM killer zonelist */
	/* 表示zone有许多脏页阻塞在设备回写的地方(设备非常繁忙)，此标志会影响等待设备的进程是否加入到设备的等待队列中
	 * 具体见wait_iff_congested()
	 * 此标志会在kswapd中当zone达到平衡后清除
	 */
	ZONE_CONGESTED,			/* zone has many dirty pages backed by
					 * a congested BDI
					 */
	/* 回收扫描最近找到了很多脏页放到了lru链表尾部 
	 * 此标志会在kswapd中当zone达到平衡后清除
	 */
	ZONE_DIRTY,			/* reclaim scanning has recently found
					 * many dirty file pages at the tail
					 * of the LRU.
					 */
	/* 回收扫描发现zone许多页在回写，但是这些页并不一定是回收导致的回写 
	 * 当进行内存回收时，所有隔离出来的页都正在回写(PG_writeback置位)，那么说明磁盘很忙，此zone很多页要进行回写，则置位此值
	 * 此标志会在kswapd对此zone进行内存回收后清除
	 */
	ZONE_WRITEBACK,			/* reclaim scanning has recently found
					 * many pages under writeback
					 */
	/* 可用于其他zone的页框数量已经用尽 */
	ZONE_FAIR_DEPLETED,		/* fair zone policy batch depleted */
};

static inline unsigned long zone_end_pfn(const struct zone *zone)
{
	return zone->zone_start_pfn + zone->spanned_pages;
}

static inline bool zone_spans_pfn(const struct zone *zone, unsigned long pfn)
{
	return zone->zone_start_pfn <= pfn && pfn < zone_end_pfn(zone);
}

static inline bool zone_is_initialized(struct zone *zone)
{
	return !!zone->wait_table;
}

static inline bool zone_is_empty(struct zone *zone)
{
	return zone->spanned_pages == 0;
}

/*
 * The "priority" of VM scanning is how much of the queues we will scan in one
 * go. A value of 12 for DEF_PRIORITY implies that we will scan 1/4096th of the
 * queues ("queue_length >> 12") during an aging round.
 */
#define DEF_PRIORITY 12

/* Maximum number of zones on a zonelist */
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)

#ifdef CONFIG_NUMA

/*
 * The NUMA zonelists are doubled because we need zonelists that restrict the
 * allocations to a single node for __GFP_THISNODE.
 *
 * [0]	: Zonelist with fallback
 * [1]	: No fallback (__GFP_THISNODE)
 */
#define MAX_ZONELISTS 2


/*
 * We cache key information from each zonelist for smaller cache
 * footprint when scanning for free pages in get_page_from_freelist().
 *
 * 1) The BITMAP fullzones tracks which zones in a zonelist have come
 *    up short of free memory since the last time (last_fullzone_zap)
 *    we zero'd fullzones.
 * 2) The array z_to_n[] maps each zone in the zonelist to its node
 *    id, so that we can efficiently evaluate whether that node is
 *    set in the current tasks mems_allowed.
 *
 * Both fullzones and z_to_n[] are one-to-one with the zonelist,
 * indexed by a zones offset in the zonelist zones[] array.
 *
 * The get_page_from_freelist() routine does two scans.  During the
 * first scan, we skip zones whose corresponding bit in 'fullzones'
 * is set or whose corresponding node in current->mems_allowed (which
 * comes from cpusets) is not set.  During the second scan, we bypass
 * this zonelist_cache, to ensure we look methodically at each zone.
 *
 * Once per second, we zero out (zap) fullzones, forcing us to
 * reconsider nodes that might have regained more free memory.
 * The field last_full_zap is the time we last zapped fullzones.
 *
 * This mechanism reduces the amount of time we waste repeatedly
 * reexaming zones for free memory when they just came up low on
 * memory momentarilly ago.
 *
 * The zonelist_cache struct members logically belong in struct
 * zonelist.  However, the mempolicy zonelists constructed for
 * MPOL_BIND are intentionally variable length (and usually much
 * shorter).  A general purpose mechanism for handling structs with
 * multiple variable length members is more mechanism than we want
 * here.  We resort to some special case hackery instead.
 *
 * The MPOL_BIND zonelists don't need this zonelist_cache (in good
 * part because they are shorter), so we put the fixed length stuff
 * at the front of the zonelist struct, ending in a variable length
 * zones[], as is needed by MPOL_BIND.
 *
 * Then we put the optional zonelist cache on the end of the zonelist
 * struct.  This optional stuff is found by a 'zlcache_ptr' pointer in
 * the fixed length portion at the front of the struct.  This pointer
 * both enables us to find the zonelist cache, and in the case of
 * MPOL_BIND zonelists, (which will just set the zlcache_ptr to NULL)
 * to know that the zonelist cache is not there.
 *
 * The end result is that struct zonelists come in two flavors:
 *  1) The full, fixed length version, shown below, and
 *  2) The custom zonelists for MPOL_BIND.
 * The custom MPOL_BIND zonelists have a NULL zlcache_ptr and no zlcache.
 *
 * Even though there may be multiple CPU cores on a node modifying
 * fullzones or last_full_zap in the same zonelist_cache at the same
 * time, we don't lock it.  This is just hint data - if it is wrong now
 * and then, the allocator will still function, perhaps a bit slower.
 */


struct zonelist_cache {
	unsigned short z_to_n[MAX_ZONES_PER_ZONELIST];		/* zone->nid */
	DECLARE_BITMAP(fullzones, MAX_ZONES_PER_ZONELIST);	/* zone full? */
	unsigned long last_full_zap;		/* when last zap'd (jiffies) */
};
#else
#define MAX_ZONELISTS 1
struct zonelist_cache;
#endif

/*
 * This struct contains information about a zone in a zonelist. It is stored
 * here to avoid dereferences into large structures and lookups of tables
 */
struct zoneref {
	/* 指向活动的zone描述符 */
	struct zone *zone;	
	/* 0是 ZONE_DMA , 1是 ZONE_NORMAL , 2是 ZONE_HIGHMEM , 3是 ZONE_MOVABLE */
	int zone_idx;		/* zone_idx(zoneref->zone) */
};

/*
 * One allocation request operates on a zonelist. A zonelist
 * is a list of zones, the first one is the 'goal' of the
 * allocation, the other zones are fallback zones, in decreasing
 * priority.
 *
 * If zlcache_ptr is not NULL, then it is just the address of zlcache,
 * as explained above.  If zlcache_ptr is NULL, there is no zlcache.
 * *
 * To speed the reading of the zonelist, the zonerefs contain the zone index
 * of the entry being read. Helper functions to access information given
 * a struct zoneref are
 *
 * zonelist_zone()	- Return the struct zone * for an entry in _zonerefs
 * zonelist_zone_idx()	- Return the index of the zone for an entry
 * zonelist_node_idx()	- Return the index of the node for an entry
 */
struct zonelist {
	/* 空 或者 &zlcache */
	struct zonelist_cache *zlcache_ptr;		     // NULL or &zlcache
	/* zone的一个数组，里面包含zone的指针和zone的id */
	struct zoneref _zonerefs[MAX_ZONES_PER_ZONELIST + 1];
#ifdef CONFIG_NUMA
	struct zonelist_cache zlcache;			     // optional ...
#endif
};

#ifdef CONFIG_HAVE_MEMBLOCK_NODE_MAP
struct node_active_region {
	unsigned long start_pfn;
	unsigned long end_pfn;
	int nid;
};
#endif /* CONFIG_HAVE_MEMBLOCK_NODE_MAP */

#ifndef CONFIG_DISCONTIGMEM
/* The array of struct pages - for discontigmem use pgdat->lmem_map */
extern struct page *mem_map;
#endif

/*
 * The pg_data_t structure is used in machines with CONFIG_DISCONTIGMEM
 * (mostly NUMA machines?) to denote a higher-level memory zone than the
 * zone denotes.
 *
 * On NUMA machines, each NUMA node would have a pg_data_t to describe
 * it's memory layout.
 *
 * Memory statistics and page replacement data structures are maintained on a
 * per-zone basis.
 */
struct bootmem_data;
/* 内存结点描述符，所有的结点描述符保存在 struct pglist_data *node_data[MAX_NUMNODES] 中 */
typedef struct pglist_data {
	/* 管理区描述符的数组 */
	struct zone node_zones[MAX_NR_ZONES]; 
	/* 页分配器使用的zonelist数据结构的数组，将所有结点的管理区按一定的关联链接成一个链表，分配内存时会按照此链表的顺序进行分配 */
	struct zonelist node_zonelists[MAX_ZONELISTS];
	/* 结点中管理区的个数 */
	int nr_zones;
#ifdef CONFIG_FLAT_NODE_MEM_MAP	/* means !SPARSEMEM */
	/* 当前结点中页描述符的数组，包含了此结点中所有页描述符，实际分配是是一个指针数组 */
	struct page *node_mem_map;
#ifdef CONFIG_MEMCG
	/* 用于资源限制机制 */
	struct page_cgroup *node_page_cgroup;
#endif
#endif
#ifndef CONFIG_NO_BOOTMEM
	/* 用在内核初始化阶段 */
	struct bootmem_data *bdata;
#endif
#ifdef CONFIG_MEMORY_HOTPLUG
	/*
	 * Must be held any time you expect node_start_pfn, node_present_pages
	 * or node_spanned_pages stay constant.  Holding this will also
	 * guarantee that any pfn_valid() stays that way.
	 *
	 * pgdat_resize_lock() and pgdat_resize_unlock() are provided to
	 * manipulate node_size_lock without checking for CONFIG_MEMORY_HOTPLUG.
	 *
	 * Nests above zone->lock and zone->span_seqlock
	 */
	/* 自旋锁 */
	spinlock_t node_size_lock;
#endif
	/* 结点中第一个页框的下标，在numa系统中，页框会有两个序号，所有页框的一个序号，还有就是在此结点中的一个序号
	 * 比如结点2中的页框1，它在结点2中的序号是1，但是在所有页框中的序号是1001，这个变量就是保存这个结点首页框的序号1000，用于方便转换
	 */
	unsigned long node_start_pfn;
	/* 内存结点的大小，不包括洞(以页框为单位) */
	unsigned long node_present_pages; 
	/* 结点的大小，包括洞(以页框为单位) */
	unsigned long node_spanned_pages; 
	
	/* 结点标识符 */
	int node_id;
	/* kswaped页换出守护进程使用的等待队列，当kswapd需要睡眠时，会把kswapd加入这个等待队列，需要调用kswapd时再把它从这个等待队列中唤醒
	 * 这个等待队列就专门用于kswapd的休眠和唤醒功能
	 */
	wait_queue_head_t kswapd_wait;
	/* 当内存不足时，会将进程挂到这个等待队列中，当swap回收内存后，会唤醒这里面的进程 */
	wait_queue_head_t pfmemalloc_wait;
	/* 指针指向kswapd内核线程的进程描述符 */
	struct task_struct *kswapd;	/* Protected by
					   mem_hotplug_begin/end() */
	/* kswapd将要释放的空闲块大小取对数的值，每次唤醒kswapd前都会设置此数，kswapd会以此数为目标进行释放 */
	int kswapd_max_order;
	/* kswapd唤醒时会根据此值尝试回收包含的管理区 */
	enum zone_type classzone_idx;
#ifdef CONFIG_NUMA_BALANCING
	/* 以下用于NUMA的负载均衡 */
	/* Lock serializing the migrate rate limiting window */
	spinlock_t numabalancing_migrate_lock;

	/* Rate limiting time interval */
	unsigned long numabalancing_migrate_next_window;

	/* Number of pages migrated during the rate limiting time interval */
	unsigned long numabalancing_migrate_nr_pages;
#endif
} pg_data_t;

#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#ifdef CONFIG_FLAT_NODE_MEM_MAP
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#else
#define pgdat_page_nr(pgdat, pagenr)	pfn_to_page((pgdat)->node_start_pfn + (pagenr))
#endif
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))

#define node_start_pfn(nid)	(NODE_DATA(nid)->node_start_pfn)
#define node_end_pfn(nid) pgdat_end_pfn(NODE_DATA(nid))

static inline unsigned long pgdat_end_pfn(pg_data_t *pgdat)
{
	return pgdat->node_start_pfn + pgdat->node_spanned_pages;
}

static inline bool pgdat_is_empty(pg_data_t *pgdat)
{
	return !pgdat->node_start_pfn && !pgdat->node_spanned_pages;
}

#include <linux/memory_hotplug.h>

extern struct mutex zonelists_mutex;
void build_all_zonelists(pg_data_t *pgdat, struct zone *zone);
void wakeup_kswapd(struct zone *zone, int order, enum zone_type classzone_idx);
bool zone_watermark_ok(struct zone *z, unsigned int order,
		unsigned long mark, int classzone_idx, int alloc_flags);
bool zone_watermark_ok_safe(struct zone *z, unsigned int order,
		unsigned long mark, int classzone_idx, int alloc_flags);
enum memmap_context {
	MEMMAP_EARLY,
	MEMMAP_HOTPLUG,
};
extern int init_currently_empty_zone(struct zone *zone, unsigned long start_pfn,
				     unsigned long size,
				     enum memmap_context context);

extern void lruvec_init(struct lruvec *lruvec);

static inline struct zone *lruvec_zone(struct lruvec *lruvec)
{
#ifdef CONFIG_MEMCG
	return lruvec->zone;
#else
	return container_of(lruvec, struct zone, lruvec);
#endif
}

#ifdef CONFIG_HAVE_MEMORY_PRESENT
void memory_present(int nid, unsigned long start, unsigned long end);
#else
static inline void memory_present(int nid, unsigned long start, unsigned long end) {}
#endif

#ifdef CONFIG_HAVE_MEMORYLESS_NODES
int local_memory_node(int node_id);
#else
static inline int local_memory_node(int node_id) { return node_id; };
#endif

#ifdef CONFIG_NEED_NODE_MEMMAP_SIZE
unsigned long __init node_memmap_size_bytes(int, unsigned long, unsigned long);
#endif

/*
 * zone_idx() returns 0 for the ZONE_DMA zone, 1 for the ZONE_NORMAL zone, etc.
 */
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

/* 此zone是否管理着页框，如果管理着页框，返回true，否则返回false */
static inline int populated_zone(struct zone *zone)
{
	return (!!zone->present_pages);
}

extern int movable_zone;

static inline int zone_movable_is_highmem(void)
{
#if defined(CONFIG_HIGHMEM) && defined(CONFIG_HAVE_MEMBLOCK_NODE_MAP)
	return movable_zone == ZONE_HIGHMEM;
#elif defined(CONFIG_HIGHMEM)
	return (ZONE_MOVABLE - 1) == ZONE_HIGHMEM;
#else
	return 0;
#endif
}

static inline int is_highmem_idx(enum zone_type idx)
{
#ifdef CONFIG_HIGHMEM
	return (idx == ZONE_HIGHMEM ||
		(idx == ZONE_MOVABLE && zone_movable_is_highmem()));
#else
	return 0;
#endif
}

/**
 * is_highmem - helper function to quickly check if a struct zone is a 
 *              highmem zone or not.  This is an attempt to keep references
 *              to ZONE_{DMA/NORMAL/HIGHMEM/etc} in general code to a minimum.
 * @zone - pointer to struct zone variable
 */
static inline int is_highmem(struct zone *zone)
{
#ifdef CONFIG_HIGHMEM
	int zone_off = (char *)zone - (char *)zone->zone_pgdat->node_zones;
	return zone_off == ZONE_HIGHMEM * sizeof(*zone) ||
	       (zone_off == ZONE_MOVABLE * sizeof(*zone) &&
		zone_movable_is_highmem());
#else
	return 0;
#endif
}

/* These two functions are used to setup the per zone pages min values */
struct ctl_table;
int min_free_kbytes_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
extern int sysctl_lowmem_reserve_ratio[MAX_NR_ZONES-1];
int lowmem_reserve_ratio_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
int percpu_pagelist_fraction_sysctl_handler(struct ctl_table *, int,
					void __user *, size_t *, loff_t *);
int sysctl_min_unmapped_ratio_sysctl_handler(struct ctl_table *, int,
			void __user *, size_t *, loff_t *);
int sysctl_min_slab_ratio_sysctl_handler(struct ctl_table *, int,
			void __user *, size_t *, loff_t *);

extern int numa_zonelist_order_handler(struct ctl_table *, int,
			void __user *, size_t *, loff_t *);
extern char numa_zonelist_order[];
#define NUMA_ZONELIST_ORDER_LEN 16	/* string buffer size */

#ifndef CONFIG_NEED_MULTIPLE_NODES

extern struct pglist_data contig_page_data;
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map

#else /* CONFIG_NEED_MULTIPLE_NODES */

#include <asm/mmzone.h>

#endif /* !CONFIG_NEED_MULTIPLE_NODES */

extern struct pglist_data *first_online_pgdat(void);
extern struct pglist_data *next_online_pgdat(struct pglist_data *pgdat);
extern struct zone *next_zone(struct zone *zone);

/**
 * for_each_online_pgdat - helper macro to iterate over all online nodes
 * @pgdat - pointer to a pg_data_t variable
 */
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
/**
 * for_each_zone - helper macro to iterate over all memory zones
 * @zone - pointer to struct zone variable
 *
 * The user only needs to declare the zone variable, for_each_zone
 * fills it in.
 */
/* 遍历所有node的所有zone */
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \	/* 获取第一个node的第一个zone */
	     zone;					\
	     zone = next_zone(zone))						/* 下一个zone，如果为此node的最后一个zone，则是下个node的第一个zone */

#define for_each_populated_zone(zone)		        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))			\
		if (!populated_zone(zone))		\
			; /* do nothing */		\
		else

static inline struct zone *zonelist_zone(struct zoneref *zoneref)
{
	return zoneref->zone;
}

static inline int zonelist_zone_idx(struct zoneref *zoneref)
{
	return zoneref->zone_idx;
}

static inline int zonelist_node_idx(struct zoneref *zoneref)
{
#ifdef CONFIG_NUMA
	/* zone_to_nid not available in this context */
	return zoneref->zone->node;
#else
	return 0;
#endif /* CONFIG_NUMA */
}

/**
 * next_zones_zonelist - Returns the next zone at or below highest_zoneidx within the allowed nodemask using a cursor within a zonelist as a starting point
 * @z - The cursor used as a starting point for the search
 * @highest_zoneidx - The zone index of the highest zone to return
 * @nodes - An optional nodemask to filter the zonelist with
 * @zone - The first suitable zone found is returned via this parameter
 *
 * This function returns the next zone at or below a given zone index that is
 * within the allowed nodemask using a cursor as the starting point for the
 * search. The zoneref returned is a cursor that represents the current zone
 * being examined. It should be advanced by one before calling
 * next_zones_zonelist again.
 */
struct zoneref *next_zones_zonelist(struct zoneref *z,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes,
					struct zone **zone);

/**
 * first_zones_zonelist - Returns the first zone at or below highest_zoneidx within the allowed nodemask in a zonelist
 * @zonelist - The zonelist to search for a suitable zone
 * @highest_zoneidx - The zone index of the highest zone to return
 * @nodes - An optional nodemask to filter the zonelist with
 * @zone - The first suitable zone found is returned via this parameter
 *
 * This function returns the first zone at or below a given zone index that is
 * within the allowed nodemask. The zoneref returned is a cursor that can be
 * used to iterate the zonelist with next_zones_zonelist by advancing it by
 * one before calling.
 */
static inline struct zoneref *first_zones_zonelist(struct zonelist *zonelist,
					enum zone_type highest_zoneidx,
					nodemask_t *nodes,
					struct zone **zone)
{
	return next_zones_zonelist(zonelist->_zonerefs, highest_zoneidx, nodes,
								zone);
}

/**
 * for_each_zone_zonelist_nodemask - helper macro to iterate over valid zones in a zonelist at or below a given zone index and within a nodemask
 * @zone - The current zone in the iterator
 * @z - The current pointer within zonelist->zones being iterated
 * @zlist - The zonelist being iterated
 * @highidx - The zone index of the highest zone to return
 * @nodemask - Nodemask allowed by the allocator
 *
 * This iterator iterates though all zones at or below a given zone index and
 * within a given nodemask
 */
#define for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (z = first_zones_zonelist(zlist, highidx, nodemask, &zone);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask, &zone))	\

/**
 * for_each_zone_zonelist - helper macro to iterate over valid zones in a zonelist at or below a given zone index
 * @zone - The current zone in the iterator
 * @z - The current pointer within zonelist->zones being iterated
 * @zlist - The zonelist being iterated
 * @highidx - The zone index of the highest zone to return
 *
 * This iterator iterates though all zones at or below a given zone index.
 */
#define for_each_zone_zonelist(zone, z, zlist, highidx) \
	for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, NULL)

#ifdef CONFIG_SPARSEMEM
#include <asm/sparsemem.h>
#endif

#if !defined(CONFIG_HAVE_ARCH_EARLY_PFN_TO_NID) && \
	!defined(CONFIG_HAVE_MEMBLOCK_NODE_MAP)
static inline unsigned long early_pfn_to_nid(unsigned long pfn)
{
	return 0;
}
#endif

#ifdef CONFIG_FLATMEM
#define pfn_to_nid(pfn)		(0)
#endif

#ifdef CONFIG_SPARSEMEM

/*
 * SECTION_SHIFT    		#bits space required to store a section #
 *
 * PA_SECTION_SHIFT		physical address to/from section number
 * PFN_SECTION_SHIFT		pfn to/from section number
 */
#define PA_SECTION_SHIFT	(SECTION_SIZE_BITS)
#define PFN_SECTION_SHIFT	(SECTION_SIZE_BITS - PAGE_SHIFT)

#define NR_MEM_SECTIONS		(1UL << SECTIONS_SHIFT)

#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGE_SECTION_MASK	(~(PAGES_PER_SECTION-1))

#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)

#if (MAX_ORDER - 1 + PAGE_SHIFT) > SECTION_SIZE_BITS
#error Allocator MAX_ORDER exceeds SECTION_SIZE
#endif

#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT)
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT)

#define SECTION_ALIGN_UP(pfn)	(((pfn) + PAGES_PER_SECTION - 1) & PAGE_SECTION_MASK)
#define SECTION_ALIGN_DOWN(pfn)	((pfn) & PAGE_SECTION_MASK)

struct page;
struct page_cgroup;
struct mem_section {
	/*
	 * This is, logically, a pointer to an array of struct
	 * pages.  However, it is stored with some other magic.
	 * (see sparse.c::sparse_init_one_section())
	 *
	 * Additionally during early boot we encode node id of
	 * the location of the section here to guide allocation.
	 * (see sparse.c::memory_present())
	 *
	 * Making it a UL at least makes someone do a cast
	 * before using it wrong.
	 */
	unsigned long section_mem_map;

	/* See declaration of similar field in struct zone */
	unsigned long *pageblock_flags;
#ifdef CONFIG_MEMCG
	/*
	 * If !SPARSEMEM, pgdat doesn't have page_cgroup pointer. We use
	 * section. (see memcontrol.h/page_cgroup.h about this.)
	 */
	struct page_cgroup *page_cgroup;
	unsigned long pad;
#endif
	/*
	 * WARNING: mem_section must be a power-of-2 in size for the
	 * calculation and use of SECTION_ROOT_MASK to make sense.
	 */
};

#ifdef CONFIG_SPARSEMEM_EXTREME
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#else
#define SECTIONS_PER_ROOT	1
#endif

#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define NR_SECTION_ROOTS	DIV_ROUND_UP(NR_MEM_SECTIONS, SECTIONS_PER_ROOT)
#define SECTION_ROOT_MASK	(SECTIONS_PER_ROOT - 1)

#ifdef CONFIG_SPARSEMEM_EXTREME
extern struct mem_section *mem_section[NR_SECTION_ROOTS];
#else
extern struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT];
#endif

static inline struct mem_section *__nr_to_section(unsigned long nr)
{
	if (!mem_section[SECTION_NR_TO_ROOT(nr)])
		return NULL;
	return &mem_section[SECTION_NR_TO_ROOT(nr)][nr & SECTION_ROOT_MASK];
}
extern int __section_nr(struct mem_section* ms);
extern unsigned long usemap_size(void);

/*
 * We use the lower bits of the mem_map pointer to store
 * a little bit of information.  There should be at least
 * 3 bits here due to 32-bit alignment.
 */
#define	SECTION_MARKED_PRESENT	(1UL<<0)
#define SECTION_HAS_MEM_MAP	(1UL<<1)
#define SECTION_MAP_LAST_BIT	(1UL<<2)
#define SECTION_MAP_MASK	(~(SECTION_MAP_LAST_BIT-1))
#define SECTION_NID_SHIFT	2

static inline struct page *__section_mem_map_addr(struct mem_section *section)
{
	unsigned long map = section->section_mem_map;
	map &= SECTION_MAP_MASK;
	return (struct page *)map;
}

static inline int present_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_MARKED_PRESENT));
}

static inline int present_section_nr(unsigned long nr)
{
	return present_section(__nr_to_section(nr));
}

static inline int valid_section(struct mem_section *section)
{
	return (section && (section->section_mem_map & SECTION_HAS_MEM_MAP));
}

static inline int valid_section_nr(unsigned long nr)
{
	return valid_section(__nr_to_section(nr));
}

static inline struct mem_section *__pfn_to_section(unsigned long pfn)
{
	return __nr_to_section(pfn_to_section_nr(pfn));
}

#ifndef CONFIG_HAVE_ARCH_PFN_VALID
static inline int pfn_valid(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return valid_section(__nr_to_section(pfn_to_section_nr(pfn)));
}
#endif

static inline int pfn_present(unsigned long pfn)
{
	if (pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS)
		return 0;
	return present_section(__nr_to_section(pfn_to_section_nr(pfn)));
}

/*
 * These are _only_ used during initialisation, therefore they
 * can use __initdata ...  They could have names to indicate
 * this restriction.
 */
#ifdef CONFIG_NUMA
#define pfn_to_nid(pfn)							\
({									\
	unsigned long __pfn_to_nid_pfn = (pfn);				\
	page_to_nid(pfn_to_page(__pfn_to_nid_pfn));			\
})
#else
#define pfn_to_nid(pfn)		(0)
#endif

#define early_pfn_valid(pfn)	pfn_valid(pfn)
void sparse_init(void);
#else
#define sparse_init()	do {} while (0)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#endif /* CONFIG_SPARSEMEM */

#ifdef CONFIG_NODES_SPAN_OTHER_NODES
bool early_pfn_in_nid(unsigned long pfn, int nid);
#else
#define early_pfn_in_nid(pfn, nid)	(1)
#endif

#ifndef early_pfn_valid
#define early_pfn_valid(pfn)	(1)
#endif

void memory_present(int nid, unsigned long start, unsigned long end);
unsigned long __init node_memmap_size_bytes(int, unsigned long, unsigned long);

/*
 * If it is possible to have holes within a MAX_ORDER_NR_PAGES, then we
 * need to check pfn validility within that MAX_ORDER_NR_PAGES block.
 * pfn_valid_within() should be used in this case; we optimise this away
 * when we have no holes within a MAX_ORDER_NR_PAGES block.
 */
#ifdef CONFIG_HOLES_IN_ZONE
#define pfn_valid_within(pfn) pfn_valid(pfn)
#else
#define pfn_valid_within(pfn) (1)
#endif

#ifdef CONFIG_ARCH_HAS_HOLES_MEMORYMODEL
/*
 * pfn_valid() is meant to be able to tell if a given PFN has valid memmap
 * associated with it or not. In FLATMEM, it is expected that holes always
 * have valid memmap as long as there is valid PFNs either side of the hole.
 * In SPARSEMEM, it is assumed that a valid section has a memmap for the
 * entire section.
 *
 * However, an ARM, and maybe other embedded architectures in the future
 * free memmap backing holes to save memory on the assumption the memmap is
 * never used. The page_zone linkages are then broken even though pfn_valid()
 * returns true. A walker of the full memmap must then do this additional
 * check to ensure the memmap they are looking at is sane by making sure
 * the zone and PFN linkages are still valid. This is expensive, but walkers
 * of the full memmap are extremely rare.
 */
int memmap_valid_within(unsigned long pfn,
					struct page *page, struct zone *zone);
#else
static inline int memmap_valid_within(unsigned long pfn,
					struct page *page, struct zone *zone)
{
	return 1;
}
#endif /* CONFIG_ARCH_HAS_HOLES_MEMORYMODEL */

#endif /* !__GENERATING_BOUNDS.H */
#endif /* !__ASSEMBLY__ */
#endif /* _LINUX_MMZONE_H */
