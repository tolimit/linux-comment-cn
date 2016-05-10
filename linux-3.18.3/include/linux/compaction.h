#ifndef _LINUX_COMPACTION_H
#define _LINUX_COMPACTION_H

/* Return values for compact_zone() and try_to_compact_pages() */
/* compaction didn't start as it was deferred due to past failures */
#define COMPACT_DEFERRED	0
/* compaction didn't start as it was not possible or direct reclaim was more suitable */
/* 内存数量不足以支持进行内存压缩 */
#define COMPACT_SKIPPED		1
/* compaction should continue to another pageblock */
/* 可以进行内存压缩 */
#define COMPACT_CONTINUE	2
/* direct compaction partially compacted a zone and there are suitable pages */
/* 不需要进行内存压缩 */
#define COMPACT_PARTIAL		3
/* The full zone was compacted */
#define COMPACT_COMPLETE	4

/* Used to signal whether compaction detected need_sched() or lock contention */
/* No contention detected */
#define COMPACT_CONTENDED_NONE	0
/* Either need_sched() was true or fatal signal pending */
/* 压缩时需要调度或者进程准备被杀死 */
#define COMPACT_CONTENDED_SCHED	1
/* Zone lock or lru_lock was contended in async compaction */
/* 异步压缩中zone->lock或者lru_lock处于竞争状态 */
#define COMPACT_CONTENDED_LOCK	2

#ifdef CONFIG_COMPACTION
extern int sysctl_compact_memory;
extern int sysctl_compaction_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos);
extern int sysctl_extfrag_threshold;
extern int sysctl_extfrag_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos);

extern int fragmentation_index(struct zone *zone, unsigned int order);
extern unsigned long try_to_compact_pages(struct zonelist *zonelist,
			int order, gfp_t gfp_mask, nodemask_t *mask,
			enum migrate_mode mode, int *contended,
			struct zone **candidate_zone);
extern void compact_pgdat(pg_data_t *pgdat, int order);
extern void reset_isolation_suitable(pg_data_t *pgdat);
extern unsigned long compaction_suitable(struct zone *zone, int order);

/* Do not skip compaction more than 64 times */
#define COMPACT_MAX_DEFER_SHIFT 6

/*
 * Compaction is deferred when compaction fails to result in a page
 * allocation success. 1 << compact_defer_limit compactions are skipped up
 * to a limit of 1 << COMPACT_MAX_DEFER_SHIFT
 */
/* 推迟压缩，提高推迟压缩阀值计数器
 * 此函数在zone进行内存压缩之后，还是无法从此zone获取连续页框时调用，为了让此zone更多的推迟进行内存压缩，反正短期内在此zone进行内存压缩也没有效果
 */
static inline void defer_compaction(struct zone *zone, int order)
{
	zone->compact_considered = 0;
	/* 推迟限制阀值++ */
	zone->compact_defer_shift++;

	/* 此zone此次压缩失败的order值保存到zone->compact_order_failed */
	if (order < zone->compact_order_failed)
		zone->compact_order_failed = order;

	/* 推迟计数器最多只能等于COMPACT_MAX_DEFER_SHIFT */
	if (zone->compact_defer_shift > COMPACT_MAX_DEFER_SHIFT)
		zone->compact_defer_shift = COMPACT_MAX_DEFER_SHIFT;
}

/* Returns true if compaction should be skipped this time */
/* 用于推迟本次内存压缩，但是有个限度，这个限度就是 1 << zone->compact_defer_shift */
static inline bool compaction_deferred(struct zone *zone, int order)
{
	unsigned long defer_limit = 1UL << zone->compact_defer_shift;

	/* 本次请求的order值小于之前失败时的order值，那这次压缩必须要进行 */
	if (order < zone->compact_order_failed)
		return false;

	/* Avoid possible overflow */
	if (++zone->compact_considered > defer_limit)
		zone->compact_considered = defer_limit;

	/* 小于推迟次数，那就推迟 */
	return zone->compact_considered < defer_limit;
}

/*
 * Update defer tracking counters after successful compaction of given order,
 * which means an allocation either succeeded (alloc_success == true) or is
 * expected to succeed.
 */
/* 在内存压缩完成后调用，当内存压缩成功后，会重置压缩推迟计数器
 * 而不确定是否成功时，只是设置了zone->compact_order_failed = order + 1
 */
static inline void compaction_defer_reset(struct zone *zone, int order,
		bool alloc_success)
{
	/* 是因为分配成功导致重置压缩推迟的 */
	if (alloc_success) {
		zone->compact_considered = 0;
		zone->compact_defer_shift = 0;
	}
	/* 如果本次压缩成功了，则将compact_order_failed设置为本次压缩的order + 1 */
	if (order >= zone->compact_order_failed)
		zone->compact_order_failed = order + 1;
}

/* Returns true if restarting compaction after many failures */
/* 推迟次数compact_considered超过了最大推迟次数COMPACT_MAX_DEFER_SHIFT则开始 */
static inline bool compaction_restarting(struct zone *zone, int order)
{
	if (order < zone->compact_order_failed)
		return false;

	return zone->compact_defer_shift == COMPACT_MAX_DEFER_SHIFT &&
		zone->compact_considered >= 1UL << zone->compact_defer_shift;
}

#else
static inline unsigned long try_to_compact_pages(struct zonelist *zonelist,
			int order, gfp_t gfp_mask, nodemask_t *nodemask,
			enum migrate_mode mode, int *contended,
			struct zone **candidate_zone)
{
	return COMPACT_CONTINUE;
}

static inline void compact_pgdat(pg_data_t *pgdat, int order)
{
}

static inline void reset_isolation_suitable(pg_data_t *pgdat)
{
}

static inline unsigned long compaction_suitable(struct zone *zone, int order)
{
	return COMPACT_SKIPPED;
}

static inline void defer_compaction(struct zone *zone, int order)
{
}

static inline bool compaction_deferred(struct zone *zone, int order)
{
	return true;
}

#endif /* CONFIG_COMPACTION */

#if defined(CONFIG_COMPACTION) && defined(CONFIG_SYSFS) && defined(CONFIG_NUMA)
extern int compaction_register_node(struct node *node);
extern void compaction_unregister_node(struct node *node);

#else

static inline int compaction_register_node(struct node *node)
{
	return 0;
}

static inline void compaction_unregister_node(struct node *node)
{
}
#endif /* CONFIG_COMPACTION && CONFIG_SYSFS && CONFIG_NUMA */

#endif /* _LINUX_COMPACTION_H */
