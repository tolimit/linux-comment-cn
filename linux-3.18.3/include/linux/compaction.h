#ifndef _LINUX_COMPACTION_H
#define _LINUX_COMPACTION_H

/* Return values for compact_zone() and try_to_compact_pages() */
/* compaction didn't start as it was deferred due to past failures */
#define COMPACT_DEFERRED	0
/* compaction didn't start as it was not possible or direct reclaim was more suitable */
/* �ڴ�����������֧�ֽ����ڴ�ѹ�� */
#define COMPACT_SKIPPED		1
/* compaction should continue to another pageblock */
/* ���Խ����ڴ�ѹ�� */
#define COMPACT_CONTINUE	2
/* direct compaction partially compacted a zone and there are suitable pages */
/* ����Ҫ�����ڴ�ѹ�� */
#define COMPACT_PARTIAL		3
/* The full zone was compacted */
#define COMPACT_COMPLETE	4

/* Used to signal whether compaction detected need_sched() or lock contention */
/* No contention detected */
#define COMPACT_CONTENDED_NONE	0
/* Either need_sched() was true or fatal signal pending */
/* ѹ��ʱ��Ҫ���Ȼ��߽���׼����ɱ�� */
#define COMPACT_CONTENDED_SCHED	1
/* Zone lock or lru_lock was contended in async compaction */
/* �첽ѹ����zone->lock����lru_lock���ھ���״̬ */
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
/* �Ƴ�ѹ��������Ƴ�ѹ����ֵ������
 * �˺�����zone�����ڴ�ѹ��֮�󣬻����޷��Ӵ�zone��ȡ����ҳ��ʱ���ã�Ϊ���ô�zone������Ƴٽ����ڴ�ѹ���������������ڴ�zone�����ڴ�ѹ��Ҳû��Ч��
 */
static inline void defer_compaction(struct zone *zone, int order)
{
	zone->compact_considered = 0;
	/* �Ƴ����Ʒ�ֵ++ */
	zone->compact_defer_shift++;

	/* ��zone�˴�ѹ��ʧ�ܵ�orderֵ���浽zone->compact_order_failed */
	if (order < zone->compact_order_failed)
		zone->compact_order_failed = order;

	/* �Ƴټ��������ֻ�ܵ���COMPACT_MAX_DEFER_SHIFT */
	if (zone->compact_defer_shift > COMPACT_MAX_DEFER_SHIFT)
		zone->compact_defer_shift = COMPACT_MAX_DEFER_SHIFT;
}

/* Returns true if compaction should be skipped this time */
/* �����Ƴٱ����ڴ�ѹ���������и��޶ȣ�����޶Ⱦ��� 1 << zone->compact_defer_shift */
static inline bool compaction_deferred(struct zone *zone, int order)
{
	unsigned long defer_limit = 1UL << zone->compact_defer_shift;

	/* ���������orderֵС��֮ǰʧ��ʱ��orderֵ�������ѹ������Ҫ���� */
	if (order < zone->compact_order_failed)
		return false;

	/* Avoid possible overflow */
	if (++zone->compact_considered > defer_limit)
		zone->compact_considered = defer_limit;

	/* С���Ƴٴ������Ǿ��Ƴ� */
	return zone->compact_considered < defer_limit;
}

/*
 * Update defer tracking counters after successful compaction of given order,
 * which means an allocation either succeeded (alloc_success == true) or is
 * expected to succeed.
 */
/* ���ڴ�ѹ����ɺ���ã����ڴ�ѹ���ɹ��󣬻�����ѹ���Ƴټ�����
 * ����ȷ���Ƿ�ɹ�ʱ��ֻ��������zone->compact_order_failed = order + 1
 */
static inline void compaction_defer_reset(struct zone *zone, int order,
		bool alloc_success)
{
	/* ����Ϊ����ɹ���������ѹ���Ƴٵ� */
	if (alloc_success) {
		zone->compact_considered = 0;
		zone->compact_defer_shift = 0;
	}
	/* �������ѹ���ɹ��ˣ���compact_order_failed����Ϊ����ѹ����order + 1 */
	if (order >= zone->compact_order_failed)
		zone->compact_order_failed = order + 1;
}

/* Returns true if restarting compaction after many failures */
/* �Ƴٴ���compact_considered����������Ƴٴ���COMPACT_MAX_DEFER_SHIFT��ʼ */
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
