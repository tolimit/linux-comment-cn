#ifndef _LINUX_SLUB_DEF_H
#define _LINUX_SLUB_DEF_H

/*
 * SLUB : A Slab allocator without object queues.
 *
 * (C) 2007 SGI, Christoph Lameter
 */
#include <linux/kobject.h>

enum stat_item {
	ALLOC_FASTPATH,		/* Allocation from cpu slab */
	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
	FREE_FASTPATH,		/* Free to cpu slab */
	FREE_SLOWPATH,		/* Freeing not to cpu slab */
	FREE_FROZEN,		/* Freeing to frozen slab */
	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
	FREE_SLAB,		/* Slab freed to the page allocator */
	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
	DEACTIVATE_BYPASS,	/* Implicit deactivation */
	ORDER_FALLBACK,		/* Number of times fallback was necessary */
	CMPXCHG_DOUBLE_CPU_FAIL,/* Failure of this_cpu_cmpxchg_double */
	CMPXCHG_DOUBLE_FAIL,	/* Number of times that cmpxchg double did not match */
	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
	NR_SLUB_STAT_ITEMS };

struct kmem_cache_cpu {
	/* ָ����һ�����ж������ڿ����ҵ����� */
	void **freelist;	/* Pointer to next available object */
	/* ���ڱ�֤cmpxchg_double���㷢������ȷ��CPU�ϣ����ҿ���Ϊһ������֤����ͬʱ�������kmem_cache_cpu�Ķ��� */
	unsigned long tid;	/* Globally unique transaction id */
	/* CPU��ǰ��ʹ�õ�slab��������������freelist��ָ���slab����һ�����ж��� */
	struct page *page;	/* The slab from which we are allocating */
	/* CPU�Ĳ��ֿ�slab�����ŵ�CPU�Ĳ��ֿ�slab�����е�slab�ᱻ���ᣬ������node�еĲ��ֿ�slab������ⶳ�������־��slab�������������� */
	struct page *partial;	/* Partially allocated frozen slabs */
#ifdef CONFIG_SLUB_STATS
	unsigned stat[NR_SLUB_STAT_ITEMS];
#endif
};

/*
 * Word size structure that can be atomically updated or read and that
 * contains both the order and the number of objects that a slab of the
 * given order would contain.
 */
struct kmem_cache_order_objects {
	unsigned long x;
};

/*
 * Slab cache management.
 */
struct kmem_cache {
	/* ÿ��CPU�ı��� */
	struct kmem_cache_cpu __percpu *cpu_slab;
	/* Used for retriving partial slabs etc */
	/* ��־ */
	unsigned long flags;
	/* ÿ��node����в��ֿ�slab�������������ܵ������ֵ�����node�����slab�����������������ֵ���ǿ����ͷŵĿ���slab�����������ͷţ�������Щ����slab�������������ͷ� */
	unsigned long min_partial;
	/* �����������ڴ��С(���ܴ��ڶ����ʵ�ʴ�С�����������ߵ��¸����ж���ָ��) */
	int size;		/* The size of an object including meta data */
	/* �����ʵ�ʴ�С */
	int object_size;	/* The size of an object without meta data */
	/* ��ſ��ж���ָ���ƫ���� */
	int offset;		/* Free pointer offset. */
	/* cpu�Ŀ���objects������Χ���ֵ */
	int cpu_partial;	/* Number of per cpu partial objects to keep around */
	/* ����slab��������Ҫ��ҳ��������orderֵ��objects������ֵ��ͨ�����ֵ���Լ������Ҫ����ҳ�������Ĭ��ֵ */
	struct kmem_cache_order_objects oo;

	/* Allocation and freeing of slabs */
	/* ����slab��������Ҫ��ҳ��������orderֵ��objects������ֵ����������ֵ */
	struct kmem_cache_order_objects max;
	/* ����slab��������Ҫ��ҳ��������orderֵ��objects������ֵ���������Сֵ����Ĭ��ֵoo����ʧ��ʱ���᳢������Сֵȥ��������ҳ�� */
	struct kmem_cache_order_objects min;
	/* ÿһ�η���ʱ��ʹ�õı�־ */
	gfp_t allocflags;	/* gfp flags to use on each alloc */
	/* �����������������û����󴴽��µĻ�����ʱ��SLUB �����������Ѵ��������ƴ�С�Ļ��������Ӷ����ٻ������ĸ����� */
	int refcount;		/* Refcount for slab cache destroy */
	/* ����slabʱ�Ĺ��캯�� */
	void (*ctor)(void *);
	/* Ԫ���ݵ�ƫ���� */
	int inuse;		/* Offset to metadata */
	/* ���� */
	int align;		/* Alignment */
	int reserved;		/* Reserved bytes at the end of slabs */
	/* ���ٻ������� */
	const char *name;	/* Name (only for display!) */
	/* ���е� kmem_cache�ṹ�������������������ͷ�� slab_caches */
	struct list_head list;	/* List of slab caches */
#ifdef CONFIG_SYSFS
	/* ����sysfs�ļ�ϵͳ����/sys�л��и�slub��ר��Ŀ¼ */
	struct kobject kobj;	/* For sysfs */
#endif
#ifdef CONFIG_MEMCG_KMEM
	/* ��������Ҫ����memory cgroup�ģ��Ȳ��� */
	struct memcg_cache_params *memcg_params;
	int max_attr_size; /* for propagation, maximum size of a stored attr */
#ifdef CONFIG_SYSFS
	struct kset *memcg_kset;
#endif
#endif

#ifdef CONFIG_NUMA
	/*
	 * Defragmentation by allocating from a remote node.
	 */
	/* ��ֵԽС��Խ�������ڱ���������� */
	int remote_node_defrag_ratio;
#endif
	/* �˸��ٻ����SLAB����ÿ��NUMA�����һ�����п��ܸø��ٻ�����ЩSLAB������������� */
	struct kmem_cache_node *node[MAX_NUMNODES];
};

#ifdef CONFIG_SYSFS
#define SLAB_SUPPORTS_SYSFS
void sysfs_slab_remove(struct kmem_cache *);
#else
static inline void sysfs_slab_remove(struct kmem_cache *s)
{
}
#endif

#endif /* _LINUX_SLUB_DEF_H */
