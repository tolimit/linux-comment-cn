#ifndef _LINUX_SLAB_DEF_H
#define	_LINUX_SLAB_DEF_H

#include <linux/reciprocal_div.h>

/*
 * Definitions unique to the original Linux SLAB allocator.
 */
/* slab/slub������������һ��SLAB����Ľṹ */
struct kmem_cache {
	/* ָ��������ж���ı��ظ��ٻ��棬ÿ��CPU��һ���ýṹ�����ж����ͷ�ʱ�����ȷ��뱾��CPU���ٻ����� */
	struct array_cache __percpu *cpu_cache;

/* 1) Cache tunables. Protected by slab_mutex */
	/* Ҫת�ƽ����ظ��ٻ����ӱ��ظ��ٻ�����ת�Ƴ�ȥ�Ķ�������� */
	unsigned int batchcount;
	/* ���ظ��ٻ����п��ж���������Ŀ */
	unsigned int limit;
	/* �Ƿ����CPU������ٻ��棬CPU������ٻ���ָ�뱣����kmem_cache_node�ṹ�� */
	unsigned int shared;

	/* ���󳤶� + ����ֽ� */
	unsigned int size;
	/* �������ӿ���� */
	struct reciprocal_value reciprocal_buffer_size;

	
/* 2) touched by every alloc & free from the backend */
	/* ���ٻ����������Եı�ʶ�����SLAB�����������ⲿ(������SLAB��)����CFLAGS_OFF_SLAB��1 */
	unsigned int flags;		/* constant flags */
	/* ÿ��slab�ж���ĸ���(��ͬһ�����ٻ�����slab�ж��������ͬ) */
	unsigned int num;		/* # of objs per slab */


/* 3) cache_grow/shrink */
	/* һ������SLAB�а���������ҳ����Ŀ�Ķ��� */
	unsigned int gfporder;

	/* ����ҳ��ʱ���ݸ����ϵͳ��һ���ʶ */
	gfp_t allocflags;

	/* SLABʹ�õ���ɫ���� */
	size_t colour;			
	/* SLAB�л�������ƫ�ƣ�����SLAB��ɫʱ��ƫ������ֵ��Ҫ���������������ƫ������������1��ƫ�������ڶ��ٸ�B��С��ֵ */
	unsigned int colour_off;	
	/* slab�����������ⲿʱʹ�ã���ָ��ĸ��ٻ������洢������ */
	struct kmem_cache *freelist_cache;
	/* ����slabͷ�Ĵ�С������SLAB�Ͷ���������������������������SLAB������ */
	unsigned int freelist_size;

	/* ���캯����һ�����ڳ�ʼ��������ٻ����еĶ��� */
	void (*ctor)(void *obj);


/* 4) cache creation/removal */
	/* ��Ÿ��ٻ������� */
	const char *name;
	/* ���ٻ���������˫������ָ�� */
	struct list_head list;
	int refcount;
	/* ���ٻ����ж���Ĵ�С */
	int object_size;
	int align;


/* 5) statistics */
	/* ͳ�� */
#ifdef CONFIG_DEBUG_SLAB
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	/* �������ʱֱ�Ӵ�CPU��SLAB������ٻ���������ɹ��Ĵ��� */
	atomic_t allochit;
	/* �������ʱû�д�CPU��SLAB������ٻ���������ɹ��Ĵ��� */
	atomic_t allocmiss;
	/* �����ͷ�ʱ�Żص�CPU��SLAB������ٻ���Ĵ��� */
	atomic_t freehit;
	/* �����ͷ�ʱû�зŻص�CPU��SLAB������ٻ���Ĵ��� */
	atomic_t freemiss;

	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	/* ������ƫ�� */
	int obj_offset;
#endif /* CONFIG_DEBUG_SLAB */
#ifdef CONFIG_MEMCG_KMEM
	/* ���ڷ�����Դ���� */
	struct memcg_cache_params *memcg_params;
#endif
	/* ��������˸��ٻ�������ڲ�ͬNUMA�Ľ�㶼��SLAB���� */
	struct kmem_cache_node *node[MAX_NUMNODES];
};

#endif	/* _LINUX_SLAB_DEF_H */
