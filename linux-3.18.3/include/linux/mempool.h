/*
 * memory buffer pool support
 */
#ifndef _LINUX_MEMPOOL_H
#define _LINUX_MEMPOOL_H

#include <linux/wait.h>

struct kmem_cache;

typedef void * (mempool_alloc_t)(gfp_t gfp_mask, void *pool_data);
typedef void (mempool_free_t)(void *element, void *pool_data);

/* �ڴ�أ�����ӵ�и��ڴ�ص�"ӵ����"�����ڴ洢����ֻ���ڳ�������·��䲻���ڴ��ʱ��Ż�ʹ���Լ����ڴ�� */
typedef struct mempool_s {
	spinlock_t lock;
	/* ���Ԫ�ظ�����Ҳ�ǳ�ʼ���� */
	int min_nr;		/* nr of elements at *elements */
	/* ��ǰԪ�ظ��� */
	int curr_nr;		/* Current nr of elements at *elements */
	/* ָ��һ�����飬�����б���ָ��Ԫ��ָ�룬������alloc������ָ��Ż���Ч */
	void **elements;

	/* �ڴ�ص�ӵ���ߵ�˽�����ݽṹ����Ԫ����slab�еĶ���ʱ�����ﱣ�����slab���������� */
	void *pool_data;
	/* ��Ԫ����slab�еĶ���ʱ����ʹ�÷���mempool_alloc_slab()��mempool_free_slab() */
	/* ����һ��Ԫ�صķ��� */
	mempool_alloc_t *alloc;
	/* �ͷ�һ��Ԫ�صķ��� */
	mempool_free_t *free;
	/* ���ڴ��Ϊ��ʱʹ�õĵȴ����� */
	wait_queue_head_t wait;
} mempool_t;

extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data);
extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data,
			gfp_t gfp_mask, int nid);

extern int mempool_resize(mempool_t *pool, int new_min_nr, gfp_t gfp_mask);
extern void mempool_destroy(mempool_t *pool);
extern void * mempool_alloc(mempool_t *pool, gfp_t gfp_mask);
extern void mempool_free(void *element, mempool_t *pool);

/*
 * A mempool_alloc_t and mempool_free_t that get the memory from
 * a slab that is passed in through pool_data.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
void mempool_free_slab(void *element, void *pool_data);
static inline mempool_t *
mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
{
	return mempool_create(min_nr, mempool_alloc_slab, mempool_free_slab,
			      (void *) kc);
}

/*
 * a mempool_alloc_t and a mempool_free_t to kmalloc and kfree the
 * amount of memory specified by pool_data
 */
void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data);
void mempool_kfree(void *element, void *pool_data);
static inline mempool_t *mempool_create_kmalloc_pool(int min_nr, size_t size)
{
	return mempool_create(min_nr, mempool_kmalloc, mempool_kfree,
			      (void *) size);
}

/*
 * A mempool_alloc_t and mempool_free_t for a simple page allocator that
 * allocates pages of the order specified by pool_data
 */
void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data);
void mempool_free_pages(void *element, void *pool_data);
static inline mempool_t *mempool_create_page_pool(int min_nr, int order)
{
	return mempool_create(min_nr, mempool_alloc_pages, mempool_free_pages,
			      (void *)(long)order);
}

#endif /* _LINUX_MEMPOOL_H */
