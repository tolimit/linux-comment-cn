/*
 *  linux/mm/mempool.c
 *
 *  memory buffer pool support. Such pools are mostly used
 *  for guaranteed, deadlock-free memory allocations during
 *  extreme VM load.
 *
 *  started by Ingo Molnar, Copyright (C) 2001
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kmemleak.h>
#include <linux/export.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>

static void add_element(mempool_t *pool, void *element)
{
	BUG_ON(pool->curr_nr >= pool->min_nr);
	pool->elements[pool->curr_nr++] = element;
}

static void *remove_element(mempool_t *pool)
{
	BUG_ON(pool->curr_nr <= 0);
	return pool->elements[--pool->curr_nr];
}

/**
 * mempool_destroy - deallocate a memory pool
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 *
 * Free all reserved elements in @pool and @pool itself.  This function
 * only sleeps if the free_fn() function sleeps.
 */
/* ����һ���ڴ�� */
void mempool_destroy(mempool_t *pool)
{
	while (pool->curr_nr) {
		/* ����elements�����е����ж��� */
		/* element = pool->elements[--pool->curr_nr] */
		void *element = remove_element(pool);
		pool->free(element, pool->pool_data);
	}
	/* ����elementsָ������ */
	kfree(pool->elements);
	/* �����ڴ�ؽṹ�� */
	kfree(pool);
}
EXPORT_SYMBOL(mempool_destroy);

/**
 * mempool_create - create a memory pool
 * @min_nr:    the minimum number of elements guaranteed to be
 *             allocated for this pool.
 * @alloc_fn:  user-defined element-allocation function.
 * @free_fn:   user-defined element-freeing function.
 * @pool_data: optional private data available to the user-defined functions.
 *
 * this function creates and allocates a guaranteed size, preallocated
 * memory pool. The pool can be used from the mempool_alloc() and mempool_free()
 * functions. This function might sleep. Both the alloc_fn() and the free_fn()
 * functions might sleep - as long as the mempool_alloc() function is not called
 * from IRQ contexts.
 */
/* ����һ���ڴ��
 * min_nr: �ڴ���д�ŵĶ�������
 * alloc_fn: ���亯��
 * free_fn: �ͷź���
 * pool_data: ˽�г�Ա����
 */
mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
				mempool_free_t *free_fn, void *pool_data)
{
	return mempool_create_node(min_nr,alloc_fn,free_fn, pool_data,
				   GFP_KERNEL, NUMA_NO_NODE);
}
EXPORT_SYMBOL(mempool_create);

mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
			       mempool_free_t *free_fn, void *pool_data,
			       gfp_t gfp_mask, int node_id)
{
	mempool_t *pool;
	/* ����һ���ڴ�ؽṹ�� */
	pool = kzalloc_node(sizeof(*pool), gfp_mask, node_id);
	if (!pool)
		return NULL;
	/* ����һ������Ϊmin_nr���������ڴ�����������ָ�� */
	pool->elements = kmalloc_node(min_nr * sizeof(void *),
				      gfp_mask, node_id);
	if (!pool->elements) {
		kfree(pool);
		return NULL;
	}
	/* ��ʼ���� */
	spin_lock_init(&pool->lock);
	pool->min_nr = min_nr;
	/* ˽�г�Ա�������ڴ���Ǵ�slab��������ȡ�ڴ����ʱ���ɽ���˽�г�Ա����ΪĿ��slab������ */
	pool->pool_data = pool_data;
	/* ��ʼ���ȴ����� */
	init_waitqueue_head(&pool->wait);
	pool->alloc = alloc_fn;
	pool->free = free_fn;

	/*
	 * First pre-allocate the guaranteed number of buffers.
	 */
	/* pool->curr_nr��ʼΪ0����Ϊpoolʹ��kzalloc_node����ģ�����0 */
	while (pool->curr_nr < pool->min_nr) {
		void *element;

		/* ����pool->alloc����min_nr�� */
		element = pool->alloc(gfp_mask, pool->pool_data);
		/* ������벻��element����ֱ�����ٴ��ڴ�� */
		if (unlikely(!element)) {
			mempool_destroy(pool);
			return NULL;
		}
		/* ��ӵ�elementsָ�������� */
		add_element(pool, element);
	}
	/* �����ڴ�ؽṹ�� */
	return pool;
}
EXPORT_SYMBOL(mempool_create_node);

/**
 * mempool_resize - resize an existing memory pool
 * @pool:       pointer to the memory pool which was allocated via
 *              mempool_create().
 * @new_min_nr: the new minimum number of elements guaranteed to be
 *              allocated for this pool.
 * @gfp_mask:   the usual allocation bitmask.
 *
 * This function shrinks/grows the pool. In the case of growing,
 * it cannot be guaranteed that the pool will be grown to the new
 * size immediately, but new mempool_free() calls will refill it.
 *
 * Note, the caller must guarantee that no mempool_destroy is called
 * while this function is running. mempool_alloc() & mempool_free()
 * might be called (eg. from IRQ contexts) while this function executes.
 */
int mempool_resize(mempool_t *pool, int new_min_nr, gfp_t gfp_mask)
{
	void *element;
	void **new_elements;
	unsigned long flags;

	BUG_ON(new_min_nr <= 0);

	spin_lock_irqsave(&pool->lock, flags);
	if (new_min_nr <= pool->min_nr) {
		while (new_min_nr < pool->curr_nr) {
			element = remove_element(pool);
			spin_unlock_irqrestore(&pool->lock, flags);
			pool->free(element, pool->pool_data);
			spin_lock_irqsave(&pool->lock, flags);
		}
		pool->min_nr = new_min_nr;
		goto out_unlock;
	}
	spin_unlock_irqrestore(&pool->lock, flags);

	/* Grow the pool */
	new_elements = kmalloc(new_min_nr * sizeof(*new_elements), gfp_mask);
	if (!new_elements)
		return -ENOMEM;

	spin_lock_irqsave(&pool->lock, flags);
	if (unlikely(new_min_nr <= pool->min_nr)) {
		/* Raced, other resize will do our work */
		spin_unlock_irqrestore(&pool->lock, flags);
		kfree(new_elements);
		goto out;
	}
	memcpy(new_elements, pool->elements,
			pool->curr_nr * sizeof(*new_elements));
	kfree(pool->elements);
	pool->elements = new_elements;
	pool->min_nr = new_min_nr;

	while (pool->curr_nr < pool->min_nr) {
		spin_unlock_irqrestore(&pool->lock, flags);
		element = pool->alloc(gfp_mask, pool->pool_data);
		if (!element)
			goto out;
		spin_lock_irqsave(&pool->lock, flags);
		if (pool->curr_nr < pool->min_nr) {
			add_element(pool, element);
		} else {
			spin_unlock_irqrestore(&pool->lock, flags);
			pool->free(element, pool->pool_data);	/* Raced */
			goto out;
		}
	}
out_unlock:
	spin_unlock_irqrestore(&pool->lock, flags);
out:
	return 0;
}
EXPORT_SYMBOL(mempool_resize);

/**
 * mempool_alloc - allocate an element from a specific memory pool
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 * @gfp_mask:  the usual allocation bitmask.
 *
 * this function only sleeps if the alloc_fn() function sleeps or
 * returns NULL. Note that due to preallocation, this function
 * *never* fails when called from process contexts. (it might
 * fail if called from an IRQ context.)
 * Note: using __GFP_ZERO is not supported.
 */
/* �ڴ�ط������ */
void * mempool_alloc(mempool_t *pool, gfp_t gfp_mask)
{
	void *element;
	unsigned long flags;
	wait_queue_t wait;
	gfp_t gfp_temp;

	VM_WARN_ON_ONCE(gfp_mask & __GFP_ZERO);
	/* �����__GFP_WAIT��־��������������л����� */
	might_sleep_if(gfp_mask & __GFP_WAIT);

	/* ��ʹ��Ԥ���ڴ� */
	gfp_mask |= __GFP_NOMEMALLOC;	/* don't allocate emergency reserves */
	/* ����ҳʱ���ʧ���򷵻أ����������� */
	gfp_mask |= __GFP_NORETRY;	/* don't loop in __alloc_pages */
	/* ����ʧ�ܲ��ṩ���� */
	gfp_mask |= __GFP_NOWARN;	/* failures are OK */

	/* gfp_temp����gfp_maskȥ��__GFP_WAIT��__GFP_IO��������־ */
	gfp_temp = gfp_mask & ~(__GFP_WAIT|__GFP_IO);

repeat_alloc:

	/* ʹ���ڴ���е�alloc�������з������ʵ���Ͼ��Ǵӻ��ϵͳ����slab��������ȡ�ڴ���� */
	element = pool->alloc(gfp_temp, pool->pool_data);
	/* ���ڴ渻�������£�һ�����ܹ���ȡ���ڴ�� */
	if (likely(element != NULL))
		return element;

	/* ���ڴ治����������ɴӻ��ϵͳ��slab��������ȡ�ڴ�ʧ�ܣ����ִ�е��� */
	/* ���ڴ����������ȡ��˶��ٽ�����ֹ�жϺ���ռ */
	spin_lock_irqsave(&pool->lock, flags);
	/* �����ǰ�ڴ�����п������������ǳ�ʼ��ʱ��ȡ���ڴ�����������curr_nr�� */
	if (likely(pool->curr_nr)) {
		/* ���ڴ���л�ȡ�ڴ���� */
		element = remove_element(pool);
		/* ���� */
		spin_unlock_irqrestore(&pool->lock, flags);
		
		/* paired with rmb in mempool_free(), read comment there */
		/* д�ڴ����ϣ���֤֮ǰ��д�����Ѿ���� */
		smp_wmb();
		/*
		 * Update the allocation stack trace as this is more useful
		 * for debugging.
		 */
		/* ����debug */
		kmemleak_update_trace(element);
		return element;
	}

	/*
	 * We use gfp mask w/o __GFP_WAIT or IO for the first round.  If
	 * alloc failed with that and @pool was empty, retry immediately.
	 */
	/* �������ڴ����Ҳû�п����ڴ�����ʱ����еĲ��� */
	/* gfp_temp != gfp_mask˵�������gfp_mask���������ȴ�������֮ǰ�Ѿ������ȴ����ˣ����������������»�ȡһ�� */
	if (gfp_temp != gfp_mask) {
		spin_unlock_irqrestore(&pool->lock, flags);
		gfp_temp = gfp_mask;
		goto repeat_alloc;
	}

	/* We must not sleep if !__GFP_WAIT */
	/* ����Ĳ���gfp_mask�����������ȴ������䲻���ڴ���ֱ���˳� */
	if (!(gfp_mask & __GFP_WAIT)) {
		spin_unlock_irqrestore(&pool->lock, flags);
		return NULL;
	}

	/* Let's wait for someone else to return an element to @pool */
	init_wait(&wait);
	/* ���뵽�ڴ�صĵȴ������У����ѵ�ǰ���̵�״̬����Ϊֻ��wake_up�źŲ��ܻ��ѵ�״̬��Ҳ���ǵ��ڴ�����п��ж���ʱ�����������ѵȴ������еĵ�һ�����̣����ߵȴ���ʱʱ����ʱ���Զ����� */
	prepare_to_wait(&pool->wait, &wait, TASK_UNINTERRUPTIBLE);

	spin_unlock_irqrestore(&pool->lock, flags);

	/*
	 * FIXME: this should be io_schedule().  The timeout is there as a
	 * workaround for some DM problems in 2.6.18.
	 */
	/* �����ȴ�5�� */
	io_schedule_timeout(5*HZ);

	/* ���ڴ�صĵȴ�����ɾ���˽��� */
	finish_wait(&pool->wait, &wait);
	/* ��ת��repeat_alloc�����³��Ի�ȡ�ڴ���� */
	goto repeat_alloc;
}
EXPORT_SYMBOL(mempool_alloc);

/**
 * mempool_free - return an element to the pool.
 * @element:   pool element pointer.
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 *
 * this function only sleeps if the free_fn() function sleeps.
 */
/* �ڴ���ͷ��ڴ������� */
void mempool_free(void *element, mempool_t *pool)
{
	unsigned long flags;

	/* ����Ķ���Ϊ�գ���ֱ���˳� */
	if (unlikely(element == NULL))
		return;

	/*
	 * Paired with the wmb in mempool_alloc().  The preceding read is
	 * for @element and the following @pool->curr_nr.  This ensures
	 * that the visible value of @pool->curr_nr is from after the
	 * allocation of @element.  This is necessary for fringe cases
	 * where @element was passed to this task without going through
	 * barriers.
	 *
	 * For example, assume @p is %NULL at the beginning and one task
	 * performs "p = mempool_alloc(...);" while another task is doing
	 * "while (!p) cpu_relax(); mempool_free(p, ...);".  This function
	 * may end up using curr_nr value which is from before allocation
	 * of @p without the following rmb.
	 */
	/* ���ڴ����� */
	smp_rmb();

	/*
	 * For correctness, we need a test which is guaranteed to trigger
	 * if curr_nr + #allocated == min_nr.  Testing curr_nr < min_nr
	 * without locking achieves that and refilling as soon as possible
	 * is desirable.
	 *
	 * Because curr_nr visible here is always a value after the
	 * allocation of @element, any task which decremented curr_nr below
	 * min_nr is guaranteed to see curr_nr < min_nr unless curr_nr gets
	 * incremented to min_nr afterwards.  If curr_nr gets incremented
	 * to min_nr after the allocation of @element, the elements
	 * allocated after that are subject to the same guarantee.
	 *
	 * Waiters happen iff curr_nr is 0 and the above guarantee also
	 * ensures that there will be frees which return elements to the
	 * pool waking up the waiters.
	 */
	/* �����ǰ�ڴ���п��е��ڴ���������ڴ����Ӧ��������ڴ���������ʱ�����Ȱ��ͷŵĶ�����뵽�ڴ�ؿ��������� */
	if (unlikely(pool->curr_nr < pool->min_nr)) {
		spin_lock_irqsave(&pool->lock, flags);
		if (likely(pool->curr_nr < pool->min_nr)) {
			/* ���뵽pool->elements[pool->curr_nr++]�� */
			add_element(pool, element);
			spin_unlock_irqrestore(&pool->lock, flags);
			/* ���ѵȴ������еĵ�һ������ */
			wake_up(&pool->wait);
			return;
		}
		spin_unlock_irqrestore(&pool->lock, flags);
	}
	/* ֱ�ӵ����ͷź��� */
	pool->free(element, pool->pool_data);
}
EXPORT_SYMBOL(mempool_free);

/*
 * A commonly used alloc and free fn.
 */
/* ���ڴ�ش�slab�������л�ȡ�ڴ�������ں��ṩ��alloc���� */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data)
{
	struct kmem_cache *mem = pool_data;
	return kmem_cache_alloc(mem, gfp_mask);
}
EXPORT_SYMBOL(mempool_alloc_slab);

/* ���ڴ�ش�slab�������л�ȡ�ڴ�������ں��ṩ��free���� */
void mempool_free_slab(void *element, void *pool_data)
{
	struct kmem_cache *mem = pool_data;
	kmem_cache_free(mem, element);
}
EXPORT_SYMBOL(mempool_free_slab);

/*
 * A commonly used alloc and free fn that kmalloc/kfrees the amount of memory
 * specified by pool_data
 */
void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data)
{
	size_t size = (size_t)pool_data;
	return kmalloc(size, gfp_mask);
}
EXPORT_SYMBOL(mempool_kmalloc);

void mempool_kfree(void *element, void *pool_data)
{
	kfree(element);
}
EXPORT_SYMBOL(mempool_kfree);

/*
 * A simple mempool-backed page allocator that allocates pages
 * of the order specified by pool_data.
 */
void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data)
{
	int order = (int)(long)pool_data;
	return alloc_pages(gfp_mask, order);
}
EXPORT_SYMBOL(mempool_alloc_pages);

void mempool_free_pages(void *element, void *pool_data)
{
	int order = (int)(long)pool_data;
	__free_pages(element, order);
}
EXPORT_SYMBOL(mempool_free_pages);
