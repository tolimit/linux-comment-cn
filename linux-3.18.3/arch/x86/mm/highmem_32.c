#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/swap.h> /* for totalram_pages */
#include <linux/bootmem.h>

void *kmap(struct page *page)
{
	might_sleep();
	if (!PageHighMem(page))
		return page_address(page);
	return kmap_high(page);
}
EXPORT_SYMBOL(kmap);

void kunmap(struct page *page)
{
	if (in_interrupt())
		BUG();
	if (!PageHighMem(page))
		return;
	kunmap_high(page);
}
EXPORT_SYMBOL(kunmap);

/*
 * kmap_atomic/kunmap_atomic is significantly faster than kmap/kunmap because
 * no global lock is needed and because the kmap code must perform a global TLB
 * invalidation when the kmap pool wraps.
 *
 * However when holding an atomic kmap it is not legal to sleep, so atomic
 * kmaps are appropriate for short, tight code paths only.
 */
/* �����߶��ڴ���ʱӳ�� */
/* ÿ��CPU�� KM_TYPE_NR �����ڹ��߶��ڴ���ʱӳ�� */
void *kmap_atomic_prot(struct page *page, pgprot_t prot)
{
	unsigned long vaddr;
	int idx, type;

	/* even !CONFIG_PREEMPT needs this, for in_atomic in do_page_fault */
	/* ��ֹȱҳ�쳣 */
	pagefault_disable();

	/* #define PageHighMem(__p) is_highmem(page_zone(__p)) */
	/* ����ҳ���Ƿ��ڸ߶��ڴ� */
	if (!PageHighMem(page))
		return page_address(page);

	/* ��ȡ��CPU����һ������ʹ�õ� kmap ���� */
	type = kmap_atomic_idx_push();
	/* ����һ�����Ե�ַ��ƫ���� */
	idx = type + KM_TYPE_NR*smp_processor_id();
	/* FIX_KMAP_BEGIN ��һ������Ŀ�ʼ��ַ���������������ڸ߶��ڴ���ʱӳ�� */
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
	BUG_ON(!pte_none(*(kmap_pte-idx)));
	/* д��kmap_pte��Ӧ��ҳ������ */
	set_pte(kmap_pte-idx, mk_pte(page, prot));
	/* ˢ��tlb */
	arch_flush_lazy_mmu_mode();

	return (void *)vaddr;
}
EXPORT_SYMBOL(kmap_atomic_prot);

void *kmap_atomic(struct page *page)
{
	return kmap_atomic_prot(page, kmap_prot);
}
EXPORT_SYMBOL(kmap_atomic);

/*
 * This is the same as kmap_atomic() but can map memory that doesn't
 * have a struct page associated with it.
 */
void *kmap_atomic_pfn(unsigned long pfn)
{
	return kmap_atomic_prot_pfn(pfn, kmap_prot);
}
EXPORT_SYMBOL_GPL(kmap_atomic_pfn);

void __kunmap_atomic(void *kvaddr)
{
	unsigned long vaddr = (unsigned long) kvaddr & PAGE_MASK;

	if (vaddr >= __fix_to_virt(FIX_KMAP_END) &&
	    vaddr <= __fix_to_virt(FIX_KMAP_BEGIN)) {
		int idx, type;

		type = kmap_atomic_idx();
		idx = type + KM_TYPE_NR * smp_processor_id();

#ifdef CONFIG_DEBUG_HIGHMEM
		WARN_ON_ONCE(vaddr != __fix_to_virt(FIX_KMAP_BEGIN + idx));
#endif
		/*
		 * Force other mappings to Oops if they'll try to access this
		 * pte without first remap it.  Keeping stale mappings around
		 * is a bad idea also, in case the page changes cacheability
		 * attributes or becomes a protected page in a hypervisor.
		 */
		kpte_clear_flush(kmap_pte-idx, vaddr);
		kmap_atomic_idx_pop();
		arch_flush_lazy_mmu_mode();
	}
#ifdef CONFIG_DEBUG_HIGHMEM
	else {
		BUG_ON(vaddr < PAGE_OFFSET);
		BUG_ON(vaddr >= (unsigned long)high_memory);
	}
#endif

	pagefault_enable();
}
EXPORT_SYMBOL(__kunmap_atomic);

struct page *kmap_atomic_to_page(void *ptr)
{
	unsigned long idx, vaddr = (unsigned long)ptr;
	pte_t *pte;

	if (vaddr < FIXADDR_START)
		return virt_to_page(ptr);

	idx = virt_to_fix(vaddr);
	pte = kmap_pte - (idx - FIX_KMAP_BEGIN);
	return pte_page(*pte);
}
EXPORT_SYMBOL(kmap_atomic_to_page);

/* ���и߶��ڴ��������ʼ����������node������zone��managed_pages��Ϊ0���������ǵ�ҳ����յ�ҳ��������� */
void __init set_highmem_pages_init(void)
{
	struct zone *zone;
	int nid;

	/*
	 * Explicitly reset zone->managed_pages because set_highmem_pages_init()
	 * is invoked before free_all_bootmem()
	 */
	/* ������node������zone��managed_pages��Ϊ0���������й�������������ҳ��������Ϊ0 */
	reset_all_zones_managed_pages();
	
	/* �������й�����������ֻ��ʼ���߶��ڴ��� */
	for_each_zone(zone) {
		unsigned long zone_start_pfn, zone_end_pfn;

		/* ������Ǹ߶��ڴ���������һ�� */
		/* �жϷ���: ��ǰzone��������ַ - ����node��zone�������������ַ == �߶��ڴ���ƫ���� */
		if (!is_highmem(zone))
			continue;

		/* �ù�������ʼҳ��� */
		zone_start_pfn = zone->zone_start_pfn;
		/* �ù���������ҳ��� */
		zone_end_pfn = zone_start_pfn + zone->spanned_pages;

		/* �ù�����������node���� */
		nid = zone_to_nid(zone);
		printk(KERN_INFO "Initializing %s for node %d (%08lx:%08lx)\n",
				zone->name, nid, zone_start_pfn, zone_end_pfn);
		
		/* ��start_pfn��end_pfn������ҳ����գ�������ҳ������� */
		add_highpages_with_active_regions(nid, zone_start_pfn,
				 zone_end_pfn);
	}
}
