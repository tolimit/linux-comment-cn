#include <linux/gfp.h>
#include <linux/initrd.h>
#include <linux/ioport.h>
#include <linux/swap.h>
#include <linux/memblock.h>
#include <linux/bootmem.h>	/* for max_low_pfn */

#include <asm/cacheflush.h>
#include <asm/e820.h>
#include <asm/init.h>
#include <asm/page.h>
#include <asm/page_types.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/tlbflush.h>
#include <asm/tlb.h>
#include <asm/proto.h>
#include <asm/dma.h>		/* for MAX_DMA_PFN */
#include <asm/microcode.h>

/*
 * We need to define the tracepoints somewhere, and tlb.c
 * is only compied when SMP=y.
 */
#define CREATE_TRACE_POINTS
#include <trace/events/tlb.h>

#include "mm_internal.h"

static unsigned long __initdata pgt_buf_start;
static unsigned long __initdata pgt_buf_end;
static unsigned long __initdata pgt_buf_top;

static unsigned long min_pfn_mapped;

static bool __initdata can_use_brk_pgt = true;

/*
 * Pages returned are already directly mapped.
 *
 * Changing that is likely to break Xen, see commit:
 *
 *    279b706 x86,xen: introduce x86_init.mapping.pagetable_reserve
 *
 * for detailed information.
 */
__ref void *alloc_low_pages(unsigned int num)
{
	unsigned long pfn;
	int i;

	/* 用伙伴系统进行分配 */
	if (after_bootmem) {
		unsigned int order;

		order = get_order((unsigned long)num << PAGE_SHIFT);
		/* 原子分配，禁止阻塞，必要时可以从保留内存池中获取 */
		return (void *)__get_free_pages(GFP_ATOMIC | __GFP_NOTRACK |
						__GFP_ZERO, order);
	}

	/* 从bootmem分配器分配页框 */
	if ((pgt_buf_end + num) > pgt_buf_top || !can_use_brk_pgt) {
		unsigned long ret;
		if (min_pfn_mapped >= max_pfn_mapped)
			panic("alloc_low_pages: ran out of memory");
		ret = memblock_find_in_range(min_pfn_mapped << PAGE_SHIFT,
					max_pfn_mapped << PAGE_SHIFT,
					PAGE_SIZE * num , PAGE_SIZE);
		if (!ret)
			panic("alloc_low_pages: can not alloc memory");
		memblock_reserve(ret, PAGE_SIZE * num);
		pfn = ret >> PAGE_SHIFT;
	} else {
		pfn = pgt_buf_end;
		pgt_buf_end += num;
		printk(KERN_DEBUG "BRK [%#010lx, %#010lx] PGTABLE\n",
			pfn << PAGE_SHIFT, (pgt_buf_end << PAGE_SHIFT) - 1);
	}

	for (i = 0; i < num; i++) {
		void *adr;

		adr = __va((pfn + i) << PAGE_SHIFT);
		clear_page(adr);
	}

	return __va(pfn << PAGE_SHIFT);
}

/* need 3 4k for initial PMD_SIZE,  3 4k for 0-ISA_END_ADDRESS */
#define INIT_PGT_BUF_SIZE	(6 * PAGE_SIZE)
RESERVE_BRK(early_pgt_alloc, INIT_PGT_BUF_SIZE);
void  __init early_alloc_pgt_buf(void)
{
	unsigned long tables = INIT_PGT_BUF_SIZE;
	phys_addr_t base;

	base = __pa(extend_brk(tables, PAGE_SIZE));

	pgt_buf_start = base >> PAGE_SHIFT;
	pgt_buf_end = pgt_buf_start;
	pgt_buf_top = pgt_buf_start + (tables >> PAGE_SHIFT);
}

int after_bootmem;

int direct_gbpages
#ifdef CONFIG_DIRECT_GBPAGES
				= 1
#endif
;

static void __init init_gbpages(void)
{
#ifdef CONFIG_X86_64
	if (direct_gbpages && cpu_has_gbpages)
		printk(KERN_INFO "Using GB pages for direct mapping\n");
	else
		direct_gbpages = 0;
#endif
}

struct map_range {
	unsigned long start;
	unsigned long end;
	unsigned page_size_mask;
};

static int page_size_mask;

static void __init probe_page_size_mask(void)
{
	init_gbpages();

#if !defined(CONFIG_DEBUG_PAGEALLOC) && !defined(CONFIG_KMEMCHECK)
	/*
	 * For CONFIG_DEBUG_PAGEALLOC, identity mapping will use small pages.
	 * This will simplify cpa(), which otherwise needs to support splitting
	 * large pages into small in interrupt context, etc.
	 */
	if (direct_gbpages)
		page_size_mask |= 1 << PG_LEVEL_1G;
	if (cpu_has_pse)
		page_size_mask |= 1 << PG_LEVEL_2M;
#endif

	/* Enable PSE if available */
	if (cpu_has_pse)
		set_in_cr4(X86_CR4_PSE);

	/* Enable PGE if available */
	if (cpu_has_pge) {
		set_in_cr4(X86_CR4_PGE);
		__supported_pte_mask |= _PAGE_GLOBAL;
	}
}

#ifdef CONFIG_X86_32
#define NR_RANGE_MR 3
#else /* CONFIG_X86_64 */
#define NR_RANGE_MR 5
#endif

static int __meminit save_mr(struct map_range *mr, int nr_range,
			     unsigned long start_pfn, unsigned long end_pfn,
			     unsigned long page_size_mask)
{
	if (start_pfn < end_pfn) {
		if (nr_range >= NR_RANGE_MR)
			panic("run out of range for init_memory_mapping\n");
		mr[nr_range].start = start_pfn<<PAGE_SHIFT;
		mr[nr_range].end   = end_pfn<<PAGE_SHIFT;
		mr[nr_range].page_size_mask = page_size_mask;
		nr_range++;
	}

	return nr_range;
}

/*
 * adjust the page_size_mask for small range to go with
 *	big page size instead small one if nearby are ram too.
 */
static void __init_refok adjust_range_page_size_mask(struct map_range *mr,
							 int nr_range)
{
	int i;

	for (i = 0; i < nr_range; i++) {
		if ((page_size_mask & (1<<PG_LEVEL_2M)) &&
		    !(mr[i].page_size_mask & (1<<PG_LEVEL_2M))) {
			unsigned long start = round_down(mr[i].start, PMD_SIZE);
			unsigned long end = round_up(mr[i].end, PMD_SIZE);

#ifdef CONFIG_X86_32
			if ((end >> PAGE_SHIFT) > max_low_pfn)
				continue;
#endif

			if (memblock_is_region_memory(start, end - start))
				mr[i].page_size_mask |= 1<<PG_LEVEL_2M;
		}
		if ((page_size_mask & (1<<PG_LEVEL_1G)) &&
		    !(mr[i].page_size_mask & (1<<PG_LEVEL_1G))) {
			unsigned long start = round_down(mr[i].start, PUD_SIZE);
			unsigned long end = round_up(mr[i].end, PUD_SIZE);

			if (memblock_is_region_memory(start, end - start))
				mr[i].page_size_mask |= 1<<PG_LEVEL_1G;
		}
	}
}

/* 这个函数会根据页的大小(4K,2M,1G)建立不同的内存段，1G大小的页框只会在64位系统下使用 */
static int __meminit split_mem_range(struct map_range *mr, int nr_range,
				     unsigned long start,
				     unsigned long end)
{
	unsigned long start_pfn, end_pfn, limit_pfn;
	unsigned long pfn;
	int i;

	/* 获取物理地址end的所在页框号 */
	limit_pfn = PFN_DOWN(end);

	/* head if not big page alignment ? */
	/* 物理地址start所在页框，初始化阶段此值为0 */
	pfn = start_pfn = PFN_DOWN(start);

	/* 这一部分建立了一个页框大小为4K的内存段(mr) */
#ifdef CONFIG_X86_32
	/*
	 * Don't use a large page for the first 2/4MB of memory
	 * because there are often fixed size MTRRs in there
	 * and overlapping MTRRs into large pages can cause
	 * slowdowns.
	 */
	 
	/* 
	 * PMD_SIZE保存页中间目录可映射区域的大小
	 * PAE禁用: 4M    
	 * PAE激活: 2M 
	 */
	if (pfn == 0)
		/* 如果pfn为0，也就是开始页框号是0，那结束页框号就是4M或者2M */
		end_pfn = PFN_DOWN(PMD_SIZE);
	else
		/* 如果pfn不为0，以pfn开始(包括pfn)，向上找到下一个是PMD_SIZE倍数的页框号 */
		end_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));

	/*   以下数值都是二进制表示
	 *   round_up(x,y):                x: 11010010              y: 1000              结果; 11011000
	 *   round_up(x,y):                x: 11011010              y: 1000              结果: 11100000
	 *
	 *   round_down(x,y):              x: 11010010              y: 1000              结果: 11010000
	 *   round_down(x,1)               x: 11011010              y: 1000              结果: 11011000
	 *
	 */
#else /* CONFIG_X86_64 */
	/* 以pfn开始(包括pfn)，向上找到下一个是PMD_SIZE倍数的页框号 */
	end_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));
#endif
	/* 如果结束页框号超过了end所在页框号，那就选取end所在页框号为结束页框 */
	if (end_pfn > limit_pfn)
		end_pfn = limit_pfn;
	/* 第一个内存段的页框大小为一个PMD_SIZE的大小，4M或者2M */
	if (start_pfn < end_pfn) {
		/* 
		 * mr[nr_range].start = start_pfn<<PAGE_SHIFT;
		 * mr[nr_range].end   = end_pfn<<PAGE_SHIFT;
		 * mr[nr_range].page_size_mask = 0;
		 * nr_range++;
		 */
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);
		/* pfn等于结束页框号，下个区创建时就会以这个pfn作为起始页框号*/
		pfn = end_pfn;
	}

	/* big page (2M) range */
	/* 第二个区域，创建大小为2M的页框内存段，32位下2M的页框只有在PAE开启的情况下才会有，这个区不是一定会有的(有的条件是 32位系统 && PAE启动 && 开启2M大小页框) */
	/* 以pfn开始(包括pfn)，向上找到下一个是PMD_SIZE倍数的页框号，这里的情况结果一般都是 start_pfn = pfn */
	start_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));
	
#ifdef CONFIG_X86_32
	/* X86_32位下的处理 */
	/* 以limit_pfn开始(包括limit_pfn)，向下找到上一个是PMD_SIZE倍数的页框号，这样就有可能有第三个段，有可能没有 */
	end_pfn = round_down(limit_pfn, PFN_DOWN(PMD_SIZE));

#else /* CONFIG_X86_64 */
	/* X86_64位下的处理 */
	/* 以pfn开始(包括pfn)，向上找到下一个是PUD_SIZE倍数的页框号 */
	end_pfn = round_up(pfn, PFN_DOWN(PUD_SIZE));
	if (end_pfn > round_down(limit_pfn, PFN_DOWN(PMD_SIZE)))
		end_pfn = round_down(limit_pfn, PFN_DOWN(PMD_SIZE));
#endif

	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pfn = end_pfn;
	}

/* X64下会建立一个区域页框大小为1G的，32位下不会有 */
#ifdef CONFIG_X86_64
	/* big page (1G) range */
	start_pfn = round_up(pfn, PFN_DOWN(PUD_SIZE));
	end_pfn = round_down(limit_pfn, PFN_DOWN(PUD_SIZE));
	if (start_pfn < end_pfn) {
		/* 
		 * mr[nr_range].start = start_pfn<<PAGE_SHIFT;
		 * mr[nr_range].end   = end_pfn<<PAGE_SHIFT;
		 * mr[nr_range].page_size_mask = page_size_mask & ((1<<PG_LEVEL_2M)|(1<<PG_LEVEL_1G)));
		 * nr_range++;
		 */
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask &
				 ((1<<PG_LEVEL_2M)|(1<<PG_LEVEL_1G)));
		pfn = end_pfn;
	}

	/* tail is not big page (1G) alignment */
	start_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));
	end_pfn = round_down(limit_pfn, PFN_DOWN(PMD_SIZE));
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pfn = end_pfn;
	}
#endif

	/* tail is not big page (2M) alignment */
	/* 将剩余所有的页框作为一个新的4K大小页框的内存段 */
	start_pfn = pfn;
	end_pfn = limit_pfn;
	nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);

	/* 如果使用的是bootmem分配器的情况下会调整一下几个段的起始页框和结束页框 */
	if (!after_bootmem)
		adjust_range_page_size_mask(mr, nr_range);

	/* try to merge same page size and continuous */
	/* 将相邻两个页框大小相等的区合并 */
	for (i = 0; nr_range > 1 && i < nr_range - 1; i++) {
		unsigned long old_start;
		if (mr[i].end != mr[i+1].start ||
		    mr[i].page_size_mask != mr[i+1].page_size_mask)
			continue;

		/* 前一个区的结束页框等于后一个区的开始页框，并且区中页框大小相等的情况下，合并 */
		old_start = mr[i].start;
		memmove(&mr[i], &mr[i+1],
			(nr_range - 1 - i) * sizeof(struct map_range));
		mr[i--].start = old_start;
		nr_range--;
	}

	/* 打印信息 */
	for (i = 0; i < nr_range; i++)
		printk(KERN_DEBUG " [mem %#010lx-%#010lx] page %s\n",
				mr[i].start, mr[i].end - 1,
			(mr[i].page_size_mask & (1<<PG_LEVEL_1G))?"1G":(
			 (mr[i].page_size_mask & (1<<PG_LEVEL_2M))?"2M":"4k"));

	/* 返回内存段的数量 */
	return nr_range;
}

struct range pfn_mapped[E820_X_MAX];
int nr_pfn_mapped;

static void add_pfn_range_mapped(unsigned long start_pfn, unsigned long end_pfn)
{
	/* E820是BIOS使用的，这里是修改BIOS中的内存段 */
	nr_pfn_mapped = add_range_with_merge(pfn_mapped, E820_X_MAX,
					     nr_pfn_mapped, start_pfn, end_pfn);
	/* 重新排列，因为在 add_range_with_merge 中新加的段是放在最后的 */
	nr_pfn_mapped = clean_sort_range(pfn_mapped, E820_X_MAX);

	/* 处于所有内存段中最后一个映射的页框号 */
	max_pfn_mapped = max(max_pfn_mapped, end_pfn);

	/* 设置低端内存中已映射的最大页框号 */
	if (start_pfn < (1UL<<(32-PAGE_SHIFT)))
		max_low_pfn_mapped = max(max_low_pfn_mapped,
					 min(end_pfn, 1UL<<(32-PAGE_SHIFT)));
}

bool pfn_range_is_mapped(unsigned long start_pfn, unsigned long end_pfn)
{
	int i;

	for (i = 0; i < nr_pfn_mapped; i++)
		if ((start_pfn >= pfn_mapped[i].start) &&
		    (end_pfn <= pfn_mapped[i].end))
			return true;

	return false;
}

/*
 * Setup the direct mapping of the physical memory at PAGE_OFFSET.
 * This runs before bootmem is initialized and gets pages directly from
 * the physical memory. To access them they are temporarily mapped.
 */
/* 内核将start ~ end 这段物理地址映射到线性地址上，这个函数仅会映射低端内存区(ZONE_DMA和ZONE_NORMAL)，线性地址0xC0000000 对应的物理地址是 0x00000000 */
unsigned long __init_refok init_memory_mapping(unsigned long start,
					       unsigned long end)
{
	/* 用于保存内存段信息，每个段的页框大小不同，可能有4K，2M，1G三种 */
	struct map_range mr[NR_RANGE_MR];
	unsigned long ret = 0;
	int nr_range, i;

	pr_info("init_memory_mapping: [mem %#010lx-%#010lx]\n",
	       start, end - 1);

	/* 清空mr */
	memset(mr, 0, sizeof(mr));
	
	/* 
	 * 根据start和end设置mr数组，并返回个数 
	 */
	nr_range = split_mem_range(mr, 0, start, end);

	/* 遍历整个mr，将所有内存段的页框进行映射，就是将页框地址写入对应的页表中，返回的是最后映射的地址 */
	for (i = 0; i < nr_range; i++)
		ret = kernel_physical_mapping_init(mr[i].start, mr[i].end,
						   mr[i].page_size_mask);

	/* 调整页框映射的设置，和map_range类似，只是map_range是线性地址的映射数据，这里面是页框映射的数据 */
	add_pfn_range_mapped(start >> PAGE_SHIFT, ret >> PAGE_SHIFT);

	/* 返回最后映射的页框号 */
	return ret >> PAGE_SHIFT;
}

/*
 * We need to iterate through the E820 memory map and create direct mappings
 * for only E820_RAM and E820_KERN_RESERVED regions. We cannot simply
 * create direct mappings for all pfns from [0 to max_low_pfn) and
 * [4GB to max_pfn) because of possible memory holes in high addresses
 * that cannot be marked as UC by fixed/variable range MTRRs.
 * Depending on the alignment of E820 ranges, this may possibly result
 * in using smaller size (i.e. 4K instead of 2M or 1G) page tables.
 *
 * init_mem_mapping() calls init_range_memory_mapping() with big range.
 * That range would have hole in the middle or ends, and only ram parts
 * will be mapped in init_range_memory_mapping().
 */
/* 内核将start ~ end 这段物理地址映射到线性地址上 */
static unsigned long __init init_range_memory_mapping(
					   unsigned long r_start,
					   unsigned long r_end)
{
	unsigned long start_pfn, end_pfn;
	unsigned long mapped_ram_size = 0;
	int i;

	/* 遍历每一个结点的页框段，与memblock_region有关，还没研究 */
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, NULL) {
		/* start_pfn, r_start, r_end中处于中间的那个数 */
		u64 start = clamp_val(PFN_PHYS(start_pfn), r_start, r_end);
		/* 同上 */
		u64 end = clamp_val(PFN_PHYS(end_pfn), r_start, r_end);
		if (start >= end)
			continue;

		/*
		 * if it is overlapping with brk pgt, we need to
		 * alloc pgt buf from memblock instead.
		 */
		can_use_brk_pgt = max(start, (u64)pgt_buf_end<<PAGE_SHIFT) >=
				    min(end, (u64)pgt_buf_top<<PAGE_SHIFT);
		/* 又调用到init_memory_mapping，将start ~ end 这段物理地址映射到线性地址上 */
		init_memory_mapping(start, end);
		mapped_ram_size += end - start;
		can_use_brk_pgt = true;
	}

	return mapped_ram_size;
}

static unsigned long __init get_new_step_size(unsigned long step_size)
{
	/*
	 * Explain why we shift by 5 and why we don't have to worry about
	 * 'step_size << 5' overflowing:
	 *
	 * initial mapped size is PMD_SIZE (2M).
	 * We can not set step_size to be PUD_SIZE (1G) yet.
	 * In worse case, when we cross the 1G boundary, and
	 * PG_LEVEL_2M is not set, we will need 1+1+512 pages (2M + 8k)
	 * to map 1G range with PTE. Use 5 as shift for now.
	 *
	 * Don't need to worry about overflow, on 32bit, when step_size
	 * is 0, round_down() returns 0 for start, and that turns it
	 * into 0x100000000ULL.
	 */
	return step_size << 5;
}

/**
 * memory_map_top_down - Map [map_start, map_end) top down
 * @map_start: start address of the target memory range
 * @map_end: end address of the target memory range
 *
 * This function will setup direct mapping for memory range
 * [map_start, map_end) in top-down. That said, the page tables
 * will be allocated at the end of the memory, and we map the
 * memory in top-down.
 */
static void __init memory_map_top_down(unsigned long map_start,
				       unsigned long map_end)
{
	unsigned long real_end, start, last_start;
	unsigned long step_size;
	unsigned long addr;
	unsigned long mapped_ram_size = 0;
	unsigned long new_mapped_ram_size;

	/* xen has big range in reserved near end of ram, skip it at first.*/
	addr = memblock_find_in_range(map_start, map_end, PMD_SIZE, PMD_SIZE);
	real_end = addr + PMD_SIZE;

	/* step_size need to be small so pgt_buf from BRK could cover it */
	step_size = PMD_SIZE;
	max_pfn_mapped = 0; /* will get exact value next */
	min_pfn_mapped = real_end >> PAGE_SHIFT;
	last_start = start = real_end;

	/*
	 * We start from the top (end of memory) and go to the bottom.
	 * The memblock_find_in_range() gets us a block of RAM from the
	 * end of RAM in [min_pfn_mapped, max_pfn_mapped) used as new pages
	 * for page table.
	 */
	while (last_start > map_start) {
		if (last_start > step_size) {
			start = round_down(last_start - 1, step_size);
			if (start < map_start)
				start = map_start;
		} else
			start = map_start;
		new_mapped_ram_size = init_range_memory_mapping(start,
							last_start);
		last_start = start;
		min_pfn_mapped = last_start >> PAGE_SHIFT;
		/* only increase step_size after big range get mapped */
		if (new_mapped_ram_size > mapped_ram_size)
			step_size = get_new_step_size(step_size);
		mapped_ram_size += new_mapped_ram_size;
	}

	if (real_end < map_end)
		init_range_memory_mapping(real_end, map_end);
}

/**
 * memory_map_bottom_up - Map [map_start, map_end) bottom up
 * @map_start: start address of the target memory range
 * @map_end: end address of the target memory range
 *
 * This function will setup direct mapping for memory range
 * [map_start, map_end) in bottom-up. Since we have limited the
 * bottom-up allocation above the kernel, the page tables will
 * be allocated just above the kernel and we map the memory
 * in [map_start, map_end) in bottom-up.
 */
/* 将物理地址map_start ~ map_end 映射到内核区域 */
static void __init memory_map_bottom_up(unsigned long map_start,
					unsigned long map_end)
{
	unsigned long next, new_mapped_ram_size, start;
	unsigned long mapped_ram_size = 0;
	/* step_size need to be small so pgt_buf from BRK could cover it */
	unsigned long step_size = PMD_SIZE;

	start = map_start;
	/* 开始页框号 */
	min_pfn_mapped = start >> PAGE_SHIFT;

	/*
	 * We start from the bottom (@map_start) and go to the top (@map_end).
	 * The memblock_find_in_range() gets us a block of RAM from the
	 * end of RAM in [min_pfn_mapped, max_pfn_mapped) used as new pages
	 * for page table.
	 */

	while (start < map_end) {
		if (map_end - start > step_size) {

			/* 向上找到下一个step_size倍数的页框号 */
			next = round_up(start + 1, step_size);
			if (next > map_end)
				next = map_end;
		} else
			next = map_end;
		/* 内核将 start ~ next 这段物理地址经过修正后映射到线性地址上，最后返回映射的大小 */
		new_mapped_ram_size = init_range_memory_mapping(start, next);
		/* 下一个setp_size倍数的页框号 */
		start = next;

		/* 映射成功后，new_mapped_ram_size必定会大于mapped_ram_size(这个初始化是0)，会将setp_size << 5，也就是下次一次会映射更多的页框 */
		if (new_mapped_ram_size > mapped_ram_size)
			step_size = get_new_step_size(step_size);
		/* 统计已映射内存大小 */
		mapped_ram_size += new_mapped_ram_size;
	}
}

void __init init_mem_mapping(void)
{
	unsigned long end;

	/* 设置了page_size_mask全局变量，这个变量决定了系统中有多少种页框大小(4K,2M,1G) */
	/* 1G大小的页框只存在于64位系统中
	 * 4K大小的页框是普通的页框
	 * 2M大小的页框是32位内核开启了PAE后可选择页大小为2M
	 */
	probe_page_size_mask();

	/* max_pfn最大可等于64T */
	/* max_pfn 和 max_low_pfn 都是由BIOS提供获取  */
#ifdef CONFIG_X86_64
	/* 64位没有高端内存区,所有结束页框就是max_pfn号页框 */
	end = max_pfn << PAGE_SHIFT;
#else
	end = max_low_pfn << PAGE_SHIFT;
#endif

	/* end为低端内存(ZONE_MDA和ZONE_NORMAL)的最大页框号 */

	/* the ISA range is always mapped regardless of memory holes */
	/* 0 ~ 1MB，一般内核启动时被安装在1MB开始处
	 * 这里先初始化 0 ~ 1MB的物理地址
	 */
	init_memory_mapping(0, ISA_END_ADDRESS);

	/*
	 * If the allocation is in bottom-up direction, we setup direct mapping
	 * in bottom-up, otherwise we setup direct mapping in top-down.
	 */
	if (memblock_bottom_up()) {
		/* 内核启动阶段使用的内存的结束地址，内核启动时一般使用物理内存 1MB ~ 4MB 的区域 */
		unsigned long kernel_end = __pa_symbol(_end);

		/*
		 * we need two separate calls here. This is because we want to
		 * allocate page tables above the kernel. So we first map
		 * [kernel_end, end) to make memory above the kernel be mapped
		 * as soon as possible. And then use page tables allocated above
		 * the kernel to map [ISA_END_ADDRESS, kernel_end).
		 */
		/* 先映射 内核结束地址 ~ ZONE_NORMAL结束地址 这块物理地址区域，如果是64位，则直接初始化到最后的内存页框，因为64位没有高端内存区 */
		memory_map_bottom_up(kernel_end, end);
		/* 再映射 1MB ~ 内核结束地址 这块物理地址区域 */
		memory_map_bottom_up(ISA_END_ADDRESS, kernel_end);
	} else {
		memory_map_top_down(ISA_END_ADDRESS, end);
	}

#ifdef CONFIG_X86_64
	if (max_pfn > max_low_pfn) {
		/* can we preseve max_low_pfn ?*/
		max_low_pfn = max_pfn;
	}
#else
	/* 高端内存区的固定映射区的初始化，只初始化好了页中间目录项和页表，页表项并没初始化 */
	/* 64位没有这个区域 */
	early_ioremap_page_table_range_init();
#endif
	/* 将初始化好的内核页全局目录地址写入cr3寄存器 */
	load_cr3(swapper_pg_dir);
	/* 刷新tlb */
	__flush_tlb_all();

	/* 检查一下是否有问题 */
	early_memtest(0, max_pfn_mapped << PAGE_SHIFT);
}

/*
 * devmem_is_allowed() checks to see if /dev/mem access to a certain address
 * is valid. The argument is a physical page number.
 *
 *
 * On x86, access has to be given to the first megabyte of ram because that area
 * contains bios code and data regions used by X and dosemu and similar apps.
 * Access has to be given to non-kernel-ram areas as well, these contain the PCI
 * mmio resources as well as potential bios/acpi data regions.
 */
int devmem_is_allowed(unsigned long pagenr)
{
	if (pagenr < 256)
		return 1;
	if (iomem_is_exclusive(pagenr << PAGE_SHIFT))
		return 0;
	if (!page_is_ram(pagenr))
		return 1;
	return 0;
}

void free_init_pages(char *what, unsigned long begin, unsigned long end)
{
	unsigned long begin_aligned, end_aligned;

	/* Make sure boundaries are page aligned */
	begin_aligned = PAGE_ALIGN(begin);
	end_aligned   = end & PAGE_MASK;

	if (WARN_ON(begin_aligned != begin || end_aligned != end)) {
		begin = begin_aligned;
		end   = end_aligned;
	}

	if (begin >= end)
		return;

	/*
	 * If debugging page accesses then do not free this memory but
	 * mark them not present - any buggy init-section access will
	 * create a kernel page fault:
	 */
#ifdef CONFIG_DEBUG_PAGEALLOC
	printk(KERN_INFO "debug: unmapping init [mem %#010lx-%#010lx]\n",
		begin, end - 1);
	set_memory_np(begin, (end - begin) >> PAGE_SHIFT);
#else
	/*
	 * We just marked the kernel text read only above, now that
	 * we are going to free part of that, we need to make that
	 * writeable and non-executable first.
	 */
	set_memory_nx(begin, (end - begin) >> PAGE_SHIFT);
	set_memory_rw(begin, (end - begin) >> PAGE_SHIFT);

	free_reserved_area((void *)begin, (void *)end, POISON_FREE_INITMEM, what);
#endif
}

void free_initmem(void)
{
	free_init_pages("unused kernel",
			(unsigned long)(&__init_begin),
			(unsigned long)(&__init_end));
}

#ifdef CONFIG_BLK_DEV_INITRD
void __init free_initrd_mem(unsigned long start, unsigned long end)
{
#ifdef CONFIG_MICROCODE_EARLY
	/*
	 * Remember, initrd memory may contain microcode or other useful things.
	 * Before we lose initrd mem, we need to find a place to hold them
	 * now that normal virtual memory is enabled.
	 */
	save_microcode_in_initrd();
#endif

	/*
	 * end could be not aligned, and We can not align that,
	 * decompresser could be confused by aligned initrd_end
	 * We already reserve the end partial page before in
	 *   - i386_start_kernel()
	 *   - x86_64_start_kernel()
	 *   - relocate_initrd()
	 * So here We can do PAGE_ALIGN() safely to get partial page to be freed
	 */
	free_init_pages("initrd", start, PAGE_ALIGN(end));
}
#endif

void __init zone_sizes_init(void)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES];

	memset(max_zone_pfns, 0, sizeof(max_zone_pfns));

#ifdef CONFIG_ZONE_DMA
	/* 保存了ZONE_DMA区最后一个页框号，就是16MB最后一个页框 */
	max_zone_pfns[ZONE_DMA]		= MAX_DMA_PFN;
#endif
#ifdef CONFIG_ZONE_DMA32
	/* 保存了ZONE_DMA32区最后一个页框号，就是4GB最后一个页框 */
	max_zone_pfns[ZONE_DMA32]	= MAX_DMA32_PFN;
#endif
	/* 同上，max_low_pfn保存的是低端内存中最后一个页框号 */
	max_zone_pfns[ZONE_NORMAL]	= max_low_pfn;
#ifdef CONFIG_HIGHMEM
	/* 同上，max_pfn保存的是物理内存中最后一个页框号 */
	max_zone_pfns[ZONE_HIGHMEM]	= max_pfn;
#endif

	free_area_init_nodes(max_zone_pfns);
}

