#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/stat.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/utsname.h>
#include <linux/personality.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/elf.h>

#include <asm/ia32.h>
#include <asm/syscalls.h>

/*
 * Align a virtual address to avoid aliasing in the I$ on AMD F15h.
 */
static unsigned long get_align_mask(void)
{
	/* handle 32- and 64-bit case with a single conditional */
	if (va_align.flags < 0 || !(va_align.flags & (2 - mmap_is_ia32())))
		return 0;

	if (!(current->flags & PF_RANDOMIZE))
		return 0;

	return va_align.mask;
}

unsigned long align_vdso_addr(unsigned long addr)
{
	unsigned long align_mask = get_align_mask();
	return (addr + align_mask) & ~align_mask;
}

static int __init control_va_addr_alignment(char *str)
{
	/* guard against enabling this on other CPU families */
	if (va_align.flags < 0)
		return 1;

	if (*str == 0)
		return 1;

	if (*str == '=')
		str++;

	if (!strcmp(str, "32"))
		va_align.flags = ALIGN_VA_32;
	else if (!strcmp(str, "64"))
		va_align.flags = ALIGN_VA_64;
	else if (!strcmp(str, "off"))
		va_align.flags = 0;
	else if (!strcmp(str, "on"))
		va_align.flags = ALIGN_VA_32 | ALIGN_VA_64;
	else
		return 0;

	return 1;
}
__setup("align_va_addr", control_va_addr_alignment);

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	long error;
	error = -EINVAL;
	if (off & ~PAGE_MASK)
		goto out;

	error = sys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
out:
	return error;
}

static void find_start_end(unsigned long flags, unsigned long *begin,
			   unsigned long *end)
{
	/* MAP_32BIT代表是32位的地址，TIF_ADDR32代表的是在64位里使用32位地址空间 */
	/* 这里是32位的处理情况 */
	if (!test_thread_flag(TIF_ADDR32) && (flags & MAP_32BIT)) {
		unsigned long new_begin;
		/* This is usually used needed to map code in small
		   model, so it needs to be in the first 31bit. Limit
		   it to that.  This means we need to move the
		   unmapped base down for this case. This can give
		   conflicts with the heap, but we assume that glibc
		   malloc knows how to fall back to mmap. Give it 1GB
		   of playground for now. -AK */
		/* 默认进程地址空间mmap区域的起始地址 */
		*begin = 0x40000000;
		/* 默认进程地址空间mmap区域的结束地址 */
		*end = 0x80000000;
		/* 如果当前进程有设置PF_RANDOMIZE，则将begin地址做一个begin ~ begin + 0x2000000的随机化，让begin处于在这段区间中 */
		if (current->flags & PF_RANDOMIZE) {
			new_begin = randomize_range(*begin, *begin + 0x02000000, 0);
			/* 随机化begin成功，设置使用 */
			if (new_begin)
				*begin = new_begin;
		}
	} else {
		/* 64位的情况 */
		/* begin = (PAGE_ALIGN(TASK_SIZE / 3)) + PAGE_ALIGN(随机数(0 ~ 1<<28)) 这种是开启了PF_RANDOMIZE的情况，没开启则直接是(PAGE_ALIGN(TASK_SIZE / 3)) */
		*begin = current->mm->mmap_legacy_base;
		*end = TASK_SIZE;
	}
}

/* mmap区域向下生长时，get_unmapped_area指向的函数 */
/* X86中mmap区域向上生长时，get_unmapped_area的函数，调用到这里是len已经做页大小对齐
 * 返回合理的addr地址
 */
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct vm_unmapped_area_info info;
	unsigned long begin, end;

	/* 起始地址必须是addr，即使addr不合理 */
	if (flags & MAP_FIXED)
		return addr;

	/* 到这里如果addr是有数据的，这里只会尝试addr，如果addr不合理，则另外获取一段地址空间 */
	/* 获取进程地址空间中mmap区域的起始地址和结束地址，起始地址可能会因为current->flags的PF_RANDOMIZE标志造成一定范围的随机 */
	/* 32位下这个地址是0x40000000 ~ 0x80000000
	 * 64位下这个地址是((1UL << 47) - PAGE_SIZE) / 3 ~ ((1UL << 47) - PAGE_SIZE)
	 */
	find_start_end(flags, &begin, &end);

	/* 长度不能大于end */
	if (len > end)
		return -ENOMEM;

	/* 如果设置了addr，先尝试从addr分配 */
	if (addr) {
		/* 将addr对齐到4096(4KB)的倍数 */
		addr = PAGE_ALIGN(addr);
		/* 查找当前进程中包含有addr的vma或者离addr最近的下一个线性区，会先从当前进程描述符中的vmacache中找，再去mm_struct的红黑树中找 */
		vma = find_vma(mm, addr);
		/* len长度是否在合理范围 */
		/* 注意 (!vma || addr + len <= vma->vm_start)
		 * 如果没有vma包含有addr，则说明所有的vma的结束地址都小于这个addr
		 * 如果获取到vma，有两种情况，addr包含在一个vma中，或者addr不在vma中，但是获取到了一个离这个addr最近并且地址比它高的vma
		 * 对于addr包含在一个vma中的情况，这个判断不会成功，会继续到下面执行找一个空闲的线性地址空间，而第二种情况，会检查addr + len 是否进入了vma区，如果没进入，那么这段地址是空闲的，可以使用，直接返回
		 */
		if (end - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}

	/* 这里处理的是没有包含着addr的vma(并不是要求包含着addr ~ addr + len的vma)，将会找到一段合适线性区间并把起始地址返回
	 * 设置好这个struct vm_unmapped_area_info
	 */
	info.flags = 0;
	info.length = len;
	info.low_limit = begin;
	info.high_limit = end;
	info.align_mask = filp ? get_align_mask() : 0;
	info.align_offset = pgoff << PAGE_SHIFT;
	/* 获取mmap区间中一段没有被映射的地址范围，返回起始地址 */
	return vm_unmapped_area(&info);
}

/* mmap区域向下生长时，get_unmapped_area指向的函数，调用到这里是len已经做页大小对齐 
 * 返回合理的addr地址
 */
unsigned long
arch_get_unmapped_area_topdown(struct file *filp, const unsigned long addr0,
			  const unsigned long len, const unsigned long pgoff,
			  const unsigned long flags)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long addr = addr0;
	struct vm_unmapped_area_info info;

	/* requested length too big for entire address space */
	/* 请求的长度大于整个进程地址空间，反正错误 */
	if (len > TASK_SIZE)
		return -ENOMEM;

	/* 强制使用addr，直接返回addr */
	if (flags & MAP_FIXED)
		return addr;

	/* 这里开始会首先尝试addr，addr不合理就会获取一段合理的进程地址范围 */

	/* 只使用32位地址，跳到bottomup */
	/* for MAP_32BIT mappings we force the legacy mmap base */
	if (!test_thread_flag(TIF_ADDR32) && (flags & MAP_32BIT))
		goto bottomup;

	/* 如果设置了addr，先尝试从addr分配 */
	/* requesting a specific address */
	if (addr) {
		/* addr按页对齐 */
		addr = PAGE_ALIGN(addr);
		/* 查找当前进程中包含有addr的vma或者离addr最近的下一个线性区，会先从当前进程描述符中的vmacache中找，再去mm_struct的红黑树中找 */
		vma = find_vma(mm, addr);
		/* len长度是否在合理范围 */
		/* 注意 (!vma || addr + len <= vma->vm_start)
		 * 如果没有vma包含有addr，则说明所有的vma的结束地址都小于这个addr
		 * 如果获取到vma，有两种情况，addr包含在一个vma中，或者addr不在vma中，但是获取到了一个离这个addr最近并且地址比它高的vma
		 * 对于addr包含在一个vma中的情况，这个判断不会成功，会继续到下面执行找一个空闲的线性地址空间，而第二种情况，会检查addr + len 是否进入了vma区，如果没进入，那么这段地址是空闲的，可以使用，直接返回
		 */
		if (TASK_SIZE - len >= addr &&
				(!vma || addr + len <= vma->vm_start))
			return addr;
	}

	/* mmap向下增长 */
	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	/* 需要的长度 */
	info.length = len;
	/* mmap区域最小地址，一个页的偏移量 */
	info.low_limit = PAGE_SIZE;
	/* mmap区域顶端地址，mmap向下增长 */
	info.high_limit = mm->mmap_base;
	info.align_mask = filp ? get_align_mask() : 0;
	/* 需要映射内容在文件中的偏移量，以页大小为单位 */
	info.align_offset = pgoff << PAGE_SHIFT;
	/* 获取到一个地址范围，addr是首地址 */
	addr = vm_unmapped_area(&info);
	/* 将addr以页大小对齐 */
	if (!(addr & ~PAGE_MASK))
		/* 返回addr */
		return addr;
	VM_BUG_ON(addr != -ENOMEM);

bottomup:
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	 /* 32位地址的处理 */
	return arch_get_unmapped_area(filp, addr0, len, pgoff, flags);
}
