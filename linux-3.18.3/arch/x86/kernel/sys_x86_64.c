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
	/* MAP_32BIT������32λ�ĵ�ַ��TIF_ADDR32���������64λ��ʹ��32λ��ַ�ռ� */
	/* ������32λ�Ĵ������ */
	if (!test_thread_flag(TIF_ADDR32) && (flags & MAP_32BIT)) {
		unsigned long new_begin;
		/* This is usually used needed to map code in small
		   model, so it needs to be in the first 31bit. Limit
		   it to that.  This means we need to move the
		   unmapped base down for this case. This can give
		   conflicts with the heap, but we assume that glibc
		   malloc knows how to fall back to mmap. Give it 1GB
		   of playground for now. -AK */
		/* Ĭ�Ͻ��̵�ַ�ռ�mmap�������ʼ��ַ */
		*begin = 0x40000000;
		/* Ĭ�Ͻ��̵�ַ�ռ�mmap����Ľ�����ַ */
		*end = 0x80000000;
		/* �����ǰ����������PF_RANDOMIZE����begin��ַ��һ��begin ~ begin + 0x2000000�����������begin��������������� */
		if (current->flags & PF_RANDOMIZE) {
			new_begin = randomize_range(*begin, *begin + 0x02000000, 0);
			/* �����begin�ɹ�������ʹ�� */
			if (new_begin)
				*begin = new_begin;
		}
	} else {
		/* 64λ����� */
		/* begin = (PAGE_ALIGN(TASK_SIZE / 3)) + PAGE_ALIGN(�����(0 ~ 1<<28)) �����ǿ�����PF_RANDOMIZE�������û������ֱ����(PAGE_ALIGN(TASK_SIZE / 3)) */
		*begin = current->mm->mmap_legacy_base;
		*end = TASK_SIZE;
	}
}

/* mmap������������ʱ��get_unmapped_areaָ��ĺ��� */
/* X86��mmap������������ʱ��get_unmapped_area�ĺ��������õ�������len�Ѿ���ҳ��С����
 * ���غ����addr��ַ
 */
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct vm_unmapped_area_info info;
	unsigned long begin, end;

	/* ��ʼ��ַ������addr����ʹaddr������ */
	if (flags & MAP_FIXED)
		return addr;

	/* ���������addr�������ݵģ�����ֻ�᳢��addr�����addr�������������ȡһ�ε�ַ�ռ� */
	/* ��ȡ���̵�ַ�ռ���mmap�������ʼ��ַ�ͽ�����ַ����ʼ��ַ���ܻ���Ϊcurrent->flags��PF_RANDOMIZE��־���һ����Χ����� */
	/* 32λ�������ַ��0x40000000 ~ 0x80000000
	 * 64λ�������ַ��((1UL << 47) - PAGE_SIZE) / 3 ~ ((1UL << 47) - PAGE_SIZE)
	 */
	find_start_end(flags, &begin, &end);

	/* ���Ȳ��ܴ���end */
	if (len > end)
		return -ENOMEM;

	/* ���������addr���ȳ��Դ�addr���� */
	if (addr) {
		/* ��addr���뵽4096(4KB)�ı��� */
		addr = PAGE_ALIGN(addr);
		/* ���ҵ�ǰ�����а�����addr��vma������addr�������һ�������������ȴӵ�ǰ�����������е�vmacache���ң���ȥmm_struct�ĺ�������� */
		vma = find_vma(mm, addr);
		/* len�����Ƿ��ں���Χ */
		/* ע�� (!vma || addr + len <= vma->vm_start)
		 * ���û��vma������addr����˵�����е�vma�Ľ�����ַ��С�����addr
		 * �����ȡ��vma�������������addr������һ��vma�У�����addr����vma�У����ǻ�ȡ����һ�������addr������ҵ�ַ�����ߵ�vma
		 * ����addr������һ��vma�е����������жϲ���ɹ��������������ִ����һ�����е����Ե�ַ�ռ䣬���ڶ������������addr + len �Ƿ������vma�������û���룬��ô��ε�ַ�ǿ��еģ�����ʹ�ã�ֱ�ӷ���
		 */
		if (end - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}

	/* ���ﴦ�����û�а�����addr��vma(������Ҫ�������addr ~ addr + len��vma)�������ҵ�һ�κ����������䲢����ʼ��ַ����
	 * ���ú����struct vm_unmapped_area_info
	 */
	info.flags = 0;
	info.length = len;
	info.low_limit = begin;
	info.high_limit = end;
	info.align_mask = filp ? get_align_mask() : 0;
	info.align_offset = pgoff << PAGE_SHIFT;
	/* ��ȡmmap������һ��û�б�ӳ��ĵ�ַ��Χ��������ʼ��ַ */
	return vm_unmapped_area(&info);
}

/* mmap������������ʱ��get_unmapped_areaָ��ĺ��������õ�������len�Ѿ���ҳ��С���� 
 * ���غ����addr��ַ
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
	/* ����ĳ��ȴ����������̵�ַ�ռ䣬�������� */
	if (len > TASK_SIZE)
		return -ENOMEM;

	/* ǿ��ʹ��addr��ֱ�ӷ���addr */
	if (flags & MAP_FIXED)
		return addr;

	/* ���￪ʼ�����ȳ���addr��addr������ͻ��ȡһ�κ���Ľ��̵�ַ��Χ */

	/* ֻʹ��32λ��ַ������bottomup */
	/* for MAP_32BIT mappings we force the legacy mmap base */
	if (!test_thread_flag(TIF_ADDR32) && (flags & MAP_32BIT))
		goto bottomup;

	/* ���������addr���ȳ��Դ�addr���� */
	/* requesting a specific address */
	if (addr) {
		/* addr��ҳ���� */
		addr = PAGE_ALIGN(addr);
		/* ���ҵ�ǰ�����а�����addr��vma������addr�������һ�������������ȴӵ�ǰ�����������е�vmacache���ң���ȥmm_struct�ĺ�������� */
		vma = find_vma(mm, addr);
		/* len�����Ƿ��ں���Χ */
		/* ע�� (!vma || addr + len <= vma->vm_start)
		 * ���û��vma������addr����˵�����е�vma�Ľ�����ַ��С�����addr
		 * �����ȡ��vma�������������addr������һ��vma�У�����addr����vma�У����ǻ�ȡ����һ�������addr������ҵ�ַ�����ߵ�vma
		 * ����addr������һ��vma�е����������жϲ���ɹ��������������ִ����һ�����е����Ե�ַ�ռ䣬���ڶ������������addr + len �Ƿ������vma�������û���룬��ô��ε�ַ�ǿ��еģ�����ʹ�ã�ֱ�ӷ���
		 */
		if (TASK_SIZE - len >= addr &&
				(!vma || addr + len <= vma->vm_start))
			return addr;
	}

	/* mmap�������� */
	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	/* ��Ҫ�ĳ��� */
	info.length = len;
	/* mmap������С��ַ��һ��ҳ��ƫ���� */
	info.low_limit = PAGE_SIZE;
	/* mmap���򶥶˵�ַ��mmap�������� */
	info.high_limit = mm->mmap_base;
	info.align_mask = filp ? get_align_mask() : 0;
	/* ��Ҫӳ���������ļ��е�ƫ��������ҳ��СΪ��λ */
	info.align_offset = pgoff << PAGE_SHIFT;
	/* ��ȡ��һ����ַ��Χ��addr���׵�ַ */
	addr = vm_unmapped_area(&info);
	/* ��addr��ҳ��С���� */
	if (!(addr & ~PAGE_MASK))
		/* ����addr */
		return addr;
	VM_BUG_ON(addr != -ENOMEM);

bottomup:
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	 /* 32λ��ַ�Ĵ��� */
	return arch_get_unmapped_area(filp, addr0, len, pgoff, flags);
}
