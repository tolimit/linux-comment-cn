/*
 *  Copyright (C) 1995  Linus Torvalds
 *  Copyright (C) 2001, 2002 Andi Kleen, SuSE Labs.
 *  Copyright (C) 2008-2009, Red Hat Inc., Ingo Molnar
 */
#include <linux/sched.h>		/* test_thread_flag(), ...	*/
#include <linux/kdebug.h>		/* oops_begin/end, ...		*/
#include <linux/module.h>		/* search_exception_table	*/
#include <linux/bootmem.h>		/* max_low_pfn			*/
#include <linux/kprobes.h>		/* NOKPROBE_SYMBOL, ...		*/
#include <linux/mmiotrace.h>		/* kmmio_handler, ...		*/
#include <linux/perf_event.h>		/* perf_sw_event		*/
#include <linux/hugetlb.h>		/* hstate_index_to_shift	*/
#include <linux/prefetch.h>		/* prefetchw			*/
#include <linux/context_tracking.h>	/* exception_enter(), ...	*/

#include <asm/traps.h>			/* dotraplinkage, ...		*/
#include <asm/pgalloc.h>		/* pgd_*(), ...			*/
#include <asm/kmemcheck.h>		/* kmemcheck_*(), ...		*/
#include <asm/fixmap.h>			/* VSYSCALL_ADDR		*/
#include <asm/vsyscall.h>		/* emulate_vsyscall		*/

#define CREATE_TRACE_POINTS
#include <asm/trace/exceptions.h>

/*
 * Page fault error code bits:
 *
 *   bit 0 ==	 0: no page found	1: protection fault
 *   bit 1 ==	 0: read access		1: write access
 *   bit 2 ==	 0: kernel-mode access	1: user-mode access
 *   bit 3 ==				1: use of reserved bit detected
 *   bit 4 ==				1: fault was an instruction fetch
 */
enum x86_pf_error_code {

	PF_PROT		=		1 << 0,
	PF_WRITE	=		1 << 1,
	PF_USER		=		1 << 2,
	PF_RSVD		=		1 << 3,
	PF_INSTR	=		1 << 4,
};

/*
 * Returns 0 if mmiotrace is disabled, or if the fault is not
 * handled by mmiotrace:
 */
static nokprobe_inline int
kmmio_fault(struct pt_regs *regs, unsigned long addr)
{
	if (unlikely(is_kmmio_active()))
		if (kmmio_handler(regs, addr) == 1)
			return -1;
	return 0;
}

static nokprobe_inline int kprobes_fault(struct pt_regs *regs)
{
	int ret = 0;

	/* kprobe_running() needs smp_processor_id() */
	if (kprobes_built_in() && !user_mode_vm(regs)) {
		/* 有编译kprobes进入内核并且cs段描述符不处于用户模式 */
		preempt_disable();
		/* 禁止抢占并执行kprobe_fault_handler */
		if (kprobe_running() && kprobe_fault_handler(regs, 14))
			ret = 1;
		preempt_enable();
	}

	return ret;
}

/*
 * Prefetch quirks:
 *
 * 32-bit mode:
 *
 *   Sometimes AMD Athlon/Opteron CPUs report invalid exceptions on prefetch.
 *   Check that here and ignore it.
 *
 * 64-bit mode:
 *
 *   Sometimes the CPU reports invalid exceptions on prefetch.
 *   Check that here and ignore it.
 *
 * Opcode checker based on code by Richard Brunner.
 */
static inline int
check_prefetch_opcode(struct pt_regs *regs, unsigned char *instr,
		      unsigned char opcode, int *prefetch)
{
	unsigned char instr_hi = opcode & 0xf0;
	unsigned char instr_lo = opcode & 0x0f;

	switch (instr_hi) {
	case 0x20:
	case 0x30:
		/*
		 * Values 0x26,0x2E,0x36,0x3E are valid x86 prefixes.
		 * In X86_64 long mode, the CPU will signal invalid
		 * opcode if some of these prefixes are present so
		 * X86_64 will never get here anyway
		 */
		return ((instr_lo & 7) == 0x6);
#ifdef CONFIG_X86_64
	case 0x40:
		/*
		 * In AMD64 long mode 0x40..0x4F are valid REX prefixes
		 * Need to figure out under what instruction mode the
		 * instruction was issued. Could check the LDT for lm,
		 * but for now it's good enough to assume that long
		 * mode only uses well known segments or kernel.
		 */
		return (!user_mode(regs) || user_64bit_mode(regs));
#endif
	case 0x60:
		/* 0x64 thru 0x67 are valid prefixes in all modes. */
		return (instr_lo & 0xC) == 0x4;
	case 0xF0:
		/* 0xF0, 0xF2, 0xF3 are valid prefixes in all modes. */
		return !instr_lo || (instr_lo>>1) == 1;
	case 0x00:
		/* Prefetch instruction is 0x0F0D or 0x0F18 */
		if (probe_kernel_address(instr, opcode))
			return 0;

		*prefetch = (instr_lo == 0xF) &&
			(opcode == 0x0D || opcode == 0x18);
		return 0;
	default:
		return 0;
	}
}

static int
is_prefetch(struct pt_regs *regs, unsigned long error_code, unsigned long addr)
{
	unsigned char *max_instr;
	unsigned char *instr;
	int prefetch = 0;

	/*
	 * If it was a exec (instruction fetch) fault on NX page, then
	 * do not ignore the fault:
	 */
	if (error_code & PF_INSTR)
		return 0;

	instr = (void *)convert_ip_to_linear(current, regs);
	max_instr = instr + 15;

	if (user_mode(regs) && instr >= (unsigned char *)TASK_SIZE)
		return 0;

	while (instr < max_instr) {
		unsigned char opcode;

		if (probe_kernel_address(instr, opcode))
			break;

		instr++;

		if (!check_prefetch_opcode(regs, instr, opcode, &prefetch))
			break;
	}
	return prefetch;
}

static void
force_sig_info_fault(int si_signo, int si_code, unsigned long address,
		     struct task_struct *tsk, int fault)
{
	unsigned lsb = 0;
	siginfo_t info;

	info.si_signo	= si_signo;
	info.si_errno	= 0;
	info.si_code	= si_code;
	info.si_addr	= (void __user *)address;
	if (fault & VM_FAULT_HWPOISON_LARGE)
		lsb = hstate_index_to_shift(VM_FAULT_GET_HINDEX(fault)); 
	if (fault & VM_FAULT_HWPOISON)
		lsb = PAGE_SHIFT;
	info.si_addr_lsb = lsb;

	force_sig_info(si_signo, &info, tsk);
}

DEFINE_SPINLOCK(pgd_lock);
LIST_HEAD(pgd_list);

#ifdef CONFIG_X86_32
static inline pmd_t *vmalloc_sync_one(pgd_t *pgd, unsigned long address)
{
	unsigned index = pgd_index(address);
	pgd_t *pgd_k;
	pud_t *pud, *pud_k;
	pmd_t *pmd, *pmd_k;

	pgd += index;
	pgd_k = init_mm.pgd + index;

	if (!pgd_present(*pgd_k))
		return NULL;

	/*
	 * set_pgd(pgd, *pgd_k); here would be useless on PAE
	 * and redundant with the set_pmd() on non-PAE. As would
	 * set_pud.
	 */
	pud = pud_offset(pgd, address);
	pud_k = pud_offset(pgd_k, address);
	if (!pud_present(*pud_k))
		return NULL;

	pmd = pmd_offset(pud, address);
	pmd_k = pmd_offset(pud_k, address);
	if (!pmd_present(*pmd_k))
		return NULL;

	if (!pmd_present(*pmd))
		set_pmd(pmd, *pmd_k);
	else
		BUG_ON(pmd_page(*pmd) != pmd_page(*pmd_k));

	return pmd_k;
}

void vmalloc_sync_all(void)
{
	unsigned long address;

	if (SHARED_KERNEL_PMD)
		return;

	for (address = VMALLOC_START & PMD_MASK;
	     address >= TASK_SIZE && address < FIXADDR_TOP;
	     address += PMD_SIZE) {
		struct page *page;

		spin_lock(&pgd_lock);
		list_for_each_entry(page, &pgd_list, lru) {
			spinlock_t *pgt_lock;
			pmd_t *ret;

			/* the pgt_lock only for Xen */
			pgt_lock = &pgd_page_get_mm(page)->page_table_lock;

			spin_lock(pgt_lock);
			ret = vmalloc_sync_one(page_address(page), address);
			spin_unlock(pgt_lock);

			if (!ret)
				break;
		}
		spin_unlock(&pgd_lock);
	}
}

/*
 * 32-bit:
 *
 *   Handle a fault on the vmalloc or module mapping area
 */
static noinline int vmalloc_fault(unsigned long address)
{
	unsigned long pgd_paddr;
	pmd_t *pmd_k;
	pte_t *pte_k;

	/* Make sure we are in vmalloc area: */
	if (!(address >= VMALLOC_START && address < VMALLOC_END))
		return -1;

	WARN_ON_ONCE(in_nmi());

	/*
	 * Synchronize this task's top level page-table
	 * with the 'reference' page table.
	 *
	 * Do _not_ use "current" here. We might be inside
	 * an interrupt in the middle of a task switch..
	 */
	pgd_paddr = read_cr3();
	pmd_k = vmalloc_sync_one(__va(pgd_paddr), address);
	if (!pmd_k)
		return -1;

	pte_k = pte_offset_kernel(pmd_k, address);
	if (!pte_present(*pte_k))
		return -1;

	return 0;
}
NOKPROBE_SYMBOL(vmalloc_fault);

/*
 * Did it hit the DOS screen memory VA from vm86 mode?
 */
static inline void
check_v8086_mode(struct pt_regs *regs, unsigned long address,
		 struct task_struct *tsk)
{
	unsigned long bit;

	if (!v8086_mode(regs))
		return;

	bit = (address - 0xA0000) >> PAGE_SHIFT;
	if (bit < 32)
		tsk->thread.screen_bitmap |= 1 << bit;
}

static bool low_pfn(unsigned long pfn)
{
	return pfn < max_low_pfn;
}

static void dump_pagetable(unsigned long address)
{
	pgd_t *base = __va(read_cr3());
	pgd_t *pgd = &base[pgd_index(address)];
	pmd_t *pmd;
	pte_t *pte;

#ifdef CONFIG_X86_PAE
	printk("*pdpt = %016Lx ", pgd_val(*pgd));
	if (!low_pfn(pgd_val(*pgd) >> PAGE_SHIFT) || !pgd_present(*pgd))
		goto out;
#endif
	pmd = pmd_offset(pud_offset(pgd, address), address);
	printk(KERN_CONT "*pde = %0*Lx ", sizeof(*pmd) * 2, (u64)pmd_val(*pmd));

	/*
	 * We must not directly access the pte in the highpte
	 * case if the page table is located in highmem.
	 * And let's rather not kmap-atomic the pte, just in case
	 * it's allocated already:
	 */
	if (!low_pfn(pmd_pfn(*pmd)) || !pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	printk("*pte = %0*Lx ", sizeof(*pte) * 2, (u64)pte_val(*pte));
out:
	printk("\n");
}

#else /* CONFIG_X86_64: */

void vmalloc_sync_all(void)
{
	sync_global_pgds(VMALLOC_START & PGDIR_MASK, VMALLOC_END, 0);
}

/*
 * 64-bit:
 *
 *   Handle a fault on the vmalloc area
 *
 * This assumes no large pages in there.
 */
/* 64位的非连续物理内存区错误处理，整个处理就是把主内核页表的address对应的页目录项复制给当前进程的页表 */
static noinline int vmalloc_fault(unsigned long address)
{
	pgd_t *pgd, *pgd_ref;
	pud_t *pud, *pud_ref;
	pmd_t *pmd, *pmd_ref;
	pte_t *pte, *pte_ref;

	/* Make sure we are in vmalloc area: */
	if (!(address >= VMALLOC_START && address < VMALLOC_END))
		return -1;

	WARN_ON_ONCE(in_nmi());

	/*
	 * Copy kernel mappings over when needed. This can also
	 * happen within a race in page table update. In the later
	 * case just flush:
	 */
	/* 当前活动的页表中对应的页表项 */
	pgd = pgd_offset(current->active_mm, address);
	/* 主内核页表中对应的页表项 */
	pgd_ref = pgd_offset_k(address);
	/* 如果主内核页表中对应的页表项为空，则错误 */
	if (pgd_none(*pgd_ref))
		return -1;

	/* 活动页表对应的页目录项为空，则做处理 */
	if (pgd_none(*pgd)) {
		/* 将主内核页表中对应的页表项复制过来 */
		set_pgd(pgd, *pgd_ref);
		/* lazy_tlb */
		arch_flush_lazy_mmu_mode();
	} else {
		BUG_ON(pgd_page_vaddr(*pgd) != pgd_page_vaddr(*pgd_ref));
	}

	/*
	 * Below here mismatches are bugs because these lower tables
	 * are shared:
	 */

	/* 根据当前进程的页目录项和线性地址获取页上级目录项 */
	pud = pud_offset(pgd, address);
	/* 主内核页表中的页上级目录项 */
	pud_ref = pud_offset(pgd_ref, address);
	/* 如果获取的页上级目录项为空则返回-1， */
	if (pud_none(*pud_ref))
		return -1;

	/* 如果当前进程的页上级目录项与主内核页表中的页上级目录项对应的地址范围不匹配，则产生一个bug信息，因为上一步已经把当前进程页表的页目录项从内核页表中复制过来 */
	if (pud_none(*pud) || pud_page_vaddr(*pud) != pud_page_vaddr(*pud_ref))
		BUG();

	/* 同上级目录 */
	pmd = pmd_offset(pud, address);
	pmd_ref = pmd_offset(pud_ref, address);
	if (pmd_none(*pmd_ref))
		return -1;

	if (pmd_none(*pmd) || pmd_page(*pmd) != pmd_page(*pmd_ref))
		BUG();

	/* 同上 */
	pte_ref = pte_offset_kernel(pmd_ref, address);
	if (!pte_present(*pte_ref))
		return -1;

	pte = pte_offset_kernel(pmd, address);

	/*
	 * Don't use pte_page here, because the mappings can point
	 * outside mem_map, and the NUMA hash lookup cannot handle
	 * that:
	 */
	if (!pte_present(*pte) || pte_pfn(*pte) != pte_pfn(*pte_ref))
		BUG();

	return 0;
}
NOKPROBE_SYMBOL(vmalloc_fault);

#ifdef CONFIG_CPU_SUP_AMD
static const char errata93_warning[] =
KERN_ERR 
"******* Your BIOS seems to not contain a fix for K8 errata #93\n"
"******* Working around it, but it may cause SEGVs or burn power.\n"
"******* Please consider a BIOS update.\n"
"******* Disabling USB legacy in the BIOS may also help.\n";
#endif

/*
 * No vm86 mode in 64-bit mode:
 */
static inline void
check_v8086_mode(struct pt_regs *regs, unsigned long address,
		 struct task_struct *tsk)
{
}

static int bad_address(void *p)
{
	unsigned long dummy;

	return probe_kernel_address((unsigned long *)p, dummy);
}

static void dump_pagetable(unsigned long address)
{
	pgd_t *base = __va(read_cr3() & PHYSICAL_PAGE_MASK);
	pgd_t *pgd = base + pgd_index(address);
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (bad_address(pgd))
		goto bad;

	printk("PGD %lx ", pgd_val(*pgd));

	if (!pgd_present(*pgd))
		goto out;

	pud = pud_offset(pgd, address);
	if (bad_address(pud))
		goto bad;

	printk("PUD %lx ", pud_val(*pud));
	if (!pud_present(*pud) || pud_large(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	if (bad_address(pmd))
		goto bad;

	printk("PMD %lx ", pmd_val(*pmd));
	if (!pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	if (bad_address(pte))
		goto bad;

	printk("PTE %lx", pte_val(*pte));
out:
	printk("\n");
	return;
bad:
	printk("BAD\n");
}

#endif /* CONFIG_X86_64 */

/*
 * Workaround for K8 erratum #93 & buggy BIOS.
 *
 * BIOS SMM functions are required to use a specific workaround
 * to avoid corruption of the 64bit RIP register on C stepping K8.
 *
 * A lot of BIOS that didn't get tested properly miss this.
 *
 * The OS sees this as a page fault with the upper 32bits of RIP cleared.
 * Try to work around it here.
 *
 * Note we only handle faults in kernel here.
 * Does nothing on 32-bit.
 */
static int is_errata93(struct pt_regs *regs, unsigned long address)
{
#if defined(CONFIG_X86_64) && defined(CONFIG_CPU_SUP_AMD)
	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD
	    || boot_cpu_data.x86 != 0xf)
		return 0;

	if (address != regs->ip)
		return 0;

	if ((address >> 32) != 0)
		return 0;

	address |= 0xffffffffUL << 32;
	if ((address >= (u64)_stext && address <= (u64)_etext) ||
	    (address >= MODULES_VADDR && address <= MODULES_END)) {
		printk_once(errata93_warning);
		regs->ip = address;
		return 1;
	}
#endif
	return 0;
}

/*
 * Work around K8 erratum #100 K8 in compat mode occasionally jumps
 * to illegal addresses >4GB.
 *
 * We catch this in the page fault handler because these addresses
 * are not reachable. Just detect this case and return.  Any code
 * segment in LDT is compatibility mode.
 */
static int is_errata100(struct pt_regs *regs, unsigned long address)
{
#ifdef CONFIG_X86_64
	if ((regs->cs == __USER32_CS || (regs->cs & (1<<2))) && (address >> 32))
		return 1;
#endif
	return 0;
}

static int is_f00f_bug(struct pt_regs *regs, unsigned long address)
{
#ifdef CONFIG_X86_F00F_BUG
	unsigned long nr;

	/*
	 * Pentium F0 0F C7 C8 bug workaround:
	 */
	if (boot_cpu_has_bug(X86_BUG_F00F)) {
		nr = (address - idt_descr.address) >> 3;

		if (nr == 6) {
			do_invalid_op(regs, 0);
			return 1;
		}
	}
#endif
	return 0;
}

static const char nx_warning[] = KERN_CRIT
"kernel tried to execute NX-protected page - exploit attempt? (uid: %d)\n";
static const char smep_warning[] = KERN_CRIT
"unable to execute userspace code (SMEP?) (uid: %d)\n";

static void
show_fault_oops(struct pt_regs *regs, unsigned long error_code,
		unsigned long address)
{
	if (!oops_may_print())
		return;

	if (error_code & PF_INSTR) {
		unsigned int level;
		pgd_t *pgd;
		pte_t *pte;

		pgd = __va(read_cr3() & PHYSICAL_PAGE_MASK);
		pgd += pgd_index(address);

		pte = lookup_address_in_pgd(pgd, address, &level);

		if (pte && pte_present(*pte) && !pte_exec(*pte))
			printk(nx_warning, from_kuid(&init_user_ns, current_uid()));
		if (pte && pte_present(*pte) && pte_exec(*pte) &&
				(pgd_flags(*pgd) & _PAGE_USER) &&
				(read_cr4() & X86_CR4_SMEP))
			printk(smep_warning, from_kuid(&init_user_ns, current_uid()));
	}

	printk(KERN_ALERT "BUG: unable to handle kernel ");
	if (address < PAGE_SIZE)
		printk(KERN_CONT "NULL pointer dereference");
	else
		printk(KERN_CONT "paging request");

	printk(KERN_CONT " at %p\n", (void *) address);
	printk(KERN_ALERT "IP:");
	printk_address(regs->ip);

	dump_pagetable(address);
}

static noinline void
pgtable_bad(struct pt_regs *regs, unsigned long error_code,
	    unsigned long address)
{
	struct task_struct *tsk;
	unsigned long flags;
	int sig;

	flags = oops_begin();
	tsk = current;
	sig = SIGKILL;

	printk(KERN_ALERT "%s: Corrupted page table at address %lx\n",
	       tsk->comm, address);
	dump_pagetable(address);

	tsk->thread.cr2		= address;
	tsk->thread.trap_nr	= X86_TRAP_PF;
	tsk->thread.error_code	= error_code;

	if (__die("Bad pagetable", regs, error_code))
		sig = 0;

	oops_end(flags, regs, sig);
}

static noinline void
no_context(struct pt_regs *regs, unsigned long error_code,
	   unsigned long address, int signal, int si_code)
{
	struct task_struct *tsk = current;
	unsigned long flags;
	int sig;

	/* Are we prepared to handle this kernel fault? */
	if (fixup_exception(regs)) {
		/*
		 * Any interrupt that takes a fault gets the fixup. This makes
		 * the below recursive fault logic only apply to a faults from
		 * task context.
		 */
		if (in_interrupt())
			return;

		/*
		 * Per the above we're !in_interrupt(), aka. task context.
		 *
		 * In this case we need to make sure we're not recursively
		 * faulting through the emulate_vsyscall() logic.
		 */
		if (current_thread_info()->sig_on_uaccess_error && signal) {
			tsk->thread.trap_nr = X86_TRAP_PF;
			tsk->thread.error_code = error_code | PF_USER;
			tsk->thread.cr2 = address;

			/* XXX: hwpoison faults will set the wrong code. */
			force_sig_info_fault(signal, si_code, address, tsk, 0);
		}

		/*
		 * Barring that, we can do the fixup and be happy.
		 */
		return;
	}

	/*
	 * 32-bit:
	 *
	 *   Valid to do another page fault here, because if this fault
	 *   had been triggered by is_prefetch fixup_exception would have
	 *   handled it.
	 *
	 * 64-bit:
	 *
	 *   Hall of shame of CPU/BIOS bugs.
	 */
	if (is_prefetch(regs, error_code, address))
		return;

	if (is_errata93(regs, address))
		return;

	/*
	 * Oops. The kernel tried to access some bad page. We'll have to
	 * terminate things with extreme prejudice:
	 */
	flags = oops_begin();

	show_fault_oops(regs, error_code, address);

	if (task_stack_end_corrupted(tsk))
		printk(KERN_EMERG "Thread overran stack, or stack corrupted\n");

	tsk->thread.cr2		= address;
	tsk->thread.trap_nr	= X86_TRAP_PF;
	tsk->thread.error_code	= error_code;

	sig = SIGKILL;
	if (__die("Oops", regs, error_code))
		sig = 0;

	/* Executive summary in case the body of the oops scrolled away */
	printk(KERN_DEFAULT "CR2: %016lx\n", address);

	oops_end(flags, regs, sig);
}

/*
 * Print out info about fatal segfaults, if the show_unhandled_signals
 * sysctl is set:
 */
static inline void
show_signal_msg(struct pt_regs *regs, unsigned long error_code,
		unsigned long address, struct task_struct *tsk)
{
	if (!unhandled_signal(tsk, SIGSEGV))
		return;

	if (!printk_ratelimit())
		return;

	printk("%s%s[%d]: segfault at %lx ip %p sp %p error %lx",
		task_pid_nr(tsk) > 1 ? KERN_INFO : KERN_EMERG,
		tsk->comm, task_pid_nr(tsk), address,
		(void *)regs->ip, (void *)regs->sp, error_code);

	print_vma_addr(KERN_CONT " in ", regs->ip);

	printk(KERN_CONT "\n");
}

static void
__bad_area_nosemaphore(struct pt_regs *regs, unsigned long error_code,
		       unsigned long address, int si_code)
{
	struct task_struct *tsk = current;

	/* User mode accesses just cause a SIGSEGV */
	if (error_code & PF_USER) {
		/*
		 * It's possible to have interrupts off here:
		 */
		local_irq_enable();

		/*
		 * Valid to do another page fault here because this one came
		 * from user space:
		 */
		if (is_prefetch(regs, error_code, address))
			return;

		if (is_errata100(regs, address))
			return;

#ifdef CONFIG_X86_64
		/*
		 * Instruction fetch faults in the vsyscall page might need
		 * emulation.
		 */
		if (unlikely((error_code & PF_INSTR) &&
			     ((address & ~0xfff) == VSYSCALL_ADDR))) {
			if (emulate_vsyscall(regs, address))
				return;
		}
#endif
		/* Kernel addresses are always protection faults: */
		if (address >= TASK_SIZE)
			error_code |= PF_PROT;

		if (likely(show_unhandled_signals))
			show_signal_msg(regs, error_code, address, tsk);

		tsk->thread.cr2		= address;
		tsk->thread.error_code	= error_code;
		tsk->thread.trap_nr	= X86_TRAP_PF;

		force_sig_info_fault(SIGSEGV, si_code, address, tsk, 0);

		return;
	}

	if (is_f00f_bug(regs, address))
		return;

	no_context(regs, error_code, address, SIGSEGV, si_code);
}

static noinline void
bad_area_nosemaphore(struct pt_regs *regs, unsigned long error_code,
		     unsigned long address)
{
	__bad_area_nosemaphore(regs, error_code, address, SEGV_MAPERR);
}

static void
__bad_area(struct pt_regs *regs, unsigned long error_code,
	   unsigned long address, int si_code)
{
	struct mm_struct *mm = current->mm;

	/*
	 * Something tried to access memory that isn't in our memory map..
	 * Fix it, but check if it's kernel or user first..
	 */
	up_read(&mm->mmap_sem);

	__bad_area_nosemaphore(regs, error_code, address, si_code);
}

static noinline void
bad_area(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	__bad_area(regs, error_code, address, SEGV_MAPERR);
}

static noinline void
bad_area_access_error(struct pt_regs *regs, unsigned long error_code,
		      unsigned long address)
{
	__bad_area(regs, error_code, address, SEGV_ACCERR);
}

static void
do_sigbus(struct pt_regs *regs, unsigned long error_code, unsigned long address,
	  unsigned int fault)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->mm;
	int code = BUS_ADRERR;

	up_read(&mm->mmap_sem);

	/* Kernel mode? Handle exceptions or die: */
	if (!(error_code & PF_USER)) {
		no_context(regs, error_code, address, SIGBUS, BUS_ADRERR);
		return;
	}

	/* User-space => ok to do another page fault: */
	if (is_prefetch(regs, error_code, address))
		return;

	tsk->thread.cr2		= address;
	tsk->thread.error_code	= error_code;
	tsk->thread.trap_nr	= X86_TRAP_PF;

#ifdef CONFIG_MEMORY_FAILURE
	if (fault & (VM_FAULT_HWPOISON|VM_FAULT_HWPOISON_LARGE)) {
		printk(KERN_ERR
	"MCE: Killing %s:%d due to hardware memory corruption fault at %lx\n",
			tsk->comm, tsk->pid, address);
		code = BUS_MCEERR_AR;
	}
#endif
	force_sig_info_fault(SIGBUS, code, address, tsk, fault);
}

static noinline void
mm_fault_error(struct pt_regs *regs, unsigned long error_code,
	       unsigned long address, unsigned int fault)
{
	if (fatal_signal_pending(current) && !(error_code & PF_USER)) {
		up_read(&current->mm->mmap_sem);
		no_context(regs, error_code, address, 0, 0);
		return;
	}

	if (fault & VM_FAULT_OOM) {
		/* Kernel mode? Handle exceptions or die: */
		if (!(error_code & PF_USER)) {
			up_read(&current->mm->mmap_sem);
			no_context(regs, error_code, address,
				   SIGSEGV, SEGV_MAPERR);
			return;
		}

		up_read(&current->mm->mmap_sem);

		/*
		 * We ran out of memory, call the OOM killer, and return the
		 * userspace (which will retry the fault, or kill us if we got
		 * oom-killed):
		 */
		pagefault_out_of_memory();
	} else {
		if (fault & (VM_FAULT_SIGBUS|VM_FAULT_HWPOISON|
			     VM_FAULT_HWPOISON_LARGE))
			do_sigbus(regs, error_code, address, fault);
		else
			BUG();
	}
}

static int spurious_fault_check(unsigned long error_code, pte_t *pte)
{
	/* 检查缺少页写权限，没有则返回0 */
	if ((error_code & PF_WRITE) && !pte_write(*pte))
		return 0;

	/* 检查缺少执行权限，没有则返回0 */
	if ((error_code & PF_INSTR) && !pte_exec(*pte))
		return 0;

	return 1;
}

/*
 * Handle a spurious fault caused by a stale TLB entry.
 *
 * This allows us to lazily refresh the TLB when increasing the
 * permissions of a kernel page (RO -> RW or NX -> X).  Doing it
 * eagerly is very expensive since that implies doing a full
 * cross-processor TLB flush, even if no stale TLB entries exist
 * on other processors.
 *
 * Spurious faults may only occur if the TLB contains an entry with
 * fewer permission than the page table entry.  Non-present (P = 0)
 * and reserved bit (R = 1) faults are never spurious.
 *
 * There are no security implications to leaving a stale TLB when
 * increasing the permissions on a page.
 *
 * Returns non-zero if a spurious fault was handled, zero otherwise.
 *
 * See Intel Developer's Manual Vol 3 Section 4.10.4.3, bullet 3
 * (Optional Invalidation).
 */
/* 发生在某个TLB项的权限小于对应的页表项权限，也就是TLB过期了
 * 一般这种情况是给内核的页增加权限的时候允许懒惰tlb刷新时使用
 * 只有页在内存中才会发生此异常
 */
static noinline int
spurious_fault(unsigned long error_code, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int ret;

	/*
	 * Only writes to RO or instruction fetches from NX may cause
	 * spurious faults.
	 *
	 * These could be from user or supervisor accesses but the TLB
	 * is only lazily flushed after a kernel mapping protection
	 * change, so user accesses are not expected to cause spurious
	 * faults.
	 */
	/* 错误代码不等于处于保护错误并且是没有可写权限或者指令错误时，则直接返回 */
	if (error_code != (PF_WRITE | PF_PROT)
	    && error_code != (PF_INSTR | PF_PROT))
		return 0;

	/* 
	 * 这下面处理的情况有两种
	 * 1.访问了没有可写权限的页表项(但实际又需要可写权限)
	 * 2.指令错误，也就是没有此线性地址对应的页没有执行权限
	 */

	/* 根据线性地址获取主内核页表的页全局目录项 */
	pgd = init_mm.pgd + pgd_index(address);
	if (!pgd_present(*pgd))
		return 0;

	/* 根据线性地址获取主内核页表的页上级目录项 */
	pud = pud_offset(pgd, address);
	/* 判断页上级目录所在页表是否处于内存中 */
	if (!pud_present(*pud))
		return 0;

	/* 如果开启了PSE(扩展分页)，则只有1级页表，pud就是页表项，一个页为4MB大小
	 * 此时直接进行检查，并返回
	 */
	if (pud_large(*pud))
		return spurious_fault_check(error_code, (pte_t *) pud);
	
	/* 根据线性地址获取主内核页表的页中间目录项 */
	pmd = pmd_offset(pud, address);
	/* 判断页表是否处于内存中 */
	if (!pmd_present(*pmd))
		return 0;
	
	/* 不太清楚这里为什么也要判断PSE */
	if (pmd_large(*pmd))
		return spurious_fault_check(error_code, (pte_t *) pmd);

	/* 根据线性地址address获取主内核页表的页表项 */
	pte = pte_offset_kernel(pmd, address);
	/* 判断页是否在内存中，不在则直接返回 */
	if (!pte_present(*pte))
		return 0;

	/* 进行检查 */
	ret = spurious_fault_check(error_code, pte);
	if (!ret)
		return 0;

	/*
	 * Make sure we have permissions in PMD.
	 * If not, then there's a bug in the page tables:
	 */
	/* 检查页中间目录项的权限 */
	ret = spurious_fault_check(error_code, (pte_t *) pmd);
	/* 因为执行到这里说明页表项权限是有可写权限或者可执行权限的，而页中间目录项的权限应该与页表项一致 */
	WARN_ONCE(!ret, "PMD has incorrect permission bits\n");

	return ret;
}
NOKPROBE_SYMBOL(spurious_fault);

int show_unhandled_signals = 1;

static inline int
access_error(unsigned long error_code, struct vm_area_struct *vma)
{
	if (error_code & PF_WRITE) {
		/* write, present and write, not present: */
		if (unlikely(!(vma->vm_flags & VM_WRITE)))
			return 1;
		return 0;
	}

	/* read, present: */
	if (unlikely(error_code & PF_PROT))
		return 1;

	/* read, not present: */
	if (unlikely(!(vma->vm_flags & (VM_READ | VM_EXEC | VM_WRITE))))
		return 1;

	return 0;
}

static int fault_in_kernel_space(unsigned long address)
{
	return address >= TASK_SIZE_MAX;
}

static inline bool smap_violation(int error_code, struct pt_regs *regs)
{
	if (!IS_ENABLED(CONFIG_X86_SMAP))
		return false;

	if (!static_cpu_has(X86_FEATURE_SMAP))
		return false;

	if (error_code & PF_USER)
		return false;

	if (!user_mode_vm(regs) && (regs->flags & X86_EFLAGS_AC))
		return false;

	return true;
}

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 *
 * This function must have noinline because both callers
 * {,trace_}do_page_fault() have notrace on. Having this an actual function
 * guarantees there's a function trace entry.
 */
/* regs: 异常发生时CPU寄存器中的值
 * error_code: 异常原因，一共5个bit，具体可见x86_pf_error_code
 * address: 发生错误的线性地址
 * error_code:
 *   bit 0 ==	 0: no page found 缺页	1: protection fault 保护错误
 *   bit 1 ==	 0: read access	读权限错误	1: write access 写权限错误
 *   bit 2 ==	 0: kernel-mode access 内核模式权限错误	1: user-mode access 用户模式权限错误
 *   bit 3 ==				1: use of reserved bit detected 保护位
 *   bit 4 ==				1: fault was an instruction fetch 指令造成的错误，一般是需要执行线性地址的指令，但是所在页没有执行权限
 */
/* 发生在内核态的缺页异常情况有4种:
 * 1.内核试图访问进程地址空间的页，但是页不存在(请求调页)，或者内核写一个进程地址空间的只读页(写时复制)。此时需要分配页框
 * 2.内核访问内核地址空间的页，但是此页的页表还没被初始化(其他进程同步vmalloc的页表时)
 * 3.内核函数包含编程错误时。(属于异常情况)
 * 4.系统调用试图读写一个内存区，但是此内存区不属于该进程的地址空间。(属于异常情况)
 */
static noinline void
__do_page_fault(struct pt_regs *regs, unsigned long error_code,
		unsigned long address)
{
	struct vm_area_struct *vma;
	struct task_struct *tsk;
	struct mm_struct *mm;
	int fault;
	/* 默认flags设置为可重试和允许杀死发生此缺页异常的进程 */
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	/* 当前进程 */
	tsk = current;
	/* 当前进程的内存描述符 */
	mm = tsk->mm;

	/*
	 * Detect and handle instructions that would cause a page fault for
	 * both a tracked kernel page and a userspace page.
	 */
	if (kmemcheck_active(regs))
		kmemcheck_hide(regs);
	/* 将此信号量提前装入缓存中 */
	prefetchw(&mm->mmap_sem);

	if (unlikely(kmmio_fault(regs, address)))
		return;

	/*
	 * We fault-in kernel-space virtual memory on-demand. The
	 * 'reference' page table is init_mm.pgd.
	 *
	 * NOTE! We MUST NOT take any locks for this case. We may
	 * be in an interrupt or a critical region, and should
	 * only copy the information from the master page table,
	 * nothing more.
	 *
	 * This verifies that the fault happens in kernel space
	 * (error_code & 4) == 0, and that the fault was not a
	 * protection error (error_code & 9) == 0.
	 */
	if (unlikely(fault_in_kernel_space(address))) {
		/* 发生缺页异常的页在内核地址空间 */
		if (!(error_code & (PF_RSVD | PF_USER | PF_PROT))) {
			/* 发生在非连续物理内存区的处理，整个处理就是把主内核页表的address对应的页目录项复制给当前进程的页表 
			 * 原因是当发生非连续物理内存区映射时，只映射了主内核页表的address对应的页目录项~页表项，当其他进程访问这个地址时，产生缺页异常，然后先检查主内核页表此项是否有设置，有则复制过来
			 */
			if (vmalloc_fault(address) >= 0)
				return;

			if (kmemcheck_fault(regs, address, error_code))
				return;
		}

		/* Can handle a stale RO->RW TLB: */
		/* 检查是否是TLB失效的原因，此检查就是根据error_code检查最后的页表项是否有可写或者可执行权限 */
		if (spurious_fault(error_code, address))
			return;

		/* kprobes don't want to hook the spurious faults: */
		/* kprobes调试使用 */
		if (kprobes_fault(regs))
			return;
		/*
		 * Don't take the mm semaphore here. If we fixup a prefetch
		 * fault we could otherwise deadlock:
		 */
		/* 如果上面的检查不能搞定直接进入"非法访问"处理函数 */ 
		bad_area_nosemaphore(regs, error_code, address);

		return;
	}

	/* 以下就是发生缺页的页处于用户地址空间的处理 */
	/* kprobes don't want to hook the spurious faults: */
	/* 同内核空间发生的缺页异常处理的kprobes_fault，在用户地址空间的缺页异常不期望发生kprobes_fault */
	if (unlikely(kprobes_fault(regs)))
		return;

	if (unlikely(error_code & PF_RSVD))
		pgtable_bad(regs, error_code, address);

	if (unlikely(smap_violation(error_code, regs))) {
		bad_area_nosemaphore(regs, error_code, address);
		return;
	}

	/*
	 * If we're in an interrupt, have no user context or are running
	 * in an atomic region then we must not take the fault:
	 */
	/* 处于中断上下文，这个情况也是不期望发生的 */
	if (unlikely(in_atomic() || !mm)) {
		bad_area_nosemaphore(regs, error_code, address);
		return;
	}

	/*
	 * It's safe to allow irq's after cr2 has been saved and the
	 * vmalloc fault has been handled.
	 *
	 * User-mode registers count as a user access even for any
	 * potential system fault or CPU buglet:
	 */
	/* 通过cs寄存器的RPL位检查是否处于用户态，注意有可能地址处于用户地址空间，但却是内核态 */
	if (user_mode_vm(regs)) {
		/* 处于用户态处理，开启终端 */
		local_irq_enable();
		/* 将缺页错误代码标记上处于用户态 */
		error_code |= PF_USER;
		/* flags页标记上是用户态 */
		flags |= FAULT_FLAG_USER;
	} else {
		/* 处于内核态，开启中断 */
		if (regs->flags & X86_EFLAGS_IF)
			local_irq_enable();
	}

	/* perf使用 */
	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, address);

	/* 错误代码中包含缺少可写权限 */
	if (error_code & PF_WRITE)
		flags |= FAULT_FLAG_WRITE;

	/*
	 * When running in the kernel we expect faults to occur only to
	 * addresses in user space.  All other faults represent errors in
	 * the kernel and should generate an OOPS.  Unfortunately, in the
	 * case of an erroneous fault occurring in a code path which already
	 * holds mmap_sem we will deadlock attempting to validate the fault
	 * against the address space.  Luckily the kernel only validly
	 * references user space from well defined areas of code, which are
	 * listed in the exceptions table.
	 *
	 * As the vast majority of faults will be valid we will only perform
	 * the source reference check when there is a possibility of a
	 * deadlock. Attempt to lock the address space, if we cannot we then
	 * validate the source. If this is invalid we can skip the address
	 * space check, thus avoiding the deadlock:
	 */
	if (unlikely(!down_read_trylock(&mm->mmap_sem))) {
		/* 获取mm_struct中的读锁失败 */
		/* 如果处于内核态并且找不到异常表中的异常时，非法访问 */
		if ((error_code & PF_USER) == 0 &&
		    !search_exception_tables(regs->ip)) {
			bad_area_nosemaphore(regs, error_code, address);
			return;
		}
retry:
		/* 获取读锁，若没获得则睡眠等待 */
		down_read(&mm->mmap_sem);
	} else {
		/*
		 * The above down_read_trylock() might have succeeded in
		 * which case we'll have missed the might_sleep() from
		 * down_read():
		 */
		/* 可能会睡眠一下 */
		might_sleep();
	}

	/* 查找包含着给定地址addr的vma线性区，如果没有，也有可能找到离addr最近的下一个vma线性区 */
	vma = find_vma(mm, address);
	if (unlikely(!vma)) {
		/* 没有匹配的线性区，进行错误处理 */
		bad_area(regs, error_code, address);
		return;
	}
	/* 简单判断下是否线性区符合，符合则跳转到good_area */
	if (likely(vma->vm_start <= address))
		goto good_area;
	/* 这种情况是判断线性区是向下生长的情况(栈)，如果address比线性区开始地址小的情况有这种情况 */
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		bad_area(regs, error_code, address);
		return;
	}

	/* 如果发生在用户态 */
	if (error_code & PF_USER) {
		/*
		 * Accessing the stack below %sp is always a bug.
		 * The large cushion allows instructions like enter
		 * and pusha to work. ("enter $65535, $31" pushes
		 * 32 pointers and then decrements %sp by 65535.)
		 */
		/* 这里应该是判断address是否超过最大栈大小，64k + 128? */
		if (unlikely(address + 65536 + 32 * sizeof(unsigned long) < regs->sp)) {
			bad_area(regs, error_code, address);
			return;
		}
	}
	/* 需要扩展用户栈大小的情况处理 */
	if (unlikely(expand_stack(vma, address))) {
		bad_area(regs, error_code, address);
		return;
	}

	/*
	 * Ok, we have a good vm_area for this memory access, so
	 * we can handle it..
	 */
good_area:
	/* 这里开始是address是一个合法合理的地址 */
	/* 权限检查，检查error_code中有写权限错误，而线性区又没有写权限的情况，这种情况发生在向一个只读线性区地址写入数据 */
	if (unlikely(access_error(error_code, vma))) {
		bad_area_access_error(regs, error_code, address);
		return;
	}

	/*
	 * If for any reason at all we couldn't handle the fault,
	 * make sure we exit gracefully rather than endlessly redo
	 * the fault.  Since we never set FAULT_FLAG_RETRY_NOWAIT, if
	 * we get VM_FAULT_RETRY back, the mmap_sem has been unlocked.
	 */
	/* 区分错误类型 */
	fault = handle_mm_fault(mm, vma, address, flags);

	/*
	 * If we need to retry but a fatal signal is pending, handle the
	 * signal first. We do not need to release the mmap_sem because it
	 * would already be released in __lock_page_or_retry in mm/filemap.c.
	 */
	if (unlikely((fault & VM_FAULT_RETRY) && fatal_signal_pending(current)))
		return;

	if (unlikely(fault & VM_FAULT_ERROR)) {
		mm_fault_error(regs, error_code, address, fault);
		return;
	}

	/*
	 * Major/minor page fault accounting is only done on the
	 * initial attempt. If we go through a retry, it is extremely
	 * likely that the page will be found in page cache at that point.
	 */
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			tsk->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1,
				      regs, address);
		} else {
			tsk->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1,
				      regs, address);
		}
		if (fault & VM_FAULT_RETRY) {
			/* Clear FAULT_FLAG_ALLOW_RETRY to avoid any risk
			 * of starvation. */
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			flags |= FAULT_FLAG_TRIED;
			goto retry;
		}
	}

	check_v8086_mode(regs, address, tsk);

	up_read(&mm->mmap_sem);
}
NOKPROBE_SYMBOL(__do_page_fault);

/* 缺页异常
 * regs: 包含缺页异常发生时CPU寄存器的值
 * error_code: 3位，第0位被清0，表明由访问一个不存在的页所引起(页表中Present标志被清0)，否则，如果第0位被设置，则异常由无效访问权限引起
 *                  第1位被清0，异常由读访问或者执行访问所引起，如果此位被设置，则异常是由写访问所引起
 *                  第2位被清0，异常发生在内核态，被置为，异常发生在用户态
 */
dotraplinkage void notrace
do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
	/* 读取引起异常的线性地址，CPU会把这个地址放在cr2寄存器 */
	unsigned long address = read_cr2(); /* Get the faulting address */
	enum ctx_state prev_state;

	/*
	 * We must have this function tagged with __kprobes, notrace and call
	 * read_cr2() before calling anything else. To avoid calling any kind
	 * of tracing machinery before we've observed the CR2 value.
	 *
	 * exception_{enter,exit}() contain all sorts of tracepoints.
	 */
	/* 保存当前状态 */
	prev_state = exception_enter();
	/* 主要处理函数 */
	__do_page_fault(regs, error_code, address);
	/* 恢复状态 */
	exception_exit(prev_state);
}
NOKPROBE_SYMBOL(do_page_fault);

#ifdef CONFIG_TRACING
static nokprobe_inline void
trace_page_fault_entries(unsigned long address, struct pt_regs *regs,
			 unsigned long error_code)
{
	if (user_mode(regs))
		trace_page_fault_user(address, regs, error_code);
	else
		trace_page_fault_kernel(address, regs, error_code);
}

dotraplinkage void notrace
trace_do_page_fault(struct pt_regs *regs, unsigned long error_code)
{
	/*
	 * The exception_enter and tracepoint processing could
	 * trigger another page faults (user space callchain
	 * reading) and destroy the original cr2 value, so read
	 * the faulting address now.
	 */
	unsigned long address = read_cr2();
	enum ctx_state prev_state;

	prev_state = exception_enter();
	trace_page_fault_entries(address, regs, error_code);
	__do_page_fault(regs, error_code, address);
	exception_exit(prev_state);
}
NOKPROBE_SYMBOL(trace_do_page_fault);
#endif /* CONFIG_TRACING */
