#ifndef _ASM_X86_HARDIRQ_H
#define _ASM_X86_HARDIRQ_H

#include <linux/threads.h>
#include <linux/irq.h>

typedef struct {
	unsigned int __softirq_pending;
	unsigned int __nmi_count;	/* arch dependent */
#ifdef CONFIG_X86_LOCAL_APIC
	unsigned int apic_timer_irqs;	/* arch dependent */
	unsigned int irq_spurious_count;
	unsigned int icr_read_retry_count;
#endif
#ifdef CONFIG_HAVE_KVM
	unsigned int kvm_posted_intr_ipis;
#endif
	unsigned int x86_platform_ipis;	/* arch dependent */
	unsigned int apic_perf_irqs;
	unsigned int apic_irq_work_irqs;
#ifdef CONFIG_SMP
	unsigned int irq_resched_count;
	unsigned int irq_call_count;
	/*
	 * irq_tlb_count is double-counted in irq_call_count, so it must be
	 * subtracted from irq_call_count when displaying irq_call_count
	 */
	unsigned int irq_tlb_count;
#endif
#ifdef CONFIG_X86_THERMAL_VECTOR
	unsigned int irq_thermal_count;
#endif
#ifdef CONFIG_X86_MCE_THRESHOLD
	unsigned int irq_threshold_count;
#endif
#if IS_ENABLED(CONFIG_HYPERV) || defined(CONFIG_XEN)
	unsigned int irq_hv_callback_count;
#endif
} ____cacheline_aligned irq_cpustat_t;

DECLARE_PER_CPU_SHARED_ALIGNED(irq_cpustat_t, irq_stat);

#define __ARCH_IRQ_STAT

#define inc_irq_stat(member)	this_cpu_inc(irq_stat.member)

/* 获取当前CPU的软中断位掩码 */
/* 软中断位掩码用于描述挂起的软中断 */
/* 挂起表明等待被执行 */
/* 一般用于判断有没有软中断需要执行 */
/* 周期性被调用来判断是否有软中断需要执行
 * 1.内核调用local_bh_enable()函数激活本地CPU的软中断时
 * 2.当do_IRQ()完成I/O中断的处理时或调用irq_exit()时
 * 3.当smp_apic_timer_interrupt()函数处理完本地定时器中断时
 * 4.在多处理器系统中，当CPU处理完被CALL_FUNCTION_VECTOR处理器间中断所触发的函数时
 * 5.当一个特殊的ksoftirqd/n内核线程被唤醒时
 */
#define local_softirq_pending()	this_cpu_read(irq_stat.__softirq_pending)

#define __ARCH_SET_SOFTIRQ_PENDING

#define set_softirq_pending(x)	\
		this_cpu_write(irq_stat.__softirq_pending, (x))
#define or_softirq_pending(x)	this_cpu_or(irq_stat.__softirq_pending, (x))

extern void ack_bad_irq(unsigned int irq);

extern u64 arch_irq_stat_cpu(unsigned int cpu);
#define arch_irq_stat_cpu	arch_irq_stat_cpu

extern u64 arch_irq_stat(void);
#define arch_irq_stat		arch_irq_stat

#endif /* _ASM_X86_HARDIRQ_H */
