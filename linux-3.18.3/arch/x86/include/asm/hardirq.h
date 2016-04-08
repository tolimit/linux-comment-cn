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

/* ��ȡ��ǰCPU�����ж�λ���� */
/* ���ж�λ��������������������ж� */
/* ��������ȴ���ִ�� */
/* һ�������ж���û�����ж���Ҫִ�� */
/* �����Ա��������ж��Ƿ������ж���Ҫִ��
 * 1.�ں˵���local_bh_enable()���������CPU�����ж�ʱ
 * 2.��do_IRQ()���I/O�жϵĴ���ʱ�����irq_exit()ʱ
 * 3.��smp_apic_timer_interrupt()���������걾�ض�ʱ���ж�ʱ
 * 4.�ڶദ����ϵͳ�У���CPU�����걻CALL_FUNCTION_VECTOR���������ж��������ĺ���ʱ
 * 5.��һ�������ksoftirqd/n�ں��̱߳�����ʱ
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
