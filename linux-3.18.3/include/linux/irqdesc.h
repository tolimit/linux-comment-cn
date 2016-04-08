#ifndef _LINUX_IRQDESC_H
#define _LINUX_IRQDESC_H

/*
 * Core internal functions to deal with irq descriptors
 *
 * This include will move to kernel/irq once we cleaned up the tree.
 * For now it's included from <linux/irq.h>
 */

struct irq_affinity_notify;
struct proc_dir_entry;
struct module;
struct irq_desc;
struct irq_domain;
struct pt_regs;

/**
 * struct irq_desc - interrupt descriptor
 * @irq_data:		per irq and chip data passed down to chip functions
 * @kstat_irqs:		irq stats per cpu
 * @handle_irq:		highlevel irq-events handler
 * @preflow_handler:	handler called before the flow handler (currently used by sparc)
 * @action:		the irq action chain
 * @status:		status information
 * @core_internal_state__do_not_mess_with_it: core internal status information
 * @depth:		disable-depth, for nested irq_disable() calls
 * @wake_depth:		enable depth, for multiple irq_set_irq_wake() callers
 * @irq_count:		stats field to detect stalled irqs
 * @last_unhandled:	aging timer for unhandled count
 * @irqs_unhandled:	stats field for spurious unhandled interrupts
 * @threads_handled:	stats field for deferred spurious detection of threaded handlers
 * @threads_handled_last: comparator field for deferred spurious detection of theraded handlers
 * @lock:		locking for SMP
 * @affinity_hint:	hint to user space for preferred irq affinity
 * @affinity_notify:	context for notification of affinity changes
 * @pending_mask:	pending rebalanced interrupts
 * @threads_oneshot:	bitfield to handle shared oneshot threads
 * @threads_active:	number of irqaction threads currently running
 * @wait_for_threads:	wait queue for sync_irq to wait for threaded handlers
 * @nr_actions:		number of installed actions on this descriptor
 * @no_suspend_depth:	number of irqactions on a irq descriptor with
 *			IRQF_NO_SUSPEND set
 * @force_resume_depth:	number of irqactions on a irq descriptor with
 *			IRQF_FORCE_RESUME set
 * @dir:		/proc/irq/ procfs entry
 * @name:		flow handler name for /proc/interrupts output
 */
struct irq_desc {
	struct irq_data		irq_data;
	/* irq的统计信息，在proc中可查到 */
	unsigned int __percpu	*kstat_irqs;
	
	/* 回调函数，当此中断产生中断时，会调用handle_irq，在handle_irq中进行遍历irqaction链表
	 * handle_simple_irq  用于简单处理；
	 * handle_level_irq  用于电平触发中断的流控处理；
	 * handle_edge_irq  用于边沿触发中断的流控处理；
	 * handle_fasteoi_irq  用于需要响应eoi的中断控制器；
	 * handle_percpu_irq  用于只在单一cpu响应的中断；
	 * handle_nested_irq  用于处理使用线程的嵌套中断；
	 */
	irq_flow_handler_t	handle_irq;
#ifdef CONFIG_IRQ_PREFLOW_FASTEOI
	irq_preflow_handler_t	preflow_handler;
#endif
	/* 中断服务例程链表 */
	struct irqaction	*action;	/* IRQ action list */
	/* 状态 */
	unsigned int		status_use_accessors;
	/* 函数调用中使用，另一个名称为istate */
	unsigned int		core_internal_state__do_not_mess_with_it;
	/* 嵌套深度，中断线被激活显示0，如果为正数，表示被禁止次数 */
	unsigned int		depth;		/* nested irq disables */
	unsigned int		wake_depth;	/* nested wake enables */
	/* 此中断线上发生的中断次数 */
	unsigned int		irq_count;	/* For detecting broken IRQs */
	/* 上次发生未处理中断时的jiffies值 */
	unsigned long		last_unhandled;	/* Aging timer for unhandled count */
	/* 中断线上无法处理的中断次数，如果当第100000次中断发生时，有超过99900次是意外中断，系统会禁止这条中断线 */
	unsigned int		irqs_unhandled;
	atomic_t		threads_handled;
	int			threads_handled_last;
	/* 锁 */
	raw_spinlock_t		lock;
	struct cpumask		*percpu_enabled;
#ifdef CONFIG_SMP
	/* CPU亲和力关系，每个CPU是占一个bit长度，某CPU位置1表明此CPU可以进行此中断的执行处理 */
	const struct cpumask	*affinity_hint;
	struct irq_affinity_notify *affinity_notify;
#ifdef CONFIG_GENERIC_PENDING_IRQ
	/* 用于调整irq在各个cpu之间的平衡 */
	cpumask_var_t		pending_mask;
#endif
#endif
	unsigned long		threads_oneshot;
	atomic_t		threads_active;
	/* 用于synchronize_irq()，等待该irq所有线程完成 */
	wait_queue_head_t       wait_for_threads;
#ifdef CONFIG_PM_SLEEP
	/* irqaction数量 */
	unsigned int		nr_actions;
	unsigned int		no_suspend_depth;
	unsigned int		force_resume_depth;
#endif
#ifdef CONFIG_PROC_FS
	/* 指向与IRQn相关的/proc/irq/n目录的描述符 */
	struct proc_dir_entry	*dir;
#endif
	int			parent_irq;
	struct module		*owner;
	/* 在/proc/interrupts所显示名称 */
	const char		*name;
} ____cacheline_internodealigned_in_smp;

#ifndef CONFIG_SPARSE_IRQ
extern struct irq_desc irq_desc[NR_IRQS];
#endif

static inline struct irq_data *irq_desc_get_irq_data(struct irq_desc *desc)
{
	return &desc->irq_data;
}

static inline struct irq_chip *irq_desc_get_chip(struct irq_desc *desc)
{
	return desc->irq_data.chip;
}

static inline void *irq_desc_get_chip_data(struct irq_desc *desc)
{
	return desc->irq_data.chip_data;
}

static inline void *irq_desc_get_handler_data(struct irq_desc *desc)
{
	return desc->irq_data.handler_data;
}

static inline struct msi_desc *irq_desc_get_msi_desc(struct irq_desc *desc)
{
	return desc->irq_data.msi_desc;
}

/*
 * Architectures call this to let the generic IRQ layer
 * handle an interrupt. If the descriptor is attached to an
 * irqchip-style controller then we call the ->handle_irq() handler,
 * and it calls __do_IRQ() if it's attached to an irqtype-style controller.
 */
static inline void generic_handle_irq_desc(unsigned int irq, struct irq_desc *desc)
{
	/* 如果是电平触发那么会调用到handle_level_irq,边沿触发的中断会调用到handle_edge_irq */
	desc->handle_irq(irq, desc);
}

int generic_handle_irq(unsigned int irq);

#ifdef CONFIG_HANDLE_DOMAIN_IRQ
/*
 * Convert a HW interrupt number to a logical one using a IRQ domain,
 * and handle the result interrupt number. Return -EINVAL if
 * conversion failed. Providing a NULL domain indicates that the
 * conversion has already been done.
 */
int __handle_domain_irq(struct irq_domain *domain, unsigned int hwirq,
			bool lookup, struct pt_regs *regs);

static inline int handle_domain_irq(struct irq_domain *domain,
				    unsigned int hwirq, struct pt_regs *regs)
{
	return __handle_domain_irq(domain, hwirq, true, regs);
}
#endif

/* Test to see if a driver has successfully requested an irq */
static inline int irq_has_action(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	return desc->action != NULL;
}

/* caller has locked the irq_desc and both params are valid */
static inline void __irq_set_handler_locked(unsigned int irq,
					    irq_flow_handler_t handler)
{
	struct irq_desc *desc;

	desc = irq_to_desc(irq);
	desc->handle_irq = handler;
}

/* caller has locked the irq_desc and both params are valid */
static inline void
__irq_set_chip_handler_name_locked(unsigned int irq, struct irq_chip *chip,
				   irq_flow_handler_t handler, const char *name)
{
	struct irq_desc *desc;

	desc = irq_to_desc(irq);
	irq_desc_get_irq_data(desc)->chip = chip;
	desc->handle_irq = handler;
	desc->name = name;
}

static inline int irq_balancing_disabled(unsigned int irq)
{
	struct irq_desc *desc;

	desc = irq_to_desc(irq);
	return desc->status_use_accessors & IRQ_NO_BALANCING_MASK;
}

static inline int irq_is_percpu(unsigned int irq)
{
	struct irq_desc *desc;

	desc = irq_to_desc(irq);
	return desc->status_use_accessors & IRQ_PER_CPU;
}

static inline void
irq_set_lockdep_class(unsigned int irq, struct lock_class_key *class)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (desc)
		lockdep_set_class(&desc->lock, class);
}

#ifdef CONFIG_IRQ_PREFLOW_FASTEOI
static inline void
__irq_set_preflow_handler(unsigned int irq, irq_preflow_handler_t handler)
{
	struct irq_desc *desc;

	desc = irq_to_desc(irq);
	desc->preflow_handler = handler;
}
#endif

#endif
