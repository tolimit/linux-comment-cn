/*  linux/include/linux/clockchips.h
 *
 *  This file contains the structure definitions for clockchips.
 *
 *  If you are not a clockchip, or the time of day code, you should
 *  not be including this file!
 */
#ifndef _LINUX_CLOCKCHIPS_H
#define _LINUX_CLOCKCHIPS_H

/* Clock event notification values */
enum clock_event_nofitiers {
	CLOCK_EVT_NOTIFY_ADD,
	CLOCK_EVT_NOTIFY_BROADCAST_ON,
	CLOCK_EVT_NOTIFY_BROADCAST_OFF,
	CLOCK_EVT_NOTIFY_BROADCAST_FORCE,
	CLOCK_EVT_NOTIFY_BROADCAST_ENTER,
	CLOCK_EVT_NOTIFY_BROADCAST_EXIT,
	CLOCK_EVT_NOTIFY_SUSPEND,
	CLOCK_EVT_NOTIFY_RESUME,
	CLOCK_EVT_NOTIFY_CPU_DYING,
	CLOCK_EVT_NOTIFY_CPU_DEAD,
};

#ifdef CONFIG_GENERIC_CLOCKEVENTS_BUILD

#include <linux/clocksource.h>
#include <linux/cpumask.h>
#include <linux/ktime.h>
#include <linux/notifier.h>

struct clock_event_device;
struct module;

/* Clock event mode commands */
enum clock_event_mode {
	CLOCK_EVT_MODE_UNUSED = 0,
	CLOCK_EVT_MODE_SHUTDOWN,
	CLOCK_EVT_MODE_PERIODIC,
	CLOCK_EVT_MODE_ONESHOT,
	CLOCK_EVT_MODE_RESUME,
};

/*
 * Clock event features
 */
#define CLOCK_EVT_FEAT_PERIODIC		0x000001
#define CLOCK_EVT_FEAT_ONESHOT		0x000002
#define CLOCK_EVT_FEAT_KTIME		0x000004
/*
 * x86(64) specific misfeatures:
 *
 * - Clockevent source stops in C3 State and needs broadcast support.
 * - Local APIC timer is used as a dummy device.
 */
#define CLOCK_EVT_FEAT_C3STOP		0x000008
#define CLOCK_EVT_FEAT_DUMMY		0x000010

/*
 * Core shall set the interrupt affinity dynamically in broadcast mode
 */
#define CLOCK_EVT_FEAT_DYNIRQ		0x000020
#define CLOCK_EVT_FEAT_PERCPU		0x000040

/*
 * Clockevent device is based on a hrtimer for broadcast
 */
#define CLOCK_EVT_FEAT_HRTIMER		0x000080

/**
 * struct clock_event_device - clock event device descriptor
 * @event_handler:	Assigned by the framework to be called by the low
 *			level handler of the event source
 * @set_next_event:	set next event function using a clocksource delta
 * @set_next_ktime:	set next event function using a direct ktime value
 * @next_event:		local storage for the next event in oneshot mode
 * @max_delta_ns:	maximum delta value in ns
 * @min_delta_ns:	minimum delta value in ns
 * @mult:		nanosecond to cycles multiplier
 * @shift:		nanoseconds to cycles divisor (power of two)
 * @mode:		operating mode assigned by the management code
 * @features:		features
 * @retries:		number of forced programming retries
 * @set_mode:		set mode function
 * @broadcast:		function to broadcast events
 * @min_delta_ticks:	minimum delta value in ticks stored for reconfiguration
 * @max_delta_ticks:	maximum delta value in ticks stored for reconfiguration
 * @name:		ptr to clock event name
 * @rating:		variable to rate clock event devices
 * @irq:		IRQ number (only for non CPU local devices)
 * @bound_on:		Bound on CPU
 * @cpumask:		cpumask to indicate for which CPUs this device works
 * @list:		list head for the management code
 * @owner:		module reference
 */
/* 时钟事件设备结构
 * 它可以工作在周期触发或单次触发模式，系统可以对它进行编程，以确定下一次事件触发的时间
 * 主要用于实现普通定时器和高精度定时器，同时也用于产生tick事件，供给进程调度子系统使用
 * clocksource: 用于描述时钟源
 * clock_event_device: 用于描述定时器
 */
/* 每个CPU都要它自己的 clock_event_device 链表 */

/* clock_event_device 代表着一个时钟硬件设备，该设备就好像是一个具有事件触发能力（通常就是指中断）的clocksource，它不停地计数
 * 当计数值达到预先编程设定的数值那一刻，会引发一个时钟事件中断，继而触发该设备的事件处理回调函数，以完成对时钟事件的处理。 
 */
 
/* tick_device是基于clock_event_device的进一步封装，用于代替原有的时钟滴答中断，给内核提供tick事件，以完成进程的调度和进程信息统计，负载平衡和时间更新等操作。 */
/* 全部的 clock_event_device 都会挂在全局变量 clockevent_devices 中 */
struct clock_event_device {
	/* 定时器回调函数指针，中断服务例程会调用 */
	void			(*event_handler)(struct clock_event_device *);
	/* 设置下一次触发的时间，使用类似于clocksource的cycle计数值（离现在的cycle差值）作为参数。 */
	int			(*set_next_event)(unsigned long evt,
						  struct clock_event_device *);
	/* 设置下一次触发的时间，直接使用ktime时间作为参数。 */
	int			(*set_next_ktime)(ktime_t expires,
						  struct clock_event_device *);
	/* 下一次触发时间，使用的是与cycle的相对值 */
	ktime_t			next_event;
	/* 可设置的最大时间差，单位是纳秒。 */
	u64			max_delta_ns;
	/* 可设置的最小时间差，单位是纳秒。 */
	u64			min_delta_ns;
	/* mult和shift与clocksource中的类似，只不过是用于把纳秒转换为cycle。 */
	u32			mult;
	u32			shift;
	/* 该时钟事件设备的工作模式
	 * CLOCK_EVT_MODE_PERIODIC: 周期触发模式，设置后按给定的周期不停地触发事件
	 * CLOCK_EVT_MODE_ONESHOT: 单次触发模式，只在设置好的触发时刻触发一次；
	 */
	enum clock_event_mode	mode;
	unsigned int		features;
	unsigned long		retries;

	void			(*broadcast)(const struct cpumask *mask);
	/* 用于设置时钟事件设备的工作模式。 */
	void			(*set_mode)(enum clock_event_mode mode,
					    struct clock_event_device *);
	void			(*suspend)(struct clock_event_device *);
	void			(*resume)(struct clock_event_device *);
	unsigned long		min_delta_ticks;
	unsigned long		max_delta_ticks;

	const char		*name;
	/* 精度 */
	int			rating;
	int			irq;
	int			bound_on;
	const struct cpumask	*cpumask;
	/* 用于组织 clock_event_device 链表 */
	struct list_head	list;
	struct module		*owner;
} ____cacheline_aligned;

/*
 * Calculate a multiplication factor for scaled math, which is used to convert
 * nanoseconds based values to clock ticks:
 *
 * clock_ticks = (nanoseconds * factor) >> shift.
 *
 * div_sc is the rearranged equation to calculate a factor from a given clock
 * ticks / nanoseconds ratio:
 *
 * factor = (clock_ticks << shift) / nanoseconds
 */
static inline unsigned long div_sc(unsigned long ticks, unsigned long nsec,
				   int shift)
{
	uint64_t tmp = ((uint64_t)ticks) << shift;

	do_div(tmp, nsec);
	return (unsigned long) tmp;
}

/* Clock event layer functions */
extern u64 clockevent_delta2ns(unsigned long latch,
			       struct clock_event_device *evt);
extern void clockevents_register_device(struct clock_event_device *dev);
extern int clockevents_unbind_device(struct clock_event_device *ced, int cpu);

extern void clockevents_config(struct clock_event_device *dev, u32 freq);
extern void clockevents_config_and_register(struct clock_event_device *dev,
					    u32 freq, unsigned long min_delta,
					    unsigned long max_delta);

extern int clockevents_update_freq(struct clock_event_device *ce, u32 freq);

extern void clockevents_exchange_device(struct clock_event_device *old,
					struct clock_event_device *new);
extern void clockevents_set_mode(struct clock_event_device *dev,
				 enum clock_event_mode mode);
extern int clockevents_program_event(struct clock_event_device *dev,
				     ktime_t expires, bool force);

extern void clockevents_handle_noop(struct clock_event_device *dev);

static inline void
clockevents_calc_mult_shift(struct clock_event_device *ce, u32 freq, u32 minsec)
{
	return clocks_calc_mult_shift(&ce->mult, &ce->shift, NSEC_PER_SEC,
				      freq, minsec);
}

extern void clockevents_suspend(void);
extern void clockevents_resume(void);

#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
#ifdef CONFIG_ARCH_HAS_TICK_BROADCAST
extern void tick_broadcast(const struct cpumask *mask);
#else
#define tick_broadcast	NULL
#endif
extern int tick_receive_broadcast(void);
#endif

#if defined(CONFIG_GENERIC_CLOCKEVENTS_BROADCAST) && defined(CONFIG_TICK_ONESHOT)
extern void tick_setup_hrtimer_broadcast(void);
extern int tick_check_broadcast_expired(void);
#else
static inline int tick_check_broadcast_expired(void) { return 0; }
static inline void tick_setup_hrtimer_broadcast(void) {};
#endif

#ifdef CONFIG_GENERIC_CLOCKEVENTS
extern int clockevents_notify(unsigned long reason, void *arg);
#else
static inline int clockevents_notify(unsigned long reason, void *arg) { return 0; }
#endif

#else /* CONFIG_GENERIC_CLOCKEVENTS_BUILD */

static inline void clockevents_suspend(void) {}
static inline void clockevents_resume(void) {}

static inline int clockevents_notify(unsigned long reason, void *arg) { return 0; }
static inline int tick_check_broadcast_expired(void) { return 0; }
static inline void tick_setup_hrtimer_broadcast(void) {};

#endif

#endif
