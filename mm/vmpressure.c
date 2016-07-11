/*
 * Linux VM pressure
 *
 * Copyright 2012 Linaro Ltd.
 *		  Anton Vorontsov <anton.vorontsov@linaro.org>
 *
 * Based on ideas from Andrew Morton, David Rientjes, KOSAKI Motohiro,
 * Leonid Moiseichuk, Mel Gorman, Minchan Kim and Pekka Enberg.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include <linux/cgroup.h>
#include <linux/fs.h>
#include <linux/log2.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/eventfd.h>
#include <linux/swap.h>
#include <linux/printk.h>
#include <linux/notifier.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmpressure.h>

static const unsigned long vmpressure_win = SWAP_CLUSTER_MAX * 16;

static const unsigned int vmpressure_level_med = 60;
static const unsigned int vmpressure_level_critical = 95;

static unsigned long vmpressure_scale_max = 100;
module_param_named(vmpressure_scale_max, vmpressure_scale_max,
			ulong, S_IRUGO | S_IWUSR);

static unsigned long allocstall_threshold = 70;
module_param_named(allocstall_threshold, allocstall_threshold,
			ulong, S_IRUGO | S_IWUSR);

static struct vmpressure global_vmpressure;
BLOCKING_NOTIFIER_HEAD(vmpressure_notifier);

int vmpressure_notifier_register(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&vmpressure_notifier, nb);
}

int vmpressure_notifier_unregister(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&vmpressure_notifier, nb);
}

void vmpressure_notify(unsigned long pressure)
{
	blocking_notifier_call_chain(&vmpressure_notifier, pressure, NULL);
}

static const unsigned int vmpressure_level_critical_prio = ilog2(100 / 10);

static struct vmpressure *work_to_vmpressure(struct work_struct *work)
{
	return container_of(work, struct vmpressure, work);
}

#ifdef CONFIG_MEMCG
static struct vmpressure *cg_to_vmpressure(struct cgroup *cg)
{
	return css_to_vmpressure(cgroup_subsys_state(cg, mem_cgroup_subsys_id));
}

static struct vmpressure *vmpressure_parent(struct vmpressure *vmpr)
{
	struct cgroup *cg = vmpressure_to_css(vmpr)->cgroup;
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cg);

	memcg = parent_mem_cgroup(memcg);
	if (!memcg)
		return NULL;
	return memcg_to_vmpressure(memcg);
}
#else
static struct vmpressure *cg_to_vmpressure(struct cgroup *cg)
{
	return NULL;
}

static struct vmpressure *vmpressure_parent(struct vmpressure *vmpr)
{
	return NULL;
}
#endif

enum vmpressure_levels {
	VMPRESSURE_LOW = 0,
	VMPRESSURE_MEDIUM,
	VMPRESSURE_CRITICAL,
	VMPRESSURE_NUM_LEVELS,
};

static const char * const vmpressure_str_levels[] = {
	[VMPRESSURE_LOW] = "low",
	[VMPRESSURE_MEDIUM] = "medium",
	[VMPRESSURE_CRITICAL] = "critical",
};

static enum vmpressure_levels vmpressure_level(unsigned long pressure)
{
	if (pressure >= vmpressure_level_critical)
		return VMPRESSURE_CRITICAL;
	else if (pressure >= vmpressure_level_med)
		return VMPRESSURE_MEDIUM;
	return VMPRESSURE_LOW;
}

static unsigned long vmpressure_calc_pressure(unsigned long scanned,
						    unsigned long reclaimed)
{
	unsigned long scale = scanned + reclaimed;
	unsigned long pressure;

	pressure = scale - (reclaimed * scale / scanned);
	pressure = pressure * 100 / scale;

	pr_debug("%s: %3lu  (s: %lu  r: %lu)\n", __func__, pressure,
		 scanned, reclaimed);

	return pressure;
}

static unsigned long vmpressure_account_stall(unsigned long pressure,
				unsigned long stall, unsigned long scanned)
{
	unsigned long scale;

	if (pressure < allocstall_threshold)
		return pressure;

	scale = ((vmpressure_scale_max - pressure) * stall) / scanned;

	return pressure + scale;
}

struct vmpressure_event {
	struct eventfd_ctx *efd;
	enum vmpressure_levels level;
	struct list_head node;
};

static bool vmpressure_event(struct vmpressure *vmpr,
			     unsigned long scanned, unsigned long reclaimed)
{
	struct vmpressure_event *ev;
	enum vmpressure_levels level;
	unsigned long pressure;
	bool signalled = false;

	pressure = vmpressure_calc_pressure(scanned, reclaimed);
	level = vmpressure_level(pressure);

	mutex_lock(&vmpr->events_lock);

	list_for_each_entry(ev, &vmpr->events, node) {
		if (level >= ev->level) {
			eventfd_signal(ev->efd, 1);
			signalled = true;
		}
	}

	mutex_unlock(&vmpr->events_lock);

	return signalled;
}

static void vmpressure_work_fn(struct work_struct *work)
{
	struct vmpressure *vmpr = work_to_vmpressure(work);
	unsigned long scanned;
	unsigned long reclaimed;

	if (!vmpr->scanned)
		return;

	mutex_lock(&vmpr->sr_lock);
	scanned = vmpr->scanned;
	reclaimed = vmpr->reclaimed;
	vmpr->scanned = 0;
	vmpr->reclaimed = 0;
	mutex_unlock(&vmpr->sr_lock);

	do {
		if (vmpressure_event(vmpr, scanned, reclaimed))
			break;
	} while ((vmpr = vmpressure_parent(vmpr)));
}

void vmpressure_memcg(gfp_t gfp, struct mem_cgroup *memcg,
		unsigned long scanned, unsigned long reclaimed)
{
	struct vmpressure *vmpr = memcg_to_vmpressure(memcg);

	BUG_ON(!vmpr);

	if (!(gfp & (__GFP_HIGHMEM | __GFP_MOVABLE | __GFP_IO | __GFP_FS)))
		return;

	if (!scanned)
		return;

	mutex_lock(&vmpr->sr_lock);
	vmpr->scanned += scanned;
	vmpr->reclaimed += reclaimed;
	scanned = vmpr->scanned;
	mutex_unlock(&vmpr->sr_lock);

	if (scanned < vmpressure_win || work_pending(&vmpr->work))
		return;
	schedule_work(&vmpr->work);
}

void vmpressure_global(gfp_t gfp, unsigned long scanned,
		unsigned long reclaimed)
{
	struct vmpressure *vmpr = &global_vmpressure;
	unsigned long pressure;
	unsigned long stall;

	if (!(gfp & (__GFP_HIGHMEM | __GFP_MOVABLE | __GFP_IO | __GFP_FS)))
		return;

	if (!scanned)
		return;

	mutex_lock(&vmpr->sr_lock);
	vmpr->scanned += scanned;
	vmpr->reclaimed += reclaimed;

	if (!current_is_kswapd())
		vmpr->stall += scanned;

	stall = vmpr->stall;
	scanned = vmpr->scanned;
	reclaimed = vmpr->reclaimed;
	mutex_unlock(&vmpr->sr_lock);

	if (scanned < vmpressure_win)
		return;

	mutex_lock(&vmpr->sr_lock);
	vmpr->scanned = 0;
	vmpr->reclaimed = 0;
	mutex_unlock(&vmpr->sr_lock);

	pressure = vmpressure_calc_pressure(scanned, reclaimed);
	vmpr->stall = 0;
	mutex_unlock(&vmpr->sr_lock);

	pressure = vmpressure_calc_pressure(scanned, reclaimed);
	pressure = vmpressure_account_stall(pressure, stall, scanned);
	vmpressure_notify(pressure);
}

void vmpressure(gfp_t gfp, struct mem_cgroup *memcg,
		unsigned long scanned, unsigned long reclaimed)
{
	if (!memcg)
		vmpressure_global(gfp, scanned, reclaimed);

	if (IS_ENABLED(CONFIG_MEMCG))
		vmpressure_memcg(gfp, memcg, scanned, reclaimed);
}

void vmpressure_prio(gfp_t gfp, struct mem_cgroup *memcg, int prio)
{
	if (prio > vmpressure_level_critical_prio)
		return;

	vmpressure(gfp, memcg, vmpressure_win, 0);
}

int vmpressure_register_event(struct cgroup *cg, struct cftype *cft,
			      struct eventfd_ctx *eventfd, const char *args)
{
	struct vmpressure *vmpr = cg_to_vmpressure(cg);
	struct vmpressure_event *ev;
	int level;

	BUG_ON(!vmpr);

	for (level = 0; level < VMPRESSURE_NUM_LEVELS; level++) {
		if (!strcmp(vmpressure_str_levels[level], args))
			break;
	}

	if (level >= VMPRESSURE_NUM_LEVELS)
		return -EINVAL;

	ev = kzalloc(sizeof(*ev), GFP_KERNEL);
	if (!ev)
		return -ENOMEM;

	ev->efd = eventfd;
	ev->level = level;

	mutex_lock(&vmpr->events_lock);
	list_add(&ev->node, &vmpr->events);
	mutex_unlock(&vmpr->events_lock);

	return 0;
}

void vmpressure_unregister_event(struct cgroup *cg, struct cftype *cft,
				 struct eventfd_ctx *eventfd)
{
	struct vmpressure *vmpr = cg_to_vmpressure(cg);
	struct vmpressure_event *ev;

	if (!vmpr)
		BUG();

	mutex_lock(&vmpr->events_lock);
	list_for_each_entry(ev, &vmpr->events, node) {
		if (ev->efd != eventfd)
			continue;
		list_del(&ev->node);
		kfree(ev);
		break;
	}
	mutex_unlock(&vmpr->events_lock);
}

void vmpressure_init(struct vmpressure *vmpr)
{
	mutex_init(&vmpr->sr_lock);
	mutex_init(&vmpr->events_lock);
	INIT_LIST_HEAD(&vmpr->events);
	INIT_WORK(&vmpr->work, vmpressure_work_fn);
}

int vmpressure_global_init(void)
{
	vmpressure_init(&global_vmpressure);
	return 0;
}
late_initcall(vmpressure_global_init);
