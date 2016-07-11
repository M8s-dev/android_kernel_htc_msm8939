/* Copyright (c) 2002,2007-2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/slab.h>
#include <linux/msm_kgsl.h>
#include <linux/sched.h>
#include <linux/debugfs.h>

#include "kgsl.h"
#include "kgsl_sharedmem.h"
#include "adreno.h"
#include "adreno_trace.h"

#define KGSL_INIT_REFTIMESTAMP		0x7FFFFFFF

static void wait_callback(struct kgsl_device *device,
		struct kgsl_event_group *group, void *priv, int result)
{
	struct adreno_context *drawctxt = priv;
	wake_up_all(&drawctxt->waiting);
}

static int _check_context_timestamp(struct kgsl_device *device,
		struct adreno_context *drawctxt, unsigned int timestamp)
{
	int ret = 0;

	
	if (kgsl_context_detached(&drawctxt->base) ||
			kgsl_context_invalid(&drawctxt->base))
		return 1;

	mutex_lock(&device->mutex);
	ret = kgsl_check_timestamp(device, &drawctxt->base, timestamp);
	mutex_unlock(&device->mutex);

	return ret;
}

void adreno_drawctxt_dump(struct kgsl_device *device,
		struct kgsl_context *context)
{
	unsigned int queue, start, retire;
	struct adreno_context *drawctxt = ADRENO_CONTEXT(context);
	int index, pos;
	char buf[120];

	kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_QUEUED, &queue);
	kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_CONSUMED, &start);
	kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_RETIRED, &retire);

	spin_lock_bh(&drawctxt->lock);
	dev_err(device->dev,
		"  context[%d]: queue=%d, submit=%d, start=%d, retire=%d\n",
		context->id, queue, drawctxt->submitted_timestamp,
		start, retire);

	if (drawctxt->cmdqueue_head != drawctxt->cmdqueue_tail) {
		struct kgsl_cmdbatch *cmdbatch =
			drawctxt->cmdqueue[drawctxt->cmdqueue_head];

		if (test_bit(CMDBATCH_FLAG_FENCE_LOG, &cmdbatch->priv)) {
			dev_err(device->dev,
				"  possible deadlock. Context %d might be blocked for itself\n",
				context->id);
			goto stats;
		}

		spin_lock_bh(&cmdbatch->lock);

		if (!list_empty(&cmdbatch->synclist)) {
			dev_err(device->dev,
				"  context[%d] (ts=%d) Active sync points:\n",
				context->id, cmdbatch->timestamp);

			kgsl_dump_syncpoints(device, cmdbatch);
		}
		spin_unlock_bh(&cmdbatch->lock);
	}

stats:
	memset(buf, 0, sizeof(buf));

	pos = 0;

	for (index = 0; index < SUBMIT_RETIRE_TICKS_SIZE; index++) {
		uint64_t msecs;
		unsigned int usecs;

		if (!drawctxt->submit_retire_ticks[index])
			continue;
		msecs = drawctxt->submit_retire_ticks[index] * 10;
		usecs = do_div(msecs, 192);
		usecs = do_div(msecs, 1000);
		pos += snprintf(buf + pos, sizeof(buf) - pos, "%d.%0d ",
			(unsigned int)msecs, usecs);
	}
	dev_err(device->dev, "  context[%d]: submit times: %s\n",
		context->id, buf);

	spin_unlock_bh(&drawctxt->lock);
}

int adreno_drawctxt_wait(struct adreno_device *adreno_dev,
		struct kgsl_context *context,
		uint32_t timestamp, unsigned int timeout)
{
	struct kgsl_device *device = &adreno_dev->dev;
	struct adreno_context *drawctxt = ADRENO_CONTEXT(context);
	int ret;
	long ret_temp;

	if (kgsl_context_detached(context))
		return -ENOENT;

	if (kgsl_context_invalid(context))
		return -EDEADLK;

	
	BUG_ON(!mutex_is_locked(&device->mutex));

	trace_adreno_drawctxt_wait_start(-1, context->id, timestamp);

	ret = kgsl_add_event(device, &context->events, timestamp,
		wait_callback, (void *) drawctxt);
	if (ret)
		goto done;

	mutex_unlock(&device->mutex);

	if (timeout) {
		ret_temp = wait_event_interruptible_timeout(
			drawctxt->waiting,
			_check_context_timestamp(device, drawctxt, timestamp),
			msecs_to_jiffies(timeout));

		if (ret_temp == 0)
			ret = -ETIMEDOUT;
		else if (ret_temp > 0)
			ret = 0;
		else
			ret = (int) ret_temp;
	} else {
		ret = wait_event_interruptible(drawctxt->waiting,
			_check_context_timestamp(device, drawctxt, timestamp));
	}

	mutex_lock(&device->mutex);

	
	if (kgsl_context_invalid(context))
		ret = -EDEADLK;


	
	if (kgsl_context_detached(context))
		ret = -ENOENT;

done:
	trace_adreno_drawctxt_wait_done(-1, context->id, timestamp, ret);
	return ret;
}

static int adreno_drawctxt_wait_rb(struct adreno_device *adreno_dev,
		struct kgsl_context *context,
		uint32_t timestamp, unsigned int timeout)
{
	struct kgsl_device *device = &adreno_dev->dev;
	struct adreno_context *drawctxt = ADRENO_CONTEXT(context);
	int ret = 0;

	
	BUG_ON(!mutex_is_locked(&device->mutex));

	if (kgsl_context_invalid(context))
		goto done;

	trace_adreno_drawctxt_wait_start(drawctxt->rb->id, context->id,
					timestamp);

	ret = adreno_ringbuffer_waittimestamp(drawctxt->rb, timestamp, timeout);
done:
	trace_adreno_drawctxt_wait_done(drawctxt->rb->id, context->id,
					timestamp, ret);
	return ret;
}

void adreno_drawctxt_invalidate(struct kgsl_device *device,
		struct kgsl_context *context)
{
	struct adreno_context *drawctxt = ADRENO_CONTEXT(context);

	trace_adreno_drawctxt_invalidate(drawctxt);

	spin_lock(&drawctxt->lock);
	set_bit(KGSL_CONTEXT_PRIV_INVALID, &context->priv);

	kgsl_sharedmem_writel(device, &device->memstore,
			KGSL_MEMSTORE_OFFSET(context->id, soptimestamp),
			drawctxt->timestamp);

	kgsl_sharedmem_writel(device, &device->memstore,
			KGSL_MEMSTORE_OFFSET(context->id, eoptimestamp),
			drawctxt->timestamp);

	
	while (drawctxt->cmdqueue_head != drawctxt->cmdqueue_tail) {
		struct kgsl_cmdbatch *cmdbatch =
			drawctxt->cmdqueue[drawctxt->cmdqueue_head];

		drawctxt->cmdqueue_head = (drawctxt->cmdqueue_head + 1) %
			ADRENO_CONTEXT_CMDQUEUE_SIZE;

		kgsl_cancel_events_timestamp(device, &context->events,
			cmdbatch->timestamp);

		kgsl_cmdbatch_destroy(cmdbatch);
	}

	spin_unlock(&drawctxt->lock);

	
	kgsl_flush_event_group(device, &context->events);

	
	wake_up_all(&drawctxt->waiting);
	wake_up_all(&drawctxt->wq);
}

#define KGSL_CONTEXT_PRIORITY_MED	0x8

static inline void _set_context_priority(struct adreno_context *drawctxt)
{
	
	if ((drawctxt->base.flags & KGSL_CONTEXT_PRIORITY_MASK) ==
			KGSL_CONTEXT_PRIORITY_UNDEF)
		drawctxt->base.flags |= (KGSL_CONTEXT_PRIORITY_MED <<
				KGSL_CONTEXT_PRIORITY_SHIFT);

	
	drawctxt->base.priority =
		(drawctxt->base.flags & KGSL_CONTEXT_PRIORITY_MASK) >>
		KGSL_CONTEXT_PRIORITY_SHIFT;
}

struct kgsl_context *
adreno_drawctxt_create(struct kgsl_device_private *dev_priv,
			uint32_t *flags)
{
	struct adreno_context *drawctxt;
	struct kgsl_device *device = dev_priv->device;
	struct adreno_device *adreno_dev = ADRENO_DEVICE(device);
	int ret;
	unsigned long local;

	local = *flags & (KGSL_CONTEXT_PREAMBLE |
		KGSL_CONTEXT_NO_GMEM_ALLOC |
		KGSL_CONTEXT_PER_CONTEXT_TS |
		KGSL_CONTEXT_USER_GENERATED_TS |
		KGSL_CONTEXT_NO_FAULT_TOLERANCE |
		KGSL_CONTEXT_CTX_SWITCH |
		KGSL_CONTEXT_PRIORITY_MASK |
		KGSL_CONTEXT_TYPE_MASK |
		KGSL_CONTEXT_PWR_CONSTRAINT |
		KGSL_CONTEXT_IFH_NOP |
		KGSL_CONTEXT_SECURE);

	

	
	if ((local & KGSL_CONTEXT_PREAMBLE) == 0 ||
		(local & KGSL_CONTEXT_NO_GMEM_ALLOC) == 0) {
		KGSL_DEV_ERR_ONCE(device,
			"legacy context switch not supported\n");
		return ERR_PTR(-EINVAL);
	}

	
	if (!kgsl_mmu_is_secured(&dev_priv->device->mmu) &&
			(local & KGSL_CONTEXT_SECURE)) {
		KGSL_DEV_ERR_ONCE(device, "Secure context not supported\n");
		return ERR_PTR(-EINVAL);
	}

	drawctxt = kzalloc(sizeof(struct adreno_context), GFP_KERNEL);

	if (drawctxt == NULL)
		return ERR_PTR(-ENOMEM);

	ret = kgsl_context_init(dev_priv, &drawctxt->base);
	if (ret != 0) {
		kfree(drawctxt);
		return ERR_PTR(ret);
	}

	drawctxt->timestamp = 0;

	drawctxt->base.flags = local;

	
	drawctxt->base.flags |= KGSL_CONTEXT_PER_CONTEXT_TS;
	drawctxt->type = (drawctxt->base.flags & KGSL_CONTEXT_TYPE_MASK)
		>> KGSL_CONTEXT_TYPE_SHIFT;
	spin_lock_init(&drawctxt->lock);
	init_waitqueue_head(&drawctxt->wq);
	init_waitqueue_head(&drawctxt->waiting);

	
	_set_context_priority(drawctxt);
	
	drawctxt->rb = adreno_ctx_get_rb(adreno_dev, drawctxt);

	plist_node_init(&drawctxt->pending, drawctxt->base.priority);

	kgsl_sharedmem_writel(device, &device->memstore,
			KGSL_MEMSTORE_OFFSET(drawctxt->base.id, soptimestamp),
			0);
	kgsl_sharedmem_writel(device, &device->memstore,
			KGSL_MEMSTORE_OFFSET(drawctxt->base.id, eoptimestamp),
			0);

	adreno_context_debugfs_init(ADRENO_DEVICE(device), drawctxt);

	
	*flags = drawctxt->base.flags;
	return &drawctxt->base;
}

void adreno_drawctxt_sched(struct kgsl_device *device,
		struct kgsl_context *context)
{
	adreno_dispatcher_queue_context(device, ADRENO_CONTEXT(context));
}

void adreno_drawctxt_detach(struct kgsl_context *context)
{
	struct kgsl_device *device;
	struct adreno_device *adreno_dev;
	struct adreno_context *drawctxt;
	struct adreno_ringbuffer *rb;
	int ret;

	if (context == NULL)
		return;

	device = context->device;
	adreno_dev = ADRENO_DEVICE(device);
	drawctxt = ADRENO_CONTEXT(context);
	rb = drawctxt->rb;

	
	if (rb->drawctxt_active == drawctxt)
		adreno_drawctxt_switch(adreno_dev, rb, NULL, 0);

	spin_lock(&drawctxt->lock);

	while (drawctxt->cmdqueue_head != drawctxt->cmdqueue_tail) {
		struct kgsl_cmdbatch *cmdbatch =
			drawctxt->cmdqueue[drawctxt->cmdqueue_head];

		drawctxt->cmdqueue_head = (drawctxt->cmdqueue_head + 1) %
			ADRENO_CONTEXT_CMDQUEUE_SIZE;

		spin_unlock(&drawctxt->lock);

		adreno_fault_skipcmd_detached(device, drawctxt, cmdbatch);


		kgsl_cmdbatch_destroy(cmdbatch);
		spin_lock(&drawctxt->lock);
	}

	spin_unlock(&drawctxt->lock);
	BUG_ON(!mutex_is_locked(&device->mutex));

	ret = adreno_drawctxt_wait_rb(adreno_dev, context,
		drawctxt->internal_timestamp, 30 * 1000);

	BUG_ON(ret && ret != -EAGAIN);

	kgsl_sharedmem_writel(device, &device->memstore,
			KGSL_MEMSTORE_OFFSET(context->id, soptimestamp),
			drawctxt->timestamp);

	kgsl_sharedmem_writel(device, &device->memstore,
			KGSL_MEMSTORE_OFFSET(context->id, eoptimestamp),
			drawctxt->timestamp);

	adreno_profile_process_results(adreno_dev);

	
	wake_up_all(&drawctxt->waiting);
	wake_up_all(&drawctxt->wq);
}

void adreno_drawctxt_destroy(struct kgsl_context *context)
{
	struct adreno_context *drawctxt;
	if (context == NULL)
		return;

	drawctxt = ADRENO_CONTEXT(context);
	debugfs_remove_recursive(drawctxt->debug_root);
	kfree(drawctxt);
}

static void _adreno_context_restore_cpu(struct adreno_ringbuffer *rb,
				struct adreno_context *drawctxt)
{
	kgsl_sharedmem_writel(rb->device, &(rb->device->memstore),
			KGSL_MEMSTORE_RB_OFFSET(rb->device, current_context),
			drawctxt ? drawctxt->base.id : 0);
	kgsl_sharedmem_writel(rb->device, &(rb->device->memstore),
			KGSL_MEMSTORE_OFFSET(KGSL_MEMSTORE_GLOBAL,
						current_context),
			drawctxt ? drawctxt->base.id : 0);
}

static void adreno_context_restore(struct adreno_ringbuffer *rb)
{
	struct kgsl_device *device = rb->device;
	struct adreno_device *adreno_dev = ADRENO_DEVICE(device);
	struct adreno_context *drawctxt = rb->drawctxt_active;
	unsigned int cmds[11];
	int ret;

	if (!drawctxt)
		return;
	cmds[0] = cp_nop_packet(1);
	cmds[1] = KGSL_CONTEXT_TO_MEM_IDENTIFIER;
	cmds[2] = cp_type3_packet(CP_MEM_WRITE, 2);
	cmds[3] = device->memstore.gpuaddr +
		KGSL_MEMSTORE_RB_OFFSET(rb, current_context);
	cmds[4] = drawctxt->base.id;
	cmds[5] = cp_type3_packet(CP_MEM_WRITE, 2);
	cmds[6] = device->memstore.gpuaddr +
		KGSL_MEMSTORE_OFFSET(KGSL_MEMSTORE_GLOBAL,
					current_context);
	cmds[7] = drawctxt->base.id;
	
	cmds[8] = cp_type0_packet(
		adreno_getreg(adreno_dev, ADRENO_REG_UCHE_INVALIDATE0), 2);
	cmds[9] = 0;
	if (adreno_is_a4xx(adreno_dev))
		cmds[10] = 0x12;
	else if (adreno_is_a3xx(adreno_dev))
		cmds[10] = 0x90000000;
	ret = adreno_ringbuffer_issuecmds(rb, KGSL_CMD_FLAGS_NONE, cmds, 11);
	if (ret) {
		ret = adreno_idle(device);
		BUG_ON(ret);
		_adreno_context_restore_cpu(rb, drawctxt);
	}
}


int adreno_drawctxt_switch(struct adreno_device *adreno_dev,
				struct adreno_ringbuffer *rb,
				struct adreno_context *drawctxt,
				unsigned int flags)
{
	struct kgsl_device *device = &adreno_dev->dev;
	struct kgsl_pagetable *new_pt;
	int ret = 0;

	
	BUG_ON(!rb);

	
	if (rb->drawctxt_active == drawctxt)
		return ret;

	trace_adreno_drawctxt_switch(rb,
		drawctxt, flags);

	
	if (drawctxt) {
		if (!_kgsl_context_get(&drawctxt->base))
			return -ENOENT;

		new_pt = drawctxt->base.proc_priv->pagetable;
	} else {
		 
		new_pt = device->mmu.defaultpagetable;
	}
	ret = adreno_iommu_set_pt(rb, new_pt);
	if (ret) {
		KGSL_DRV_ERR(device,
			"Failed to set pagetable on rb %d\n", rb->id);
		return ret;
	}

	
	if (rb->drawctxt_active)
		kgsl_context_put(&rb->drawctxt_active->base);

	rb->drawctxt_active = drawctxt;
	
	adreno_context_restore(rb);

	return 0;
}
