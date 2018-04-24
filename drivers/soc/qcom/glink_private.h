/* Copyright (c) 2014-2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef _SOC_QCOM_GLINK_PRIVATE_H_
#define _SOC_QCOM_GLINK_PRIVATE_H_

#include <linux/ipc_logging.h>

#ifdef INIT_COMPLETION
#define reinit_completion(x) INIT_COMPLETION(*(x))
#endif 

enum {
	QCOM_GLINK_INFO = 1U << 0,
	QCOM_GLINK_DEBUG = 1U << 1,
	QCOM_GLINK_GPIO = 1U << 2,
	QCOM_GLINK_PERF = 1U << 3,
};

enum glink_dbgfs_ss {
	GLINK_DBGFS_MPSS,
	GLINK_DBGFS_APSS,
	GLINK_DBGFS_LPASS,
	GLINK_DBGFS_DSPS,
	GLINK_DBGFS_RPM,
	GLINK_DBGFS_WCNSS,
	GLINK_DBGFS_LLOOP,
	GLINK_DBGFS_MOCK,
	GLINK_DBGFS_MAX_NUM_SUBS
};

enum glink_dbgfs_xprt {
	GLINK_DBGFS_SMEM,
	GLINK_DBGFS_SMD,
	GLINK_DBGFS_XLLOOP,
	GLINK_DBGFS_XMOCK,
	GLINK_DBGFS_XMOCK_LOW,
	GLINK_DBGFS_XMOCK_HIGH,
	GLINK_DBGFS_MAX_NUM_XPRTS
};

struct glink_dbgfs {
	const char *curr_name;
	const char *par_name;
	bool b_dir_create;
};

struct glink_dbgfs_data {
	struct list_head flist;
	struct dentry *dent;
	void (*o_func)(struct seq_file *s);
	void *priv_data;
	bool b_priv_free_req;
};

struct xprt_ctx_iterator {
	struct list_head *xprt_list;
	struct glink_core_xprt_ctx *i_curr;
	unsigned long xprt_list_flags;
};

struct ch_ctx_iterator {
	struct list_head *ch_list;
	struct channel_ctx *i_curr;
	unsigned long ch_list_flags;
};

struct glink_ch_intent_info {
	spinlock_t *li_lst_lock;
	struct list_head *li_avail_list;
	struct list_head *li_used_list;
	spinlock_t *ri_lst_lock;
	struct list_head *ri_list;
};

struct glink_core_xprt_ctx;
struct channel_ctx;
enum transport_state_e;
enum local_channel_state_e;

enum glink_tracer_pkt_events {
	GLINK_CORE_TX = 1,
	GLINK_QUEUE_TO_SCHEDULER = 2,
	GLINK_SCHEDULER_TX = 3,
	GLINK_XPRT_TX = 4,
	GLINK_XPRT_RX = 5,
	GLINK_CORE_RX = 6,
};

const char *glink_get_ss_enum_string(unsigned int enum_id);

const char *glink_get_xprt_enum_string(unsigned int enum_id);

const char *glink_get_xprt_state_string(enum transport_state_e enum_id);

const char *glink_get_ch_state_string(enum local_channel_state_e enum_id);

#define GLINK_IPC_LOG_STR(x...) do { \
	if (glink_get_log_ctx()) \
		ipc_log_string(glink_get_log_ctx(), x); \
} while (0)

#define GLINK_DBG(x...) do {                              \
	if (glink_get_debug_mask() & QCOM_GLINK_DEBUG) \
			GLINK_IPC_LOG_STR(x);  \
} while (0)

#define GLINK_INFO(x...) do {                              \
	if (glink_get_debug_mask() & QCOM_GLINK_INFO) \
			GLINK_IPC_LOG_STR(x);  \
} while (0)

#define GLINK_INFO_PERF(x...) do {                              \
	if (glink_get_debug_mask() & (QCOM_GLINK_INFO | QCOM_GLINK_PERF)) \
			GLINK_IPC_LOG_STR(x);  \
} while (0)

#define GLINK_PERF(x...) do {                              \
	if (glink_get_debug_mask() & QCOM_GLINK_PERF) \
			GLINK_IPC_LOG_STR("<PERF> " x);  \
} while (0)

#define GLINK_UT_ERR(x...) do {                              \
	if (!(glink_get_debug_mask() & QCOM_GLINK_PERF)) \
		pr_err("<UT> " x); \
	GLINK_IPC_LOG_STR("<UT> " x);  \
} while (0)

#define GLINK_UT_DBG(x...) do {                              \
	if (glink_get_debug_mask() & QCOM_GLINK_DEBUG) \
			GLINK_IPC_LOG_STR("<UT> " x);  \
} while (0)

#define GLINK_UT_INFO(x...) do {                              \
	if (glink_get_debug_mask() & QCOM_GLINK_INFO) \
			GLINK_IPC_LOG_STR("<UT> " x);  \
} while (0)

#define GLINK_UT_INFO_PERF(x...) do {                              \
	if (glink_get_debug_mask() & (QCOM_GLINK_INFO | QCOM_GLINK_PERF)) \
			GLINK_IPC_LOG_STR("<UT> " x);  \
} while (0)

#define GLINK_UT_PERF(x...) do {                              \
	if (glink_get_debug_mask() & QCOM_GLINK_PERF) \
			GLINK_IPC_LOG_STR("<PERF> " x);  \
} while (0)

#define GLINK_PERF_XPRT(xprt, fmt, args...) do { \
	if (glink_get_debug_mask() & QCOM_GLINK_PERF) \
			GLINK_IPC_LOG_STR("<PERF> %s:%s " fmt, \
					xprt->name, xprt->edge, args);  \
} while (0)

#define GLINK_PERF_CH(ctx, fmt, args...) do { \
	if (glink_get_debug_mask() & QCOM_GLINK_PERF) \
			GLINK_IPC_LOG_STR("<PERF> %s:%s:%s[%u:%u] " fmt, \
					ctx->transport_ptr->name, \
					ctx->transport_ptr->edge, \
					ctx->name, \
					ctx->lcid, \
					ctx->rcid, args);  \
} while (0)

#define GLINK_PERF_CH_XPRT(ctx, xprt, fmt, args...) do { \
	if (glink_get_debug_mask() & QCOM_GLINK_PERF) \
			GLINK_IPC_LOG_STR("<PERF> %s:%s:%s[%u:%u] " fmt, \
					xprt->name, \
					xprt->edge, \
					ctx->name, \
					ctx->lcid, \
					ctx->rcid, args);  \
} while (0)

#define GLINK_INFO_PERF_XPRT(xprt, fmt, args...) do { \
	if (glink_get_debug_mask() & (QCOM_GLINK_INFO | QCOM_GLINK_PERF)) \
			GLINK_IPC_LOG_STR("<CORE> %s:%s " fmt, \
					xprt->name, xprt->edge, args);  \
} while (0)

#define GLINK_INFO_PERF_CH(ctx, fmt, args...) do { \
	if (glink_get_debug_mask() & (QCOM_GLINK_INFO | QCOM_GLINK_PERF)) \
			GLINK_IPC_LOG_STR("<CORE> %s:%s:%s[%u:%u] " fmt, \
					ctx->transport_ptr->name, \
					ctx->transport_ptr->edge, \
					ctx->name, \
					ctx->lcid, \
					ctx->rcid, args);  \
} while (0)

#define GLINK_INFO_PERF_CH_XPRT(ctx, xprt, fmt, args...) do { \
	if (glink_get_debug_mask() & (QCOM_GLINK_INFO | QCOM_GLINK_PERF)) \
			GLINK_IPC_LOG_STR("<CORE> %s:%s:%s[%u:%u] " fmt, \
					xprt->name, \
					xprt->edge, \
					ctx->name, \
					ctx->lcid, \
					ctx->rcid, args);  \
} while (0)

#define GLINK_INFO_XPRT(xprt, fmt, args...) do { \
	if (glink_get_debug_mask() & QCOM_GLINK_INFO) \
			GLINK_IPC_LOG_STR("<CORE> %s:%s " fmt, \
					xprt->name, xprt->edge, args);  \
} while (0)

#define GLINK_INFO_CH(ctx, fmt, args...) do { \
	if (glink_get_debug_mask() & QCOM_GLINK_INFO) \
			GLINK_IPC_LOG_STR("<CORE> %s:%s:%s[%u:%u] " fmt, \
					ctx->transport_ptr->name, \
					ctx->transport_ptr->edge, \
					ctx->name, \
					ctx->lcid, \
					ctx->rcid, args);  \
} while (0)

#define GLINK_INFO_CH_XPRT(ctx, xprt, fmt, args...) do { \
	if (glink_get_debug_mask() & QCOM_GLINK_INFO) \
			GLINK_IPC_LOG_STR("<CORE> %s:%s:%s[%u:%u] " fmt, \
					xprt->name, \
					xprt->edge, \
					ctx->name, \
					ctx->lcid, \
					ctx->rcid, args);  \
} while (0)

#define GLINK_DBG_XPRT(xprt, fmt, args...) do { \
	if (glink_get_debug_mask() & QCOM_GLINK_DEBUG) \
			GLINK_IPC_LOG_STR("<CORE> %s:%s " fmt, \
					xprt->name, xprt->edge, args);  \
} while (0)

#define GLINK_DBG_CH(ctx, fmt, args...) do { \
	if (glink_get_debug_mask() & QCOM_GLINK_DEBUG) \
			GLINK_IPC_LOG_STR("<CORE> %s:%s:%s[%u:%u] " fmt, \
					ctx->transport_ptr->name, \
					ctx->transport_ptr->edge, \
					ctx->name, \
					ctx->lcid, \
					ctx->rcid, args);  \
} while (0)

#define GLINK_DBG_CH_XPRT(ctx, xprt, fmt, args...) do { \
	if (glink_get_debug_mask() & QCOM_GLINK_DEBUG) \
			GLINK_IPC_LOG_STR("<CORE> %s:%s:%s[%u:%u] " fmt, \
					xprt->name, \
					xprt->edge, \
					ctx->name, \
					ctx->lcid, \
					ctx->rcid, args);  \
} while (0)

#define GLINK_ERR(x...) do {                              \
	pr_err("<CORE> " x); \
	GLINK_IPC_LOG_STR("<CORE> " x);  \
} while (0)

#define GLINK_ERR_XPRT(xprt, fmt, args...) do { \
	pr_err("<CORE> %s:%s " fmt, \
		xprt->name, xprt->edge, args);  \
	GLINK_INFO_XPRT(xprt, fmt, args); \
} while (0)

#define GLINK_ERR_CH(ctx, fmt, args...) do { \
	pr_err("<CORE> %s:%s:%s[%u:%u] " fmt, \
		ctx->transport_ptr->name, \
		ctx->transport_ptr->edge, \
		ctx->name, \
		ctx->lcid, \
		ctx->rcid, args);  \
	GLINK_INFO_CH(ctx, fmt, args); \
} while (0)

#define GLINK_ERR_CH_XPRT(ctx, xprt, fmt, args...) do { \
	pr_err("<CORE> %s:%s:%s[%u:%u] " fmt, \
		xprt->name, \
		xprt->edge, \
		ctx->name, \
		ctx->lcid, \
		ctx->rcid, args);  \
	GLINK_INFO_CH_XPRT(ctx, xprt, fmt, args); \
} while (0)

#define OVERFLOW_ADD_UNSIGNED(type, a, b) \
	(((type)~0 - (a)) < (b) ? true : false)

unsigned glink_get_debug_mask(void);

void *glink_get_log_ctx(void);

int glink_get_channel_id_for_handle(void *handle);

char *glink_get_channel_name_for_handle(void *handle);

int glink_debugfs_init(void);

void glink_debugfs_exit(void);

struct dentry *glink_debugfs_create(const char *name,
		void (*show)(struct seq_file *),
		struct glink_dbgfs *dir, void *dbgfs_data, bool b_free_req);

void glink_debugfs_remove_recur(struct glink_dbgfs *dfs);

void glink_debugfs_remove_channel(struct channel_ctx *ch_ctx,
			struct glink_core_xprt_ctx *xprt_ctx);

void glink_debugfs_add_channel(struct channel_ctx *ch_ctx,
		struct glink_core_xprt_ctx *xprt_ctx);

void glink_debugfs_add_xprt(struct glink_core_xprt_ctx *xprt_ctx);

void glink_xprt_ctx_iterator_init(struct xprt_ctx_iterator *xprt_i);

void glink_xprt_ctx_iterator_end(struct xprt_ctx_iterator *xprt_i);

struct glink_core_xprt_ctx *glink_xprt_ctx_iterator_next(
			struct xprt_ctx_iterator *xprt_i);

char  *glink_get_xprt_name(struct glink_core_xprt_ctx *xprt_ctx);

char *glink_get_xprt_edge_name(struct glink_core_xprt_ctx *xprt_ctx);

const char *glink_get_xprt_state(struct glink_core_xprt_ctx *xprt_ctx);

const struct glink_core_version *glink_get_xprt_version_features(
			struct glink_core_xprt_ctx *xprt_ctx);

void  glink_ch_ctx_iterator_init(struct ch_ctx_iterator *ch_iter,
			struct glink_core_xprt_ctx *xprt);

void glink_ch_ctx_iterator_end(struct ch_ctx_iterator *ch_iter,
				struct glink_core_xprt_ctx *xprt);

struct channel_ctx *glink_ch_ctx_iterator_next(struct ch_ctx_iterator *ch_iter);

char *glink_get_ch_name(struct channel_ctx *ch_ctx);

char *glink_get_ch_edge_name(struct channel_ctx *ch_ctx);

int glink_get_ch_lcid(struct channel_ctx *ch_ctx);

int glink_get_ch_rcid(struct channel_ctx *ch_ctx);

const char *glink_get_ch_lstate(struct channel_ctx *ch_ctx);

bool glink_get_ch_rstate(struct channel_ctx *ch_ctx);

char *glink_get_ch_xprt_name(struct channel_ctx *ch_ctx);

int glink_get_ch_tx_pkt_count(struct channel_ctx *ch_ctx);

int glink_get_ch_rx_pkt_count(struct channel_ctx *ch_ctx);

int glink_get_ch_lintents_queued(struct channel_ctx *ch_ctx);

int glink_get_ch_rintents_queued(struct channel_ctx *ch_ctx);

void glink_get_ch_intent_info(struct channel_ctx *ch_ctx,
			struct glink_ch_intent_info *ch_ctx_i);

enum ssr_command {
	GLINK_SSR_DO_CLEANUP,
	GLINK_SSR_CLEANUP_DONE,
};

struct subsys_info {
	const char *ssr_name;
	const char *edge;
	const char *xprt;
	void *handle;
	void *link_state_handle;
	struct glink_link_info *link_info;
	struct ssr_notify_data *cb_data;
	struct list_head subsystem_list_node;
	struct list_head notify_list;
	int notify_list_len;
	bool link_up;
	spinlock_t link_up_lock;
};

struct subsys_info_leaf {
	const char *ssr_name;
	const char *edge;
	const char *xprt;
	bool restarted;
	struct ssr_notify_data *cb_data;
	struct list_head notify_list_node;
};

struct do_cleanup_msg {
	uint32_t version;
	uint32_t command;
	uint32_t seq_num;
	uint32_t name_len;
	char name[32];
};

struct cleanup_done_msg {
	uint32_t version;
	uint32_t response;
	uint32_t seq_num;
};

struct ssr_notify_data {
	bool tx_done;
	unsigned event;
	bool responded;
	uint32_t version;
	uint32_t seq_num;
	const char *edge;
};

struct subsys_info *get_info_for_subsystem(const char *subsystem);

struct subsys_info *get_info_for_edge(const char *edge);

uint32_t glink_ssr_get_seq_num(void);

int glink_ssr(const char *subsystem);

int notify_for_subsystem(struct subsys_info *ss_info);

bool glink_ssr_wait_cleanup_done(unsigned ssr_timeout_multiplier);

struct channel_lcid {
	struct list_head list_node;
	uint32_t lcid;
};

struct rwref_lock {
	struct kref kref;
	unsigned read_count;
	unsigned write_count;
	spinlock_t lock;
	struct completion count_zero;

	void (*release)(struct rwref_lock *);
};

static inline void rwref_lock_release(struct kref *kref_ptr)
{
	struct rwref_lock *lock_ptr;

	BUG_ON(kref_ptr == NULL);

	lock_ptr = container_of(kref_ptr, struct rwref_lock, kref);
	if (lock_ptr->release)
		lock_ptr->release(lock_ptr);
}

static inline void rwref_lock_init(struct rwref_lock *lock_ptr,
		void (*release)(struct rwref_lock *))
{
	BUG_ON(lock_ptr == NULL);

	kref_init(&lock_ptr->kref);
	lock_ptr->read_count = 0;
	lock_ptr->write_count = 0;
	spin_lock_init(&lock_ptr->lock);
	init_completion(&lock_ptr->count_zero);
	lock_ptr->release = release;
}

static inline void rwref_get(struct rwref_lock *lock_ptr)
{
	BUG_ON(lock_ptr == NULL);

	kref_get(&lock_ptr->kref);
}

static inline void rwref_put(struct rwref_lock *lock_ptr)
{
	BUG_ON(lock_ptr == NULL);

	kref_put(&lock_ptr->kref, rwref_lock_release);
}

static inline void rwref_read_get(struct rwref_lock *lock_ptr)
{
	unsigned long flags;

	BUG_ON(lock_ptr == NULL);

	kref_get(&lock_ptr->kref);
	while (1) {
		spin_lock_irqsave(&lock_ptr->lock, flags);
		if (lock_ptr->write_count == 0) {
			lock_ptr->read_count++;
			spin_unlock_irqrestore(&lock_ptr->lock, flags);
			break;
		}
		spin_unlock_irqrestore(&lock_ptr->lock, flags);
		wait_for_completion(&lock_ptr->count_zero);
	}
}

static inline void rwref_read_put(struct rwref_lock *lock_ptr)
{
	unsigned long flags;

	BUG_ON(lock_ptr == NULL);

	spin_lock_irqsave(&lock_ptr->lock, flags);
	BUG_ON(lock_ptr->read_count == 0);
	if (--lock_ptr->read_count == 0)
		complete(&lock_ptr->count_zero);
	spin_unlock_irqrestore(&lock_ptr->lock, flags);
	kref_put(&lock_ptr->kref, rwref_lock_release);
}

static inline void rwref_write_get(struct rwref_lock *lock_ptr)
{
	unsigned long flags;

	BUG_ON(lock_ptr == NULL);

	kref_get(&lock_ptr->kref);
	while (1) {
		spin_lock_irqsave(&lock_ptr->lock, flags);
		if (lock_ptr->read_count == 0 && lock_ptr->write_count == 0) {
			lock_ptr->write_count++;
			spin_unlock_irqrestore(&lock_ptr->lock, flags);
			break;
		}
		spin_unlock_irqrestore(&lock_ptr->lock, flags);
		wait_for_completion(&lock_ptr->count_zero);
	}
}

static inline void rwref_write_put(struct rwref_lock *lock_ptr)
{
	unsigned long flags;

	BUG_ON(lock_ptr == NULL);

	spin_lock_irqsave(&lock_ptr->lock, flags);
	BUG_ON(lock_ptr->write_count != 1);
	if (--lock_ptr->write_count == 0)
		complete(&lock_ptr->count_zero);
	spin_unlock_irqrestore(&lock_ptr->lock, flags);
	kref_put(&lock_ptr->kref, rwref_lock_release);
}

#endif 
