/* Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
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

#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "mdss_dsi.h"
#include "mdss_mdp.h"

static void mdss_report_panel_dead(struct dsi_status_data *pstatus_data)
{
	char *envp[2] = {"PANEL_ALIVE=0", NULL};
	struct mdss_panel_data *pdata =
		dev_get_platdata(&pstatus_data->mfd->pdev->dev);
	if (!pdata) {
		pr_err("%s: Panel data not available\n", __func__);
		return;
	}

	pdata->panel_info.panel_dead = true;
	kobject_uevent_env(&pstatus_data->mfd->fbi->dev->kobj,
		KOBJ_CHANGE, envp);
	pr_err("%s: Panel has gone bad, sending uevent - %s\n",
		__func__, envp[0]);
	return;
}

static void mdss_check_te_status(struct mdss_dsi_ctrl_pdata *ctrl_pdata,
		struct dsi_status_data *pstatus_data, uint32_t interval)
{
	if (!atomic_read(&ctrl_pdata->te_irq_ready)) {
		schedule_delayed_work(&pstatus_data->check_status,
			msecs_to_jiffies(interval));
		pr_debug("%s: TE IRQ line not enabled yet\n", __func__);
		return;
	}

	mdss_report_panel_dead(pstatus_data);
}

void mdss_check_dsi_ctrl_status(struct work_struct *work, uint32_t interval)
{
	struct dsi_status_data *pstatus_data = NULL;
	struct mdss_panel_data *pdata = NULL;
	struct mipi_panel_info *mipi = NULL;
	struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	struct mdss_overlay_private *mdp5_data = NULL;
	struct mdss_mdp_ctl *ctl = NULL;
	int ret = 0;

	pstatus_data = container_of(to_delayed_work(work),
		struct dsi_status_data, check_status);
	if (!pstatus_data || !(pstatus_data->mfd)) {
		pr_err("%s: mfd not available\n", __func__);
		return;
	}

	pdata = dev_get_platdata(&pstatus_data->mfd->pdev->dev);
	if (!pdata) {
		pr_err("%s: Panel data not available\n", __func__);
		return;
	}
	mipi = &pdata->panel_info.mipi;

	ctrl_pdata = container_of(pdata, struct mdss_dsi_ctrl_pdata,
							panel_data);
	if (!ctrl_pdata || (!ctrl_pdata->check_status &&
		(ctrl_pdata->status_mode != ESD_TE))) {
		pr_err("%s: DSI ctrl or status_check callback not available\n",
								__func__);
		return;
	}

	mdp5_data = mfd_to_mdp5_data(pstatus_data->mfd);
	ctl = mfd_to_ctl(pstatus_data->mfd);

	if (!ctl) {
		pr_err("%s: Display is off\n", __func__);
		return;
	}

	if (ctl->power_state == MDSS_PANEL_POWER_OFF) {
		schedule_delayed_work(&pstatus_data->check_status,
			msecs_to_jiffies(interval));
		pr_debug("%s: ctl not powered on\n", __func__);
		return;
	}

	if (ctrl_pdata->status_mode == ESD_TE) {
		mdss_check_te_status(ctrl_pdata, pstatus_data, interval);
		return;
	}



	mutex_lock(&ctl->offlock);
	if (mipi->mode == DSI_CMD_MODE)
		mutex_lock(&mdp5_data->ov_lock);

		if (mdss_panel_is_power_off(pstatus_data->mfd->panel_power_state) ||
			pstatus_data->mfd->shutdown_pending) {
		if (mipi->mode == DSI_CMD_MODE)
			mutex_unlock(&mdp5_data->ov_lock);
		mutex_unlock(&ctl->offlock);
		pr_err("%s: DSI turning off, avoiding panel status check\n",
							__func__);
		return;
	}

	if (ctl->wait_pingpong)
		ctl->wait_pingpong(ctl, NULL);

	pr_debug("%s: DSI ctrl wait for ping pong done\n", __func__);

	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_ON);
	ret = ctrl_pdata->check_status(ctrl_pdata);
	mdss_mdp_clk_ctrl(MDP_BLOCK_POWER_OFF);

	if (mipi->mode == DSI_CMD_MODE)
		mutex_unlock(&mdp5_data->ov_lock);
	mutex_unlock(&ctl->offlock);

	if ((pstatus_data->mfd->panel_power_state == MDSS_PANEL_POWER_ON)) {
		if (ret > 0)
			schedule_delayed_work(&pstatus_data->check_status,
				msecs_to_jiffies(interval));
		else
			mdss_report_panel_dead(pstatus_data);
	}
}
