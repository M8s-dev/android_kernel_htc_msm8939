/* Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
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
#include "msm_sensor.h"
#include "msm_sensor_driver.h"
#include "msm_cci.h"
#include "msm_camera_io_util.h"

#define S5K5E2_SENSOR_NAME "s5k5e2_front"
#define PLATFORM_DRIVER_NAME "msm_camera_s5k5e2_front"
#define s5k5e_obj s5k5e2_##obj

DEFINE_MSM_MUTEX(s5k5e2_mut);

static struct msm_sensor_ctrl_t s5k5e2_s_ctrl;

#define CONFIG_MSMB_CAMERA_DEBUG
#undef CDBG
#ifdef CONFIG_MSMB_CAMERA_DEBUG
#define CDBG(fmt, args...) pr_err("[CAM]"fmt, ##args)
#else
#define CDBG(fmt, args...) do { } while (0)
#endif

static struct msm_sensor_power_setting s5k5e2_power_setting[] = {
  {
		.seq_type = SENSOR_CLK,
		.seq_val = SENSOR_CAM_MCLK,
		.config_val = 23880000,
		.delay = 5,
	},
    {
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VIO,
		.config_val = 1,
		.delay = 1,
	},
	{
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VANA,
		.config_val = 1,
		.delay = 1,
	},
	/*{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_STANDBY,
		.config_val = GPIO_OUT_LOW,//mipi_sel:main as 0.
		.delay = 1,
	},*/
	{
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VDIG,
		.config_val = 1,
		.delay = 1,
	},
	{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_RESET,
		.config_val = GPIO_OUT_HIGH,//GPIO_OUT_LOW,
		.delay = 1,
	},
	{
		.seq_type = SENSOR_I2C_MUX,
		.seq_val = 0,
		.config_val = 1,
		.delay = 0,
	},
};


static struct msm_sensor_power_setting s5k5e2_power_down_setting[] = {
  {
		.seq_type = SENSOR_I2C_MUX,
		.seq_val = 0,
		.config_val = 0,
		.delay = 0,
	},
	{
		.seq_type = SENSOR_GPIO,
		.seq_val = SENSOR_GPIO_RESET,
		.config_val = GPIO_OUT_LOW,//GPIO_OUT_LOW,
		.delay = 1,
	},
	{
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VDIG,
		.config_val = 0,
		.delay = 1,
	},
	{
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VANA,
		.config_val = 0,
		.delay = 1,
	},
	{
		.seq_type = SENSOR_VREG,
		.seq_val = CAM_VIO,
		.config_val = 0,
		.delay = 1,
	},
	{
		.seq_type = SENSOR_CLK,
		.seq_val = SENSOR_CAM_MCLK,
		.config_val = 23880000,
		.delay = 5,
	},
};


static struct v4l2_subdev_info s5k5e2_subdev_info[] = {
	{
		.code   = V4L2_MBUS_FMT_SBGGR10_1X10,
		.colorspace = V4L2_COLORSPACE_JPEG,
		.fmt    = 1,
		.order    = 0,
	},
};

static const struct i2c_device_id s5k5e2_i2c_id[] = {
	{S5K5E2_SENSOR_NAME, (kernel_ulong_t)&s5k5e2_s_ctrl},
	{ }
};

static int32_t msm_s5k5e2_i2c_probe(struct i2c_client *client,
	const struct i2c_device_id *id)
{
	return msm_sensor_i2c_probe(client, id, &s5k5e2_s_ctrl);
}

static struct msm_camera_i2c_client s5k5e2_sensor_i2c_client = {
	.addr_type = MSM_CAMERA_I2C_WORD_ADDR,
};

static const struct of_device_id s5k5e2_dt_match[] = {
	{.compatible = "htc,s5k5e2", .data = &s5k5e2_s_ctrl},
	{}
};


static struct i2c_driver s5k5e2_i2c_driver = {
	.id_table = s5k5e2_i2c_id,
	.probe  = msm_s5k5e2_i2c_probe,
	.driver = {
		.name = S5K5E2_SENSOR_NAME,
	},
};

MODULE_DEVICE_TABLE(of, s5k5e2_dt_match);

static struct platform_driver s5k5e2_platform_driver = {
	.driver = {
		.name = "htc,s5k5e2",
		.owner = THIS_MODULE,
		.of_match_table = s5k5e2_dt_match,
	},
};

static const char *s5k5e2Vendor = "Samsung";
static const char *s5k5e2NAME = "s5k5e2";
static const char *s5k5e2Size = "5.0M";

static ssize_t sensor_vendor_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t ret = 0;

	sprintf(buf, "%s %s %s\n", s5k5e2Vendor, s5k5e2NAME, s5k5e2Size);
	ret = strlen(buf) + 1;

	return ret;
}

static DEVICE_ATTR(sensor, 0444, sensor_vendor_show, NULL);

static struct kobject *android_s5k5e2;

static int s5k5e2_sysfs_init(void)
{
	int ret ;
	pr_info("s5k5e2:kobject creat and add\n");
	android_s5k5e2 = kobject_create_and_add("android_camera2", NULL);
	if (android_s5k5e2 == NULL) {
		pr_info("s5k5e2_sysfs_init: subsystem_register " \
		"failed\n");
		ret = -ENOMEM;
		return ret ;
	}
	pr_info("s5k5e2:sysfs_create_file\n");
	ret = sysfs_create_file(android_s5k5e2, &dev_attr_sensor.attr);
	if (ret) {
		pr_info("s5k5e2_sysfs_init: sysfs_create_file " \
		"failed\n");
		kobject_del(android_s5k5e2);
	}

	return 0 ;
}

static int32_t s5k5e2_platform_probe(struct platform_device *pdev)
{
	int32_t rc = 0;
	const struct of_device_id *match;
	match = of_match_device(s5k5e2_dt_match, &pdev->dev);

	/* HTC_START , add to fix Klocwork issue */
	if (match == NULL) {
		pr_err("%s: match is NULL\n", __func__);
		return -ENODEV;
	}
	/* HTC_END */

	rc = msm_sensor_platform_probe(pdev, match->data);
	return rc;
}

static int __init s5k5e2_init_module(void)
{
	int32_t rc = 0;
	pr_info("%s:%d\n", __func__, __LINE__);
	rc = platform_driver_probe(&s5k5e2_platform_driver,
		s5k5e2_platform_probe);
	if (!rc) {
		s5k5e2_sysfs_init();
		return rc;
	}
	pr_err("%s:%d rc %d\n", __func__, __LINE__, rc);
	return i2c_add_driver(&s5k5e2_i2c_driver);
}

static void __exit s5k5e2_exit_module(void)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	if (s5k5e2_s_ctrl.pdev) {
		msm_sensor_free_sensor_data(&s5k5e2_s_ctrl);
		platform_driver_unregister(&s5k5e2_platform_driver);
	} else
		i2c_del_driver(&s5k5e2_i2c_driver);
	return;
}

static int s5k5e2_read_fuseid(struct sensorb_cfg_data *cdata,
	struct msm_sensor_ctrl_t *s_ctrl)
{
	int32_t rc = 0;
	int i,j;
	uint16_t read_data = 0;
	uint16_t id_addr[6] = {0x0A04,0x0A05,0x0A06,0x0A07,0x0A08,0x0A09};
	static uint16_t id_data[6] = {0,0,0,0,0,0};
	static int first = true;
	static int32_t valid_page=-1;

	pr_info("%s called\n", __func__);
	if(first){
		first = false;
		for(j=4;j>=2;j--){
				rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write(s_ctrl->sensor_i2c_client, 0x0A00, 0x04, MSM_CAMERA_I2C_BYTE_DATA);
				if (rc < 0)
					pr_err("%s: i2c_write failed\n", __func__);
				rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write(s_ctrl->sensor_i2c_client, 0x0A02, j, MSM_CAMERA_I2C_BYTE_DATA);
				if (rc < 0)
					pr_info("%s: i2c_write failed\n", __func__);
				rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write(s_ctrl->sensor_i2c_client, 0x0A00, 0x01, MSM_CAMERA_I2C_BYTE_DATA);
				if (rc < 0)
					pr_info("%s: i2c_write failed\n", __func__);
				msleep(10);
				for (i=0; i<6; i++) {
					rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_read(s_ctrl->sensor_i2c_client, id_addr[i], &read_data, MSM_CAMERA_I2C_BYTE_DATA);

					if (rc < 0)
						pr_err("%s: i2c_read 0x%x failed\n", __func__, i);

					id_data[i] = read_data & 0xff;
				}
				if (read_data)
					valid_page = j;
				if (valid_page!=-1)
					break;
		}
	}
	rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write(s_ctrl->sensor_i2c_client, 0x0A00, 0x04, MSM_CAMERA_I2C_BYTE_DATA);
	if (rc < 0)
		pr_err("%s: i2c_write failed\n", __func__);
	rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write(s_ctrl->sensor_i2c_client, 0x0A00, 0x00, MSM_CAMERA_I2C_BYTE_DATA);
	if (rc < 0)
		pr_err("%s: i2c_write failed\n", __func__);
	if (cdata != NULL)
        {
	cdata->cfg.fuse.fuse_id_word1 = 0;
	cdata->cfg.fuse.fuse_id_word2 = id_data[3];
	cdata->cfg.fuse.fuse_id_word3 = id_data[4];
	cdata->cfg.fuse.fuse_id_word4 = id_data[5];

	pr_info("s5k5e2: fuse->fuse_id : 0x%x 0x%x 0x%x 0x%x\n",
		cdata->cfg.fuse.fuse_id_word1,
		cdata->cfg.fuse.fuse_id_word2,
		cdata->cfg.fuse.fuse_id_word3,
		cdata->cfg.fuse.fuse_id_word4);
	}
	else
	{
	pr_info("s5k5e2: first fuse->fuse_id : 0x%x 0x%x 0x%x 0x%x\n",
		0,
		id_data[3],
		id_data[4],
		id_data[5]);
	}
	pr_info("%s: OTP Module vendor = 0x%x\n", __func__,id_data[0]);
	pr_info("%s: OTP LENS = 0x%x\n",          __func__,id_data[1]);
	pr_info("%s: OTP Sensor Version = 0x%x\n",__func__,id_data[2]);

	return rc;
}

static int s5k5e2_read_fuseid32(struct sensorb_cfg_data32 *cdata,
	struct msm_sensor_ctrl_t *s_ctrl)
{
	int32_t rc = 0;
	int i,j;
	uint16_t read_data = 0;
	uint16_t id_addr[6] = {0x0A04,0x0A05,0x0A06,0x0A07,0x0A08,0x0A09};
	static uint16_t id_data[6] = {0,0,0,0,0,0};
	static int first = true;
	static int32_t valid_page=-1;

	pr_info("%s called\n", __func__);
	if(first){
		first = false;
		for(j=4;j>=2;j--){
				rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write(s_ctrl->sensor_i2c_client, 0x0A00, 0x04, MSM_CAMERA_I2C_BYTE_DATA);
				if (rc < 0)
					pr_err("%s: i2c_write failed\n", __func__);
				rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write(s_ctrl->sensor_i2c_client, 0x0A02, j, MSM_CAMERA_I2C_BYTE_DATA);
				if (rc < 0)
					pr_info("%s: i2c_write failed\n", __func__);
				rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write(s_ctrl->sensor_i2c_client, 0x0A00, 0x01, MSM_CAMERA_I2C_BYTE_DATA);
				if (rc < 0)
					pr_info("%s: i2c_write failed\n", __func__);
				msleep(10);
				for (i=0; i<6; i++) {
					rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_read(s_ctrl->sensor_i2c_client, id_addr[i], &read_data, MSM_CAMERA_I2C_BYTE_DATA);

					if (rc < 0)
						pr_err("%s: i2c_read 0x%x failed\n", __func__, i);

					id_data[i] = read_data & 0xff;
				}
				if (read_data)
					valid_page = j;
				if (valid_page!=-1)
					break;
		}
	}
	rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write(s_ctrl->sensor_i2c_client, 0x0A00, 0x04, MSM_CAMERA_I2C_BYTE_DATA);
	if (rc < 0)
		pr_err("%s: i2c_write failed\n", __func__);
	rc = s_ctrl->sensor_i2c_client->i2c_func_tbl->i2c_write(s_ctrl->sensor_i2c_client, 0x0A00, 0x00, MSM_CAMERA_I2C_BYTE_DATA);
	if (rc < 0)
		pr_err("%s: i2c_write failed\n", __func__);
	if (cdata != NULL)
        {
	cdata->cfg.fuse.fuse_id_word1 = 0;
	cdata->cfg.fuse.fuse_id_word2 = id_data[3];
	cdata->cfg.fuse.fuse_id_word3 = id_data[4];
	cdata->cfg.fuse.fuse_id_word4 = id_data[5];

	pr_info("s5k5e2: fuse->fuse_id : 0x%x 0x%x 0x%x 0x%x\n",
		cdata->cfg.fuse.fuse_id_word1,
		cdata->cfg.fuse.fuse_id_word2,
		cdata->cfg.fuse.fuse_id_word3,
		cdata->cfg.fuse.fuse_id_word4);
	}
	else
	{
	pr_info("s5k5e2: first fuse->fuse_id : 0x%x 0x%x 0x%x 0x%x\n",
		0,
		id_data[3],
		id_data[4],
		id_data[5]);
	}
	pr_info("%s: OTP Module vendor = 0x%x\n", __func__,id_data[0]);
	pr_info("%s: OTP LENS = 0x%x\n",          __func__,id_data[1]);
	pr_info("%s: OTP Sensor Version = 0x%x\n",__func__,id_data[2]);

	return rc;
}
//HTC_START , move read OTP to sensor probe
int32_t s5k5e2_sensor_match_id(struct msm_sensor_ctrl_t *s_ctrl)
{
	int32_t rc = 0;
	int32_t rc1 = 0;
	static int first = 0;
	rc = msm_sensor_match_id(s_ctrl);
	if(rc == 0) {
		if(first == 0) {
			pr_info("%s read_fuseid\n",__func__);
			#ifdef CONFIG_COMPAT
			rc1 = s5k5e2_read_fuseid32(NULL, s_ctrl);
			#else
			rc1 = s5k5e2_read_fuseid(NULL, s_ctrl);
			#endif
		}
	}
	first = 1;
	return rc;
}
//HTC_END
static struct msm_sensor_fn_t s5k5e2_sensor_func_tbl = {
	.sensor_power_up = msm_sensor_power_up,
	.sensor_power_down = msm_sensor_power_down,
	.sensor_match_id = s5k5e2_sensor_match_id,
	.sensor_config = msm_sensor_config,
	.sensor_config32 = msm_sensor_config32,
	.sensor_i2c_read_fuseid = s5k5e2_read_fuseid,
	.sensor_i2c_read_fuseid32 = s5k5e2_read_fuseid32
};

static struct msm_sensor_ctrl_t s5k5e2_s_ctrl = {
	.sensor_i2c_client = &s5k5e2_sensor_i2c_client,
	.power_setting_array.power_setting = s5k5e2_power_setting,
	.power_setting_array.size = ARRAY_SIZE(s5k5e2_power_setting),
	.power_setting_array.power_down_setting = s5k5e2_power_down_setting,//s5k5e2_power_down_setting,
	.power_setting_array.size_down = ARRAY_SIZE(s5k5e2_power_down_setting),
	.msm_sensor_mutex = &s5k5e2_mut,
	.sensor_v4l2_subdev_info = s5k5e2_subdev_info,
	.sensor_v4l2_subdev_info_size = ARRAY_SIZE(s5k5e2_subdev_info),
	.func_tbl = &s5k5e2_sensor_func_tbl
};

MODULE_DEVICE_TABLE(of, s5k5e2_dt_match);

module_init(s5k5e2_init_module);
module_exit(s5k5e2_exit_module);
MODULE_DESCRIPTION("s5k5e2");
MODULE_LICENSE("GPL v2");
