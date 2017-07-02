#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <asm/debug_display.h>
#include "../../../drivers/video/msm/mdss/mdss_dsi.h"
#include <linux/device.h>
#include <linux/i2c.h>
#include <linux/delay.h>

/* HTC: dsi_power_data overwrite the role of dsi_drv_cm_data
   in mdss_dsi_ctrl_pdata structure */
struct dsi_power_data {
	uint32_t sysrev;         /* system revision info */
	int lcm_ld0_1v8_en;
	int lcmp5v;					/* TPS65132 */
	int lcmn5v;					/* TPS65132 */
};

static int lv52130_status = 0;
static struct i2c_adapter	*i2c_bus_adapter = NULL;

struct i2c_dev_info {
	uint8_t				dev_addr;
	struct i2c_client	*client;
};

#define I2C_DEV_INFO(addr) \
	{.dev_addr = addr >> 1, .client = NULL}

static struct i2c_dev_info device_addresses[] = {
	I2C_DEV_INFO(0x7C)
};

static const struct i2c_device_id lv52130_tx_id[] = {
	{"lv52130", 0},
	{ }
};

static struct of_device_id LV_match_table[] = {
	{.compatible = "disp-lv52130",}
};

static ssize_t lv52130_status_show(struct class *class,
      struct class_attribute *attr, char *buffer)
{
		return scnprintf(buffer, PAGE_SIZE, "%d\n", lv52130_status);
}

static struct class_attribute lv52130_attribute[] = {
      __ATTR(power_ic, S_IRUGO, lv52130_status_show, NULL),
       __ATTR_NULL,
};

static struct class lv52130_class = {
       .name           = "display",
       .class_attrs       = lv52130_attribute,
};


static inline int platform_write_i2c_block(struct i2c_adapter *i2c_bus
								, u8 page
								, u8 offset
								, u16 count
								, u8 *values
								)
{
		struct i2c_msg msg;
		u8 *buffer;
		int ret;

		buffer = kmalloc(count + 1, GFP_KERNEL);
		if (!buffer) {
			printk("%s:%d buffer allocation failed\n",__FUNCTION__,__LINE__);
			return -ENOMEM;
		}

		buffer[0] = offset;
		memmove(&buffer[1], values, count);

		msg.flags = 0;
		msg.addr = page >> 1;
		msg.buf = buffer;
		msg.len = count + 1;

		ret = i2c_transfer(i2c_bus, &msg, 1);

		kfree(buffer);

		if (ret != 1) {
			printk("%s:%d I2c write failed 0x%02x:0x%02x, error %d\n"
					,__FUNCTION__,__LINE__, page, offset, ret);
			ret = 0;
		}

		return ret;
}

static int lv52130_add_i2c(struct i2c_client *client)
{
		struct i2c_adapter *adapter = client->adapter;
		int idx;

		/* "Hotplug" the MHL transmitter device onto the 2nd I2C bus  for BB-xM or 4th for pandaboard*/
		i2c_bus_adapter = adapter;
		if (i2c_bus_adapter == NULL) {
			PR_DISP_ERR("%s() failed to get i2c adapter\n", __func__);
			return ENODEV;
		}
			PR_DISP_ERR("%s() get i2c adapter\n", __func__);

		for (idx = 0; idx < ARRAY_SIZE(device_addresses); idx++) {
			if(idx == 0)
				device_addresses[idx].client = client;
			else {
				device_addresses[idx].client = i2c_new_dummy(i2c_bus_adapter,
												device_addresses[idx].dev_addr);
				if (device_addresses[idx].client == NULL){
					return ENODEV;
				}
			}
		}

		return 0;
}


void lv52130_tx_status(struct device *dev)
{
	u8 data = 0x00;
	bool panel_on;
	int lcmp5v, lcmn5v;

	lcmp5v = of_get_named_gpio(dev->of_node,"htc,lcm_p5v-gpio", 0);
	lcmn5v = of_get_named_gpio(dev->of_node,"htc,lcm_n5v-gpio", 0);

	panel_on = (gpio_get_value(lcmp5v) || gpio_get_value(lcmn5v));
	if(!panel_on)
		gpio_set_value(lcmp5v, 1);

	data = 0x0F;
	lv52130_status = platform_write_i2c_block(i2c_bus_adapter, 0x7C, 0x00, 1, &data);

	if(!panel_on)
		gpio_set_value(lcmp5v, 0);
	return;
};

static int lv52130_tx_i2c_probe(struct i2c_client *client,
					      const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	int ret;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA)) {
		pr_err("[DISP] %s: Failed to i2c_check_functionality \n", __func__);
		return -EIO;
	}


	if (!client->dev.of_node) {
		pr_err("[DISP] %s: client->dev.of_node = NULL\n", __func__);
		return -ENOMEM;
	}

	ret = lv52130_add_i2c(client);

	if(ret < 0) {
		pr_err("[DISP] %s: Failed to lv_52130_add_i2c, ret=%d\n", __func__,ret);
		return ret;
	}
	lv52130_tx_status(&client->dev);
	class_register(&lv52130_class);

	return 0;
}

static struct i2c_driver lv52130_tx_i2c_driver = {
	.driver = {
		.name = "lv52130",
		.of_match_table = LV_match_table,
		},
	.id_table = lv52130_tx_id,
	.probe = lv52130_tx_i2c_probe,
	.command = NULL,
};



static int htc_a32_regulator_init(struct platform_device *pdev)
{
	int ret = 0;
	struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	struct dsi_power_data *pwrdata = NULL;
	PR_DISP_INFO("%s\n", __func__);
	if (!pdev) {
		PR_DISP_ERR("%s: invalid input\n", __func__);
		return -EINVAL;
	}

	ctrl_pdata = platform_get_drvdata(pdev);
	if (!ctrl_pdata) {
		PR_DISP_ERR("%s: invalid driver data\n", __func__);
		return -EINVAL;
	}

	pwrdata = devm_kzalloc(&pdev->dev,
				sizeof(struct dsi_power_data), GFP_KERNEL);
	if (!pwrdata) {
		PR_DISP_ERR("%s: FAILED to alloc pwrdata\n", __func__);
		return -ENOMEM;
	}

	ctrl_pdata->dsi_pwrctrl_data = pwrdata;


	pwrdata->lcmp5v = of_get_named_gpio(pdev->dev.of_node,
						"htc,lcm_p5v-gpio", 0);
	pwrdata->lcmn5v = of_get_named_gpio(pdev->dev.of_node,
						"htc,lcm_n5v-gpio", 0);

	pwrdata->lcm_ld0_1v8_en = of_get_named_gpio(pdev->dev.of_node,
						"htc,lcm_ld0_1v8_en-gpio", 0);

	return ret;
}

static int htc_a32_regulator_deinit(struct platform_device *pdev)
{
	class_unregister(&lv52130_class);
	/* devm_regulator() will automatically free regulators
	   while dev detach. */
	/* nothing */
	return 0;
}

void htc_a32_panel_reset(struct mdss_panel_data *pdata, int enable)
{
	struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	struct dsi_power_data *pwrdata = NULL;
	u8 avdd_level = 0;

	if (pdata == NULL) {
		PR_DISP_ERR("%s: Invalid input data\n", __func__);
		return;
	}

	ctrl_pdata = container_of(pdata, struct mdss_dsi_ctrl_pdata,
				panel_data);
	pwrdata = ctrl_pdata->dsi_pwrctrl_data;

	if (!gpio_is_valid(ctrl_pdata->rst_gpio)) {
		PR_DISP_DEBUG("%s:%d, reset line not configured\n",
			   __func__, __LINE__);
		return;
	}

	PR_DISP_INFO("%s: enable = %d\n", __func__, enable);

	if (enable) {
		if (pdata->panel_info.first_power_on == 1) {
			PR_DISP_INFO("reset already on in first time\n");
			return;
		}
		usleep_range(1000, 1200);
		gpio_set_value(ctrl_pdata->rst_gpio, 1);
		usleep_range(5000, 5500);

		gpio_set_value(pwrdata->lcmp5v, 1);
		usleep_range(10000, 10500);
		gpio_set_value(pwrdata->lcmn5v, 1);
		msleep(3);
		/*enable +-5v*/
		avdd_level = 0x0F;
		platform_write_i2c_block(i2c_bus_adapter,0x7C,0x00, 0x01, &avdd_level);
		platform_write_i2c_block(i2c_bus_adapter,0x7C,0x01, 0x01, &avdd_level);
		msleep(15);
	} else {
		gpio_set_value((ctrl_pdata->rst_gpio), 0);
		usleep_range(5000, 5500);
		gpio_set_value(pwrdata->lcmn5v, 0);
		usleep_range(10000, 10500);
		gpio_set_value(pwrdata->lcmp5v, 0);
		usleep_range(10000, 10500);
		gpio_set_value(pwrdata->lcm_ld0_1v8_en, 0);
	}
	PR_DISP_INFO("%s: enable = %d done\n", __func__, enable);
}

static int htc_a32_panel_power_on(struct mdss_panel_data *pdata, int enable)
{
	int ret = 0;

	struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	struct dsi_power_data *pwrdata = NULL;

	PR_DISP_INFO("%s: en=%d\n", __func__, enable);
	if (pdata == NULL) {
		PR_DISP_ERR("%s: Invalid input data\n", __func__);
		return -EINVAL;
	}

	ctrl_pdata = container_of(pdata, struct mdss_dsi_ctrl_pdata,
				panel_data);
	pwrdata = ctrl_pdata->dsi_pwrctrl_data;

	if (!pwrdata) {
		PR_DISP_ERR("%s: pwrdata not initialized\n", __func__);
		return -EINVAL;
	}

	if (enable) {

		if (!gpio_is_valid(pwrdata->lcm_ld0_1v8_en)) {
					pr_debug("%s:%d, lcm_ld0_1v8_en line not configured\n",
					__func__, __LINE__);
					return -EINVAL;
				}
		gpio_set_value(pwrdata->lcm_ld0_1v8_en, 1);
		usleep_range(1000,1500);
	}

	PR_DISP_INFO("%s: en=%d done\n", __func__, enable);

	return ret;
}

static struct mdss_dsi_pwrctrl dsi_pwrctrl = {
	.dsi_regulator_init = htc_a32_regulator_init,
	.dsi_regulator_deinit = htc_a32_regulator_deinit,
	.dsi_power_on = htc_a32_panel_power_on,
	.dsi_panel_reset = htc_a32_panel_reset,
};

static struct platform_device dsi_pwrctrl_device = {
	.name          = "mdss_dsi_pwrctrl",
	.id            = -1,
	.dev.platform_data = &dsi_pwrctrl,
};

int __init htc_8916_dsi_panel_power_register(void)
{

	int ret= 0;

	ret = platform_device_register(&dsi_pwrctrl_device);
	if (ret) {
		pr_err("[DISP] %s: dsi_pwrctrl_device register failed! ret =%x\n",__func__, ret);
		return ret;
	}

	ret = i2c_add_driver(&lv52130_tx_i2c_driver);
	if (ret < 0) {
		pr_err("[DISP] %s: FAILED to add i2c_add_driver ret=%x\n",
			__func__, ret);
		return ret;
	}

	return 0;

}
arch_initcall(htc_8916_dsi_panel_power_register);

