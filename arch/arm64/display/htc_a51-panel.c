#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <asm/debug_display.h>
#include "../../../drivers/video/msm/mdss/mdss_dsi.h"

#define PANEL_ID_A51_JDI_NT35521_C3      1
#define PANEL_ID_A51_TRULY_NT35521	 2
#define PANEL_ID_A51_TRULY_HX8934D	 3
#define PANEL_ID_A51_TIANMA_HX8934D	 4
/* HTC: dsi_power_data overwrite the role of dsi_drv_cm_data
   in mdss_dsi_ctrl_pdata structure */
struct dsi_power_data {
	uint32_t sysrev;         /* system revision info */
	struct regulator *vddio; 	/* LCMIO 1.8v */
	int lcmp5v;
	int lcmn5v;
	int lcm_bl_en;
};
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
		printk("%s:%d I2c write failed 0x%02x:0x%02x\n"
				,__FUNCTION__,__LINE__, page, offset);
		ret = -EIO;
	} else {
		printk("%s:%d I2c write success 0x%02x:0x%02x\n"
				,__FUNCTION__,__LINE__, page, offset);
	}

	return ret;
}


static int tps_65132_add_i2c(struct i2c_client *client)
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


// static int __devinit tps_65132_tx_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
static int tps_65132_tx_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	int ret;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA)) {
		PR_DISP_ERR("%s: Failed to i2c_check_functionality \n", __func__);
		return -EIO;
	}


	if (!client->dev.of_node) {
		PR_DISP_ERR("%s: client->dev.of_node = NULL\n", __func__);
		return -ENOMEM;
	}

	ret = tps_65132_add_i2c(client);

	if(ret < 0) {
		PR_DISP_ERR("%s: Failed to tps_65132_add_i2c, ret=%d\n", __func__,ret);
		return ret;
	}
		PR_DISP_ERR("CONY %s: tps_65132_add_i2c, ret=%d\n", __func__,ret);

	return 0;
}


static const struct i2c_device_id tps_65132_tx_id[] = {
	{"tps65132_disp", 0}
};

static struct of_device_id TSP_match_table[] = {
	{.compatible = "disp-tps-65132",}
};

static struct i2c_driver tps_65132_tx_i2c_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "tps65132_disp",
		.of_match_table = TSP_match_table,
		},
	.id_table = tps_65132_tx_id,
	.probe = tps_65132_tx_i2c_probe,
	.command = NULL,
};

static int htc_a51_regulator_init(struct platform_device *pdev)
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

	//LCMIO NCP6924 L4 1v8
	pwrdata->vddio = regulator_get(NULL, "ncp6924_ldo4");
	if (IS_ERR(pwrdata->vddio)) {
		PR_DISP_ERR("%s: could not get vddio vreg, rc=%ld\n",
			__func__, PTR_ERR(pwrdata->vddio));
		return PTR_ERR(pwrdata->vddio);
	}

	ret = regulator_set_voltage(pwrdata->vddio, 1800000, 1800000);
	if (ret) {
		PR_DISP_ERR("%s: set voltage failed on vddio vreg, rc=%d\n",
		__func__, ret);
		return ret;
	}

	pwrdata->lcmp5v = of_get_named_gpio(pdev->dev.of_node,
						"htc,lcm_p5v-gpio", 0);
	pwrdata->lcmn5v = of_get_named_gpio(pdev->dev.of_node,
						"htc,lcm_n5v-gpio", 0);
	pwrdata->lcm_bl_en = of_get_named_gpio(pdev->dev.of_node,
						"htc,lcm_bl_en-gpio", 0);
	return 0;
}

static int htc_a51_regulator_deinit(struct platform_device *pdev)
{
	/* devm_regulator() will automatically free regulators
	   while dev detach. */
	/* nothing */
	return 0;
}
static inline bool htc_a51_novatek_panel_check(int panel_id)
{
	return ((panel_id == PANEL_ID_A51_JDI_NT35521_C3) ? true:
		(panel_id == PANEL_ID_A51_TRULY_NT35521)  ? true:
		false);
}

void htc_a51_panel_reset(struct mdss_panel_data *pdata, int enable)
{
	struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	struct dsi_power_data *pwrdata = NULL;

	if (pdata == NULL) {
		PR_DISP_ERR("%s: Invalid input data\n", __func__);
		return;
	}
	ctrl_pdata = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);
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
		if (gpio_request(ctrl_pdata->rst_gpio, "disp_rst_n")) {
			PR_DISP_ERR("%s: request reset gpio failed", __func__);
			return;
		}

		if (htc_a51_novatek_panel_check(pdata->panel_info.panel_id)) {
			/*just after lp11*/
			msleep(40);

			gpio_set_value((ctrl_pdata->rst_gpio), 1);
			usleep_range(1000,1500);
			gpio_set_value((ctrl_pdata->rst_gpio), 0);
			usleep_range(1000,1500);
			gpio_set_value((ctrl_pdata->rst_gpio), 1);
			usleep_range(20000,20500);
		} else {
			u8 avdd_level = 0;
			usleep_range(1000, 1200);
			gpio_set_value(ctrl_pdata->rst_gpio, 1);
			usleep_range(5000, 5500);
			gpio_set_value(pwrdata->lcmp5v, 1);
			usleep_range(10000, 10500);
			gpio_set_value(pwrdata->lcmn5v, 1);

			//enable +-5v
			avdd_level = 0x0F;
			platform_write_i2c_block(i2c_bus_adapter,0x7C,0x00, 0x01, &avdd_level);
			platform_write_i2c_block(i2c_bus_adapter,0x7C,0x01, 0x01, &avdd_level);

			msleep(150);
		}
	} else {
		usleep_range(2000,2500);
		gpio_set_value(ctrl_pdata->rst_gpio, 0);
		if (!htc_a51_novatek_panel_check(pdata->panel_info.panel_id)) {
			usleep_range(5000, 5500);
			gpio_set_value(pwrdata->lcmn5v, 0);
			usleep_range(10000,10500);
			gpio_set_value(pwrdata->lcmp5v, 0);
		}

		if (!pdata->panel_info.first_power_on)
			gpio_free(ctrl_pdata->rst_gpio);
	}

	PR_DISP_INFO("%s: enable = %d done\n", __func__, enable);
}
static void htc_a51_bkl_en(struct mdss_panel_data *pdata, int enable)
{
	static int en = 1;
	struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	struct dsi_power_data *pwrdata = NULL;

	if(en == enable)
		return;

	en = enable;
	PR_DISP_INFO("%s: en=%d\n", __func__, enable);

	if (pdata == NULL) {
		pr_err("%s: Invalid input data\n", __func__);
		return;
	}

	ctrl_pdata = container_of(pdata, struct mdss_dsi_ctrl_pdata,
								panel_data);
	pwrdata = ctrl_pdata->dsi_pwrctrl_data;

	if (enable) {
		gpio_set_value(pwrdata->lcm_bl_en, 1);
	} else {
		gpio_set_value(pwrdata->lcm_bl_en, 0);
	}
}
static int htc_a51_panel_power_on(struct mdss_panel_data *pdata, int enable)
{

	struct mdss_dsi_ctrl_pdata *ctrl_pdata = NULL;
	struct dsi_power_data *pwrdata = NULL;
	u8 avdd_level = 0x00;
	int ret = 0;

	PR_DISP_INFO("%s: en=%d\n", __func__, enable);
	if (pdata == NULL) {
		PR_DISP_ERR("%s: Invalid input data\n", __func__);
		return -EINVAL;
	}

	ctrl_pdata = container_of(pdata, struct mdss_dsi_ctrl_pdata, panel_data);
	pwrdata = ctrl_pdata->dsi_pwrctrl_data;

	if (!pwrdata) {
		PR_DISP_ERR("%s: pwrdata not initialized\n", __func__);
		return -EINVAL;
	}
	if (enable) {

		//enable vddio NCP6924 L4 1v8
		ret= regulator_enable(pwrdata->vddio);
		if (ret < 0) {
			PR_DISP_ERR("%s: regulator_enable(ncp) failed (%d)\n", __func__, ret);
			return ret;
		}

		usleep_range(1000,1500);
		if (htc_a51_novatek_panel_check(pdata->panel_info.panel_id)) {
			gpio_set_value(pwrdata->lcmp5v, 1);
			usleep_range(2000,2500);
			gpio_set_value(pwrdata->lcmn5v, 1);
			usleep_range(2000,2500);

			//enable +-5v
			avdd_level = 0x0F;
			platform_write_i2c_block(i2c_bus_adapter,0x7C,0x00, 0x01, &avdd_level);
			platform_write_i2c_block(i2c_bus_adapter,0x7C,0x01, 0x01, &avdd_level);

		}
	} else {
		usleep_range(2000,2500);
		if (htc_a51_novatek_panel_check(pdata->panel_info.panel_id)) {
			gpio_set_value(pwrdata->lcmn5v, 0);
			usleep_range(2000,2500);
			gpio_set_value(pwrdata->lcmp5v, 0);
			usleep_range(2000,2500);
		}

		//disable vddio ncp6924 L4 1v8
		ret= regulator_disable(pwrdata->vddio);
		if (ret) {
			PR_DISP_ERR("%s: Falied to disable vddio regulator. ret = %d \n", __func__, ret);
			return ret;
		}

	}
	PR_DISP_INFO("%s: en=%d done\n", __func__, enable);

	return 0;
}

static struct mdss_dsi_pwrctrl dsi_pwrctrl = {
	.dsi_regulator_init = htc_a51_regulator_init,
	.dsi_regulator_deinit = htc_a51_regulator_deinit,
	.dsi_power_on = htc_a51_panel_power_on,
	.dsi_panel_reset = htc_a51_panel_reset,
	.bkl_config = htc_a51_bkl_en,
};
static struct platform_device dsi_pwrctrl_device = {
	.name          = "mdss_dsi_pwrctrl",
	.id            = -1,
	.dev.platform_data = &dsi_pwrctrl,
};

int __init htc_8939_dsi_panel_power_register(void)
{
       int ret = 0;

       pr_err("[DISP]CONY %s: dsi_pwrctrl_device register!! ret =%x\n",__func__, ret);
       ret = platform_device_register(&dsi_pwrctrl_device);
       if (ret) {
               pr_err("[DISP] %s: dsi_pwrctrl_device register failed! ret =%x\n",__func__, ret);
               return ret;
       }
       ret = i2c_add_driver(&tps_65132_tx_i2c_driver);
       if (ret < 0) {
               pr_err("[DISP] %s: FAILED to add i2c_add_driver ret=%x\n",
                         __func__, ret);
		return ret;
	}
       return 0;
}
arch_initcall(htc_8939_dsi_panel_power_register);
