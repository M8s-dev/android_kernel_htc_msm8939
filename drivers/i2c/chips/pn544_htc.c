/******************************************************************************
 *
 *  This is the implementation file for the PN547 NFC customization Functions
 *
 ******************************************************************************/

#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/types.h>
#include "pn544_htc.h"

#if NFC_GET_BOOTMODE
#include <htc/devices_cmdline.h>
#endif //NFC_GET_BOOTMODE



#define D(x...)	\
	if (is_debug) \
		printk(KERN_DEBUG "[NFC] " x)
#define I(x...) printk(KERN_INFO "[NFC] " x)
#define E(x...) printk(KERN_ERR "[NFC] [Err] " x)


// for off mode charging ++
#if NFC_OFF_MODE_CHARGING_LOAD_SWITCH
static unsigned int   pvdd_gpio;
#endif //NFC_OFF_MODE_CHARGING_LOAD_SWITCH
// for off mode charging --


/******************************************************************************
 *
 *  Function pn544_htc_check_rfskuid:
 *  Return With(1)/Without(0) NFC chip if this SKU can get RFSKUID in kernal
 *  Return is_alive(original value) by default.
 *
 ******************************************************************************/
int pn544_htc_check_rfskuid(int in_is_alive){
	return in_is_alive;
}


/******************************************************************************
 *
 *  Function pn544_htc_get_bootmode:
 *  Return  NFC_BOOT_MODE_NORMAL            0
 *          NFC_BOOT_MODE_FTM               1
 *          NFC_BOOT_MODE_DOWNLOAD          2
 *          NFC_BOOT_MODE_OFF_MODE_CHARGING 5
 *  Return 	NFC_BOOT_MODE_NORMAL by default
 *          if there's no bootmode infomation available
 *
 *          Bootmode enum is defined in
 *          kernel/include/htc/devices_cmdline.h
 *  enum {
 *	MFG_MODE_NORMAL,
 *	MFG_MODE_FACTORY2,
 *	MFG_MODE_RECOVERY,
 *	MFG_MODE_CHARGE,
 *	MFG_MODE_POWER_TEST,
 *	MFG_MODE_OFFMODE_CHARGING,
 *	MFG_MODE_MFGKERNEL_DIAG58,
 *	MFG_MODE_GIFT_MODE,
 *	MFG_MODE_MFGKERNEL,
 *	MFG_MODE_MINI,
 *	};
 ******************************************************************************/
int pn544_htc_get_bootmode(void) {
	int bootmode = NFC_BOOT_MODE_NORMAL;
#if NFC_GET_BOOTMODE
	bootmode = board_mfg_mode();
	if (bootmode == MFG_MODE_OFFMODE_CHARGING) {
		I("%s: Check bootmode done NFC_BOOT_MODE_OFF_MODE_CHARGING\n",__func__);
		return NFC_BOOT_MODE_OFF_MODE_CHARGING;
	} else {
		I("%s: Check bootmode done NFC_BOOT_MODE_NORMAL mode = %d\n",__func__,bootmode);
		return NFC_BOOT_MODE_NORMAL;
	}
#else
	return bootmode;
#endif  //NFC_GET_BOOTMODE
}


/******************************************************************************
 *
 *  Function pn544_htc_get_bootmode:
 *  Get platform required GPIO number from device tree
 *  For Power off sequence and OFF_MODE_CHARGING
 *
 ******************************************************************************/
void pn544_htc_parse_dt(struct device *dev) {
#if NFC_OFF_MODE_CHARGING_LOAD_SWITCH
	struct device_node *dt = dev->of_node;
	pvdd_gpio = of_get_named_gpio_flags(dt, "nxp,pvdd-gpio",0, NULL);
	I("%s: pvdd_gpio:%d\n", __func__, pvdd_gpio);
#endif
}

/******************************************************************************
 *
 *  Function pn544_htc_off_mode_charging
 *  Turn of NFC_PVDD when bootmode = NFC_BOOT_MODE_OFF_MODE_CHARGING
 *
 ******************************************************************************/
void pn544_htc_off_mode_charging (void) {
#if NFC_OFF_MODE_CHARGING_LOAD_SWITCH
	I("%s: Turn off NFC_PVDD \n", __func__);
	gpio_set_value(pvdd_gpio, 0);
#endif
}
