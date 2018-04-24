/*
 * Copyright (C) 2011 HTC, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <htc/devices_dtb.h>
#include <linux/platform_device.h>

#define PDATA_NOT_DEFINED(field) \
    printk(KERN_INFO "[USB] %s: %s isnt defined\n", __func__, field);

static int use_mfg_serialno;
static int manual_serialno_flag = 0;
static char mfg_df_serialno[256];
unsigned int usb_project_pid;
static int usb_disable;

void htc_setprop(char *func)
{
	int	call_us_ret = -1;

	char *envp[] = {
		"HOME=/",
		"PATH=/sbin:/system/sbin:/system/bin:/system/xbin",
		NULL,
	};
	char *exec_path[1] = {"/system/bin/setprop"};
	char *argv_setprop[] = { exec_path[0], "sys.usb.config", func, NULL,};
	call_us_ret = call_usermodehelper(exec_path[0],
				argv_setprop, envp, UMH_WAIT_PROC);
}
static void setup_usb_denied(int htc_mode)
{
	USB_INFO("%s: htc_mode = %d\n", __func__, htc_mode);
	if (htc_mode)
		_android_dev->autobot_mode = 1;
	else
		_android_dev->autobot_mode = 0;
}

static int usb_autobot_mode(void)
{
	if (_android_dev->autobot_mode)
		return 1;
	else
		return 0;
}

void android_switch_htc_mode(void)
{
	htc_usb_enable_function("adb,mass_storage,serial,projector", 1);
}

int htc_usb_enable_function(char *name, int ebl)
{
	struct android_dev *dev = _android_dev;
	struct usb_composite_dev *cdev = dev->cdev;
	char state_buf[60];
	char name_buf[60];
	char *function[3];
	if (!strcmp(name, "ffs"))
		snprintf(state_buf, sizeof(state_buf), "SWITCH_STATE=%s", "adb");
	else
		snprintf(state_buf, sizeof(state_buf), "SWITCH_STATE=%s", name);
	function[0] = state_buf;
	function[2] = NULL;

	if (ebl) {
		snprintf(name_buf, sizeof(name_buf),
				"SWITCH_NAME=%s", "function_switch_on");
		function[1] = name_buf;
		kobject_uevent_env(&cdev->sw_function_switch_on.dev->kobj, KOBJ_CHANGE,
				function);
	} else {
		snprintf(name_buf, sizeof(name_buf),
				"SWITCH_NAME=%s", "function_switch_off");
		function[1] = name_buf;
		kobject_uevent_env(&cdev->sw_function_switch_off.dev->kobj, KOBJ_CHANGE,
				function);
	}
	return 0;

}

const char * change_charging_to_ums(const char *buff) {
	USB_INFO("switch ums function from %s\n", buff);
	if (!strcmp(buff, "charging"))
		return "mass_storage";
	else if (!strcmp(buff, "adb"))
		return "mass_storage,adb";
	else if (!strcmp(buff, "ffs"))
		return "mass_storage,ffs";
	return buff;
}

void change_charging_pid_to_ums(struct usb_composite_dev *cdev) {
	switch(cdev->desc.idProduct) {
		case 0x0f0b:
			cdev->desc.idVendor = 0x0bb4;
			cdev->desc.idProduct = 0x0ff9;
			break;
		case 0x0c81:
			cdev->desc.idVendor = 0x0bb4;
			cdev->desc.idProduct = 0x0f86;
			break;
		default:
			break;
	}
	return;
}

const char * add_usb_radio_debug_function(const char *buff) {
	USB_INFO("switch to radio debug function from %s\n", buff);

	if (!strcmp(buff, "mtp,adb,mass_storage")) 
		return "adb,diag,modem,rmnet";
	else if (!strcmp(buff, "mtp,adb,mass_storage,acm")) 
		return "adb,diag,modem,rmnet";
	else if (!strcmp(buff, "mtp,mass_storage")) 
		return "mass_storage,diag,modem,rmnet";
	else if (!strcmp(buff, "mtp,mass_storage,acm")) 
		return "mass_storage,diag,modem,rmnet";
	else if (!strcmp(buff, "ffs,acm")) 
		return "adb,diag,modem,acm";
	else if (!strcmp(buff, "mtp,adb,mass_storage,diag,modem,rmnet")) 
		return "adb,diag,modem,rmnet";
	
	else if (!strcmp(buff, "mtp,adb")) 
		return "adb,diag,modem,rmnet";
	else if (!strcmp(buff, "mass_storage,adb")) 
		return "mass_storage,adb,diag,modem,rmnet";
	else if (!strcmp(buff, "mass_storage")) 
		return "mass_storage,diag,modem,rmnet";
	else if (!strcmp(buff, "rndis")) 
		return "rndis,diag,modem";
	else if (!strcmp(buff, "rndis,adb")) 
		return "rndis,adb,diag,modem";
	
	printk(KERN_INFO " switch to original function:%s\n", buff);
	return buff;
}

void check_usb_vid_pid(struct usb_composite_dev *cdev) {
	switch(cdev->desc.idProduct) {
		
		case 0x0ffe:
			cdev->desc.idVendor = 0x0bb4;
			cdev->desc.idProduct = 0x0f82;
			break;
		case 0x0ffc:
			cdev->desc.idVendor = 0x0bb4;
			cdev->desc.idProduct = 0x0f83;
			break;
		case 0x0ff9:
			cdev->desc.idVendor = 0x0bb4;
			cdev->desc.idProduct = 0x0fd9;
			break;
		case 0x0f86:
			cdev->desc.idVendor = 0x0bb4;
			cdev->desc.idProduct = 0x0fd8;
			break;
		case 0x0f87:
		
		case 0x0f90:
		case 0x0fa2:
		case 0x0f63:
			cdev->desc.idVendor = 0x0bb4;
			cdev->desc.idProduct = 0x0f24;
			break;
		case 0x0f25:
		case 0x0f26:
		case 0x0f91:
		case 0x0fa3:
		case 0x0f64:
			cdev->desc.idVendor = 0x0bb4;
			cdev->desc.idProduct = 0x0fd9;
			break;
		case 0x0f15:
			cdev->desc.idVendor = 0x0bb4;
			cdev->desc.idProduct = 0x0f17;
		default:
			break;
	}
	return;
}
static ssize_t show_usb_disable_setting(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned length;

	length = sprintf(buf, "%d\n", usb_disable);
	return length;
}

void msm_otg_set_disable_usb(int disable_usb_function);
static ssize_t store_usb_disable_setting(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int disable_usb_function;
	ssize_t  ret;

	ret = kstrtouint(buf, 2, &disable_usb_function);
	if (ret < 0) {
		printk(KERN_ERR "[USB] %s: %zu\n", __func__, ret);
		return count;
	}
	printk(KERN_INFO "USB_disable set %d\n", disable_usb_function);
	usb_disable = disable_usb_function;
	msm_otg_set_disable_usb(disable_usb_function);
	return count;
}
static const char *os_to_string(int os_type)
{
	switch (os_type) {
	case OS_NOT_YET:	return "OS_NOT_YET";
	case OS_MAC:		return "OS_MAC";
	case OS_LINUX:		return "OS_LINUX";
	case OS_WINDOWS:	return "OS_WINDOWS";
	default:		return "UNKNOWN";
	}
}
static ssize_t show_os_type(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned length;

	length = sprintf(buf, "%d\n", os_type);
	USB_INFO("%s: %s, %s", __func__, os_to_string(os_type), buf);
	return length;
}

static ssize_t store_ats(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	sscanf(buf, "%d ", &usb_ats);
	return count;
}

static ssize_t show_ats(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned length;

	length = sprintf(buf, "%d\n", (get_debug_flag() & 0x100) || usb_ats);
	USB_INFO("%s: %s\n", __func__, buf);
	return length;
}

static ssize_t show_is_usb_denied(struct device *dev,
                struct device_attribute *attr, char *buf)
{
        unsigned length;
        int deny = 0;

        if (usb_autobot_mode()) {
                deny = 1;
        }

        length = sprintf(buf, "%d\n", deny);
        return length;
}

static ssize_t show_usb_ac_cable_status(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned length;
	length = sprintf(buf, "%d",cable_get_connect_type());
	return length;
}

static ssize_t show_usb_cable_connect(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned length;
	struct android_dev *and_dev = _android_dev;

	length = sprintf(buf, "%d",(and_dev->connected == 1) && !usb_disable ? 1 : 0);
	return length;
}

static ssize_t store_usb_modem_enable_setting(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count) {
	int usb_modem_enable;
	sscanf(buf, "%d ", &usb_modem_enable);

	USB_INFO("modem: enable %d\n", usb_modem_enable);
	htc_usb_enable_function("modem", usb_modem_enable?1:0);
	return count;
}

void android_set_serialno(char *serialno)
{
	strings_dev[STRING_SERIAL_IDX].s = serialno;
}

int cable_get_usb_id_level(void); 
void mfg_check_white_line(void)
{
	struct android_dev *dev = _android_dev;
	struct android_usb_platform_data *pdata = dev->pdata;
	int mode,id_level;
	char *serialno;

	mode = board_mfg_mode();
	id_level = cable_get_usb_id_level();

	printk("[USB] mfg mode %d , id level = %d, mfg flag %d,manual flag %d\n",
					mode, id_level, use_mfg_serialno, manual_serialno_flag);

	if (manual_serialno_flag)
		return;

	if (mode == MFG_MODE_FACTORY2) {
		if (cable_get_usb_id_level() == 1)
			serialno = "000000000000";
		else if(cable_get_usb_id_level() == 0)
			serialno = "000000000003";
		strncpy(mfg_df_serialno, serialno, strlen(serialno));
		android_set_serialno(mfg_df_serialno);
		use_mfg_serialno = 1;
	}
	else
		android_set_serialno(pdata->serial_number);
}

void check_usb_project_pid(struct usb_composite_dev *cdev) {
	if (cdev->desc.idProduct == 0x0f90 && usb_project_pid != 0x0000) {
		cdev->desc.idVendor = 0x0bb4;
		cdev->desc.idProduct = usb_project_pid;
	}
	return;
}

static int __init get_usb_project_pid(char *str) 
{
	int ret = kstrtouint(str, 0, &usb_project_pid);
	USB_INFO("androidusb.pid %d: %08x from %26s\r\n",
			ret, usb_project_pid, str);
	return ret;
} early_param("androidusb.pid", get_usb_project_pid);

static ssize_t show_dummy_usb_serial_number(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	unsigned length = 0;
	struct android_usb_platform_data *pdata =
		dev->platform_data != NULL ? dev->platform_data : _android_dev->pdata;

	if (use_mfg_serialno)
		length = sprintf(buf, "%s", mfg_df_serialno); 
	else if (pdata)
		length = sprintf(buf, "%s", pdata->serial_number); 
	else
		PDATA_NOT_DEFINED("serial number");
	return length;
}
static ssize_t store_dummy_usb_serial_number(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct android_dev *android_dev = _android_dev;
	struct usb_composite_dev *cdev = android_dev->cdev;

	int data_buff_size = (sizeof(mfg_df_serialno) > strlen(buf))?
		strlen(buf):sizeof(mfg_df_serialno);
	int loop_i;

	if(!use_mfg_serialno)
		return count;

	
	if (data_buff_size == 16)
		data_buff_size--;

	for (loop_i = 0; loop_i < data_buff_size; loop_i++)     {
		if (buf[loop_i] >= 0x30 && buf[loop_i] <= 0x39) 
			continue;
		else if (buf[loop_i] >= 0x41 && buf[loop_i] <= 0x5A) 
			continue;
		if (buf[loop_i] == 0x0A) 
			continue;
		else {
			printk(KERN_INFO "%s(): get invaild char (0x%2.2X)\n",
					__func__, buf[loop_i]);
			return -EINVAL;
		}
	}

	memset(mfg_df_serialno, 0x0, sizeof(mfg_df_serialno));
	strncpy(mfg_df_serialno, buf, data_buff_size);
	android_set_serialno(mfg_df_serialno);
	
	if (android_dev->connected) {
		manual_serialno_flag = 1;
		schedule_delayed_work(&cdev->request_reset, REQUEST_RESET_DELAYED);
	}

	return count;
}
static DEVICE_ATTR(usb_modem_enable, 0660,NULL, store_usb_modem_enable_setting);

static DEVICE_ATTR(usb_disable, 0664,show_usb_disable_setting, store_usb_disable_setting);
static DEVICE_ATTR(usb_ac_cable_status, 0444, show_usb_ac_cable_status, NULL);
static DEVICE_ATTR(dummy_usb_serial_number, 0644, show_dummy_usb_serial_number, store_dummy_usb_serial_number);
static DEVICE_ATTR(os_type, 0444, show_os_type, NULL);
static DEVICE_ATTR(ats, 0664, show_ats, store_ats);
static DEVICE_ATTR(usb_denied, 0444, show_is_usb_denied, NULL);
static DEVICE_ATTR(usb_cable_connect, 0444, show_usb_cable_connect, NULL);

static __maybe_unused struct attribute *android_htc_usb_attributes[] = {
	&dev_attr_usb_ac_cable_status.attr,
	&dev_attr_dummy_usb_serial_number.attr,
	&dev_attr_os_type.attr,
	&dev_attr_usb_disable.attr,
	&dev_attr_ats.attr,
	&dev_attr_usb_denied.attr,
	&dev_attr_usb_cable_connect.attr,
	&dev_attr_usb_modem_enable.attr,
	NULL
};

static  __maybe_unused const struct attribute_group android_usb_attr_group = {
	.attrs = android_htc_usb_attributes,
};

static void setup_vendor_info(struct android_dev *dev)
{
	if (sysfs_create_group(&dev->pdev->dev.kobj, &android_usb_attr_group))
		pr_err("%s: fail to create sysfs\n", __func__);
	
	if (sysfs_create_link(&platform_bus.kobj, &dev->pdev->dev.kobj, "android_usb"))
		pr_err("%s: fail to link android_usb to /sys/devices/platform/\n", __func__);
}
