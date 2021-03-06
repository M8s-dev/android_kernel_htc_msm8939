/* drivers/htc_sdservice/htc_sdservice.c
 *
 * Copyright (C) 2014 HTC Corporation.
 * Author: HTC
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
#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/compat.h>

#include <soc/qcom/scm.h>
#include <soc/qcom/smd.h>
#include "qseecom_kernel.h"

#define DEVICE_NAME "htc_sdservice"
/*
static char *appname = "htc_sdservice";
*/

#define HTC_SDKEY_LEN 32
#define HTC_IOCTL_SDSERVICE 0x9527
#define HTC_IOCTL_SEC_ATS_GET	0x9528
#define HTC_IOCTL_SEC_ATS_SET	0x9529

#define ITEM_SD_KEY_ENCRYPT     0x33
#define ITEM_SD_KEY_DECRYPT     0x34

#define TAG "[SEC] "
#define HTC_SDSERVICE_DEBUG	0
#undef PDEBUG
#if HTC_SDSERVICE_DEBUG
#define PDEBUG(fmt, args...) printk(KERN_INFO TAG "[K] %s(%i, %s): " fmt "\n", \
		__func__, current->pid, current->comm, ## args)
#else
#define PDEBUG(fmt, args...) do {} while (0)
#endif /* HTC_SDSERVICE_DEBUG */

#undef PERR
#define PERR(fmt, args...) printk(KERN_ERR TAG "[E] %s(%i, %s): " fmt "\n", \
		__func__, current->pid, current->comm, ## args)

#undef PINFO
#define PINFO(fmt, args...) printk(KERN_INFO TAG "[I] %s(%i, %s): " fmt "\n", \
		__func__, current->pid, current->comm, ## args)

static int htc_sdservice_major;
static struct class *htc_sdservice_class;
static const struct file_operations htc_sdservice_fops;

static unsigned char *htc_sdkey;

typedef struct _htc_sdservice_msg_s{
	int func;
	int offset;
	unsigned char *req_buf;
	int req_len;
	unsigned char *resp_buf;
	int resp_len;
} htc_sdservice_msg_s;

typedef struct _compat_htc_sdservice_msg_s{
	compat_int_t func;
	compat_int_t offset;
	compat_uptr_t req_buf;
	compat_int_t req_len;
	compat_uptr_t resp_buf;
	compat_int_t resp_len;
} compat_htc_sdservice_msg_t;

/* ATS structure, total size 6 * uint32 = 24 bytes */
typedef struct {
	struct {
		uint8_t func_id;
		uint8_t func_cur_state;
		int8_t  func_return;
		uint8_t func_exec;
	} func_info;
	uint32_t    input[2];
	uint32_t    output[2];
	uint8_t reserve[4];
} htc_sec_ats_t;

struct qsc_send_cmd {
    uint32_t cmd_id;
    uint32_t data;
    uint32_t data2;
    uint32_t len;
    uint32_t start_pkt;
    uint32_t end_pkt;
    uint32_t test_buf_size;
};

static long htc_sdservice_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	htc_sdservice_msg_s hmsg;
	htc_sec_ats_t amsg;
	int ret = 0;
    /*
    struct qseecom_handle *l_QSEEComHandle = NULL;
    struct qsc_send_cmd *send_cmd = NULL;
    void *resp = NULL;
    */

	PDEBUG("command = %x", command);
	switch (command) {
	case HTC_IOCTL_SDSERVICE:
		if (copy_from_user(&hmsg, (void __user *)arg, sizeof(hmsg))) {
			PERR("copy_from_user error (msg)");
			return -EFAULT;
		}
		PDEBUG("func = %x", hmsg.func);
		switch (hmsg.func) {
		case ITEM_SD_KEY_ENCRYPT:
			if ((hmsg.req_buf == NULL) || (hmsg.req_len != HTC_SDKEY_LEN)) {
				PERR("invalid arguments");
				return -EFAULT;
			}
			if (copy_from_user(htc_sdkey, (void __user *)hmsg.req_buf, hmsg.req_len)) {
				PERR("copy_from_user error (sdkey)");
				return -EFAULT;
			}
            /*
            ret = qseecom_start_app(&l_QSEEComHandle, appname, 1024);
            if (ret) {
                PERR("Start app: fail");
                return -1;
            } else {
                PDEBUG("Start app: pass");
            }
            if(l_QSEEComHandle == NULL) {
                PERR("Failed to get QSEECOM handle\n");
                return -1;
            }

            send_cmd = (struct qsc_send_cmd *)l_QSEEComHandle->sbuf;
            resp = (struct qsc_send_cmd *)((uintptr_t)(l_QSEEComHandle->sbuf) + l_QSEEComHandle->sbuf_len/2);
            memset(resp, 0, HTC_SDKEY_LEN);

            send_cmd->cmd_id = ITEM_SD_KEY_ENCRYPT;
            send_cmd->test_buf_size = HTC_SDKEY_LEN;
            memcpy((uint8_t *)send_cmd + sizeof(struct qsc_send_cmd), htc_sdkey, HTC_SDKEY_LEN);

            ret = qseecom_set_bandwidth(l_QSEEComHandle, true);
            if (ret) {
                PERR("qseecom_set_bandwidth fail(%d)", ret);
                return -1;
            }
            ret = qseecom_send_command(l_QSEEComHandle, send_cmd, HTC_SDKEY_LEN, resp, HTC_SDKEY_LEN);
            if (ret) {
                PERR("qseecom_send_cmd fail(%d)", ret);
                return -1;
            }
            ret = qseecom_set_bandwidth(l_QSEEComHandle, false);
            if (ret) {
                PERR("qseecom_set_bandwidth fail(%d)", ret);
                return -1;
            }
            memcpy(htc_sdkey, resp, HTC_SDKEY_LEN);
            ret = qseecom_shutdown_app(&l_QSEEComHandle);

             */
			scm_flush_range((uintptr_t)htc_sdkey, (uintptr_t)htc_sdkey + HTC_SDKEY_LEN);
			ret = secure_access_item(0, ITEM_SD_KEY_ENCRYPT, hmsg.req_len, htc_sdkey);
			if (ret)
				PERR("Encrypt SD key fail (%d)", ret);

			if (copy_to_user((void __user *)hmsg.resp_buf, htc_sdkey, hmsg.req_len)) {
				PERR("copy_to_user error (sdkey)");
				return -EFAULT;
			}
			break;

		case ITEM_SD_KEY_DECRYPT:
			if ((hmsg.req_buf == NULL) || (hmsg.req_len != HTC_SDKEY_LEN)) {
				PERR("invalid arguments");
				return -EFAULT;
			}
			if (copy_from_user(htc_sdkey, (void __user *)hmsg.req_buf, hmsg.req_len)) {
				PERR("copy_from_user error (sdkey)");
				return -EFAULT;
			}
            /*
            ret = qseecom_start_app(&l_QSEEComHandle, appname, 1024);
            if (ret) {
                PERR("Start app: fail");
                return -1;
            } else {
                PDEBUG("Start app: pass");
            }
            if(l_QSEEComHandle == NULL) {
                PERR("Failed to get QSEECOM handle\n");
                return -1;
            }

            send_cmd = (struct qsc_send_cmd *)l_QSEEComHandle->sbuf;
            resp = (struct qsc_send_cmd *)((uintptr_t)(l_QSEEComHandle->sbuf) + l_QSEEComHandle->sbuf_len/2);
            memset(resp, 0, HTC_SDKEY_LEN);

            send_cmd->cmd_id = ITEM_SD_KEY_DECRYPT;
            send_cmd->test_buf_size = HTC_SDKEY_LEN;
            memcpy((uint8_t *)send_cmd + sizeof(struct qsc_send_cmd), htc_sdkey, HTC_SDKEY_LEN);

            ret = qseecom_set_bandwidth(l_QSEEComHandle, true);
            if (ret) {
                PERR("qseecom_set_bandwidth fail(%d)", ret);
                return -1;
            }
            ret = qseecom_send_command(l_QSEEComHandle, send_cmd, HTC_SDKEY_LEN, resp, HTC_SDKEY_LEN);
            if (ret) {
                PERR("qseecom_send_cmd fail(%d)", ret);
                return -1;
            }
            ret = qseecom_set_bandwidth(l_QSEEComHandle, false);
            if (ret) {
                PERR("qseecom_set_bandwidth fail(%d)", ret);
                return -1;
            }
            memcpy(htc_sdkey, resp, HTC_SDKEY_LEN);
            ret = qseecom_shutdown_app(&l_QSEEComHandle);

             */
			scm_flush_range((uintptr_t)htc_sdkey, (uintptr_t)htc_sdkey + HTC_SDKEY_LEN);
			ret = secure_access_item(0, ITEM_SD_KEY_DECRYPT, hmsg.req_len, htc_sdkey);
			if (ret)
				PERR("Encrypt SD key fail (%d)", ret);

			if (copy_to_user((void __user *)hmsg.resp_buf, htc_sdkey, hmsg.req_len)) {
				PERR("copy_to_user error (sdkey)");
				return -EFAULT;
			}
			break;

		default:
			PERR("func error");
			return -EFAULT;
		}
		break;

	case HTC_IOCTL_SEC_ATS_GET:
		if (!arg) {
			PERR("invalid arguments");
			return -ENOMEM;
		}
        /*
		scm_flush_range((uint32_t)&amsg, (uint32_t)&amsg + sizeof(htc_sec_ats_t));
		ret = secure_access_item(0, ITEM_SEC_ATS, sizeof(htc_sec_ats_t), (unsigned char *)&amsg);
		if (ret) {
			PERR("ATS service fail (%d)", ret);
			return ret;
		}
        */

		if (copy_to_user((void __user *)arg, &amsg, sizeof(htc_sec_ats_t))) {
			PERR("copy_to_user error (msg)");
			return -EFAULT;
		}
		break;

	case HTC_IOCTL_SEC_ATS_SET:
		if (!arg) {
			PERR("invalid arguments");
			return -ENOMEM;
		}
		if (copy_from_user(&amsg, (void __user *)arg, sizeof(htc_sec_ats_t))) {
			PERR("copy_from_user error (msg)");
			return -EFAULT;
		}
		PDEBUG("func = %x, sizeof htc_sec_ats_t = %zd", amsg.func_info.func_id, sizeof(htc_sec_ats_t));
        /*
		ret = secure_access_item(1, ITEM_SEC_ATS, sizeof(htc_sec_ats_t), (unsigned char *)&amsg);
		if (ret)
			PERR("ATS service fail (%d)", ret);
         */
		break;

	default:
		PERR("command error");
		return -EFAULT;
	}
	return ret;
}

static int compat_get_htc_sdservice_msg (
		compat_htc_sdservice_msg_t __user *data32,
		htc_sdservice_msg_s __user *data)
{
	compat_int_t func;
	compat_int_t offset;
	compat_uptr_t req_buf;
	compat_int_t req_len;
	compat_uptr_t resp_buf;
	compat_int_t resp_len;
	int err = 0;

	PDEBUG("Entry");
	err |= get_user(func, &data32->func);
	err |= put_user(func, &data->func);

	err |= get_user(offset, &data32->offset);
	err |= put_user(offset, &data->offset);

	err |= get_user(req_buf, &data32->req_buf);
	data->req_buf = 0;
	err |= put_user(req_buf, (compat_uptr_t *)&data->req_buf);

	err |= get_user(req_len, &data32->req_len);
	err |= put_user(req_len, &data->req_len);

	err |= get_user(resp_buf, &data32->resp_buf);
	data->resp_buf = 0;
	err |= put_user(resp_buf, (compat_uptr_t *)&data->resp_buf);

	err |= get_user(resp_len, &data32->resp_len);
	err |= put_user(resp_len, &data->resp_len);

	PDEBUG("err: %d", err);
	return err;
}

static int compat_put_htc_sdservice_msg (
		compat_htc_sdservice_msg_t __user *data32,
		htc_sdservice_msg_s __user *data)
{
	compat_int_t func;
	compat_int_t offset;
	compat_uptr_t req_buf;
	compat_int_t req_len;
	compat_uptr_t resp_buf;
	compat_int_t resp_len;
	int err = 0;

	PDEBUG("Entry");
	err |= get_user(func, &data->func);
	err |= put_user(func, &data32->func);

	err |= get_user(offset, &data->offset);
	err |= put_user(offset, &data32->offset);

	err |= get_user(req_buf, (compat_uptr_t *)&data->req_buf);
	data32->req_buf = 0;
	err |= put_user(req_buf, &data32->req_buf);

	err |= get_user(req_len, &data->req_len);
	err |= put_user(req_len, &data32->req_len);

	err |= get_user(resp_buf, (compat_uptr_t *)&data->resp_buf);
	data32->resp_buf = 0;
	err |= put_user(resp_buf, &data32->resp_buf);

	err |= get_user(resp_len, &data->resp_len);
	err |= put_user(resp_len, &data32->resp_len);

	PDEBUG("err: %d", err);
	return err;
}

static long compat_htc_sdservice_ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	compat_htc_sdservice_msg_t __user *compat_hmsg_32;
	htc_sdservice_msg_s __user *hmsg;
	int ret = 0;
	int err = 0;

	PDEBUG("command = %x", command);
	switch (command) {
	case HTC_IOCTL_SDSERVICE:
		compat_hmsg_32 = compat_ptr(arg);
		hmsg = compat_alloc_user_space(sizeof(*hmsg));

		/* Copy 32bit data to 64bit space */
		err = compat_get_htc_sdservice_msg(compat_hmsg_32, hmsg);
		if (err)
			return err;

		ret = htc_sdservice_ioctl(file, command, (unsigned long)hmsg);

		/* Copy 64bit data to 32bit space */
		err = compat_put_htc_sdservice_msg(compat_hmsg_32, hmsg);

		return ret ? ret : err;

	default:
		break;

	}

	return ret ? ret : err;
}

static int htc_sdservice_open(struct inode *inode, struct file *filp)
{
	PDEBUG("Open htc_sdservice success");
	return 0;
}

static int htc_sdservice_release(struct inode *inode, struct file *filp)
{
	PDEBUG("Release htc_sdservice success");
	return 0;
}

static const struct file_operations htc_sdservice_fops = {
	.unlocked_ioctl = htc_sdservice_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_htc_sdservice_ioctl,
#endif
	.open = htc_sdservice_open,
	.release = htc_sdservice_release,
	.owner = THIS_MODULE,
};

static int __init htc_sdservice_init(void)
{
	int ret;

	htc_sdkey = kzalloc(HTC_SDKEY_LEN, GFP_KERNEL);
	if (htc_sdkey == NULL) {
		PERR("allocate the space for SD key failed");
		return -1;
	}

	ret = register_chrdev(0, DEVICE_NAME, &htc_sdservice_fops);
	if (ret < 0) {
		PERR("register module fail");
		return ret;
	}
	htc_sdservice_major = ret;

	htc_sdservice_class = class_create(THIS_MODULE, "htc_sdservice");
	device_create(htc_sdservice_class, NULL, MKDEV(htc_sdservice_major, 0), NULL, DEVICE_NAME);

	PDEBUG("register module ok");
	return 0;
}

static void  __exit htc_sdservice_exit(void)
{
	device_destroy(htc_sdservice_class, MKDEV(htc_sdservice_major, 0));
	class_unregister(htc_sdservice_class);
	class_destroy(htc_sdservice_class);
	unregister_chrdev(htc_sdservice_major, DEVICE_NAME);
	kfree(htc_sdkey);
	PDEBUG("un-registered module ok");
}

module_init(htc_sdservice_init);
module_exit(htc_sdservice_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HTC");

