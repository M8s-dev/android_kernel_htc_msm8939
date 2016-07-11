/*
 * Copyright (c) 2013-2015 Yamaha Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#ifdef CONFIG_HAS_EARLYSUSPEND
#include <linux/earlysuspend.h>
#endif

#include <linux/iio/buffer.h>
#include <linux/iio/iio.h>
#include <linux/iio/kfifo_buf.h>
#include <linux/iio/sysfs.h>
#include <linux/iio/trigger.h>
#include <linux/iio/trigger_consumer.h>
#include <linux/irq_work.h>
#include <linux/yas_5.4.1024.h>
#include <linux/of_gpio.h>

#define D(x...) printk(KERN_DEBUG "[COMP][YAS53X] " x)
#define I(x...) printk(KERN_INFO "[COMP][YAS53X] " x)
#define W(x...) printk(KERN_WARNING "[COMP][YAS53X] " x)
#define E(x...) printk(KERN_ERR "[COMP][YAS53X] " x)

struct yas_platform_data {
    int placement;
    int intr;
};

static struct i2c_client *this_client;

enum {
	YAS_SCAN_MAGN_X,
	YAS_SCAN_MAGN_Y,
	YAS_SCAN_MAGN_Z,
	YAS_SCAN_TIMESTAMP,
};
struct yas_state {
	struct mutex lock;
	spinlock_t spin_lock;
	struct yas_mag_driver mag;
	struct i2c_client *client;
	struct iio_trigger  *trig;
	struct delayed_work work;
	int16_t sampling_frequency;
	atomic_t pseudo_irq_enable;
	int32_t compass_data[3];
#ifdef CONFIG_HAS_EARLYSUSPEND
	struct early_suspend sus;
#endif
	struct irq_work iio_irq_work;
	struct iio_dev *indio_dev;

	struct class *sensor_class;
	struct device *sensor_dev;

	u8 i2c_rdata;
	int intr;
};

static struct yas_state *g_st;

static int yas_device_open(int32_t type)
{
	return 0;
}

static int yas_device_close(int32_t type)
{
	return 0;
}

static int yas_device_write(int32_t type, uint8_t addr, const uint8_t *buf,
		int len)
{
	uint8_t tmp[2];
	if (sizeof(tmp) - 1 < len)
		return -1;
	tmp[0] = addr;
	memcpy(&tmp[1], buf, len);
	if (i2c_master_send(this_client, tmp, len + 1) < 0)
		return -1;
	return 0;
}

static int yas_device_read(int32_t type, uint8_t addr, uint8_t *buf, int len)
{
	struct i2c_msg msg[2];
	int err;
	msg[0].addr = this_client->addr;
	msg[0].flags = 0;
	msg[0].len = 1;
	msg[0].buf = &addr;
	msg[1].addr = this_client->addr;
	msg[1].flags = I2C_M_RD;
	msg[1].len = len;
	msg[1].buf = buf;
	err = i2c_transfer(this_client->adapter, msg, 2);
	if (err != 2) {
		E(
		  "i2c_transfer() read error: "
		  "slave_addr=%02x, reg_addr=%02x, err=%d\n",
		  this_client->addr, addr, err);
		return err;
	}
	return 0;
}

static void yas_usleep(int us)
{
	usleep_range(us, us + 1000);
}

static uint32_t yas_current_time(void)
{
	return jiffies_to_msecs(jiffies);
}

static int yas_pseudo_irq_enable(struct iio_dev *indio_dev)
{
	struct yas_state *st = iio_priv(indio_dev);
	if (!atomic_cmpxchg(&st->pseudo_irq_enable, 0, 1)) {
		mutex_lock(&st->lock);
		st->mag.set_enable(1);
		mutex_unlock(&st->lock);
		schedule_delayed_work(&st->work, 0);
	}
	return 0;
}

static int yas_pseudo_irq_disable(struct iio_dev *indio_dev)
{
	struct yas_state *st = iio_priv(indio_dev);
	if (atomic_cmpxchg(&st->pseudo_irq_enable, 1, 0)) {
		cancel_delayed_work_sync(&st->work);
		mutex_lock(&st->lock);
		st->mag.set_enable(0);
		mutex_unlock(&st->lock);
	}
	return 0;
}

static int yas_set_pseudo_irq(struct iio_dev *indio_dev, int enable)
{
	if (enable)
		yas_pseudo_irq_enable(indio_dev);
	else
		yas_pseudo_irq_disable(indio_dev);
	return 0;
}

static void iio_trigger_work(struct irq_work *work)
{
	struct yas_state *st = g_st;
	unsigned long flags;
	spin_lock_irqsave(&st->spin_lock, flags);
	iio_trigger_poll(st->trig, iio_get_time_ns());
	spin_unlock_irqrestore(&st->spin_lock, flags);
}

static irqreturn_t yas_trigger_handler(int irq, void *p)
{
	struct iio_poll_func *pf = p;
	struct iio_dev *indio_dev = pf->indio_dev;
	struct yas_state *st = iio_priv(indio_dev);
	int len = 0, i, j;
	int32_t *mag;

	mag = (int32_t *)kmalloc(indio_dev->scan_bytes, GFP_KERNEL);
	if (mag == NULL) {
		E("%s: memory alloc failed in buffer bh\n", __func__);
		goto done;
	}
	if (!bitmap_empty(indio_dev->active_scan_mask, indio_dev->masklength)) {
		j = 0;
		for (i = 0; i < 3; i++) {
			if (test_bit(i, indio_dev->active_scan_mask)) {
				mag[j] = st->compass_data[i];
				j++;
			}
		}
		len = j * 4;
	}

	/* Guaranteed to be aligned with 8 byte boundary */
	if (indio_dev->scan_timestamp)
		*(s64 *)((u8 *)mag + ALIGN(len, sizeof(s64))) = pf->timestamp;

	iio_push_to_buffers(indio_dev, (u8 *)mag);
	kfree(mag);
done:
	iio_trigger_notify_done(indio_dev->trig);
	return IRQ_HANDLED;
}

static int yas_data_rdy_trigger_set_state(struct iio_trigger *trig,
		bool state)
{
	struct iio_dev *indio_dev = iio_trigger_get_drvdata(trig);

	yas_set_pseudo_irq(indio_dev, state);
	return 0;
}

static const struct iio_trigger_ops yas_trigger_ops = {
	.owner = THIS_MODULE,
	.set_trigger_state = &yas_data_rdy_trigger_set_state,
};

static int yas_probe_trigger(struct iio_dev *indio_dev)
{
	int ret;
	struct yas_state *st = iio_priv(indio_dev);
	indio_dev->pollfunc = iio_alloc_pollfunc(&iio_pollfunc_store_time,
			&yas_trigger_handler, IRQF_ONESHOT, indio_dev,
			"%s_consumer%d", indio_dev->name, indio_dev->id);
	if (indio_dev->pollfunc == NULL) {
		ret = -ENOMEM;
		goto error_ret;
	}
	st->trig = iio_trigger_alloc("%s-dev%d",
			indio_dev->name,
			indio_dev->id);
	if (!st->trig) {
		ret = -ENOMEM;
		goto error_dealloc_pollfunc;
	}
	st->trig->dev.parent = &st->client->dev;
	st->trig->ops = &yas_trigger_ops;
	iio_trigger_set_drvdata(st->trig, indio_dev);
	ret = iio_trigger_register(st->trig);
	if (ret)
		goto error_free_trig;
	return 0;

error_free_trig:
	iio_trigger_free(st->trig);
error_dealloc_pollfunc:
	iio_dealloc_pollfunc(indio_dev->pollfunc);
error_ret:
	return ret;
}

static void yas_remove_trigger(struct iio_dev *indio_dev)
{
	struct yas_state *st = iio_priv(indio_dev);
	iio_trigger_unregister(st->trig);
	iio_trigger_free(st->trig);
	iio_dealloc_pollfunc(indio_dev->pollfunc);
}

static const struct iio_buffer_setup_ops yas_buffer_setup_ops = {
	.preenable = &iio_sw_buffer_preenable,
	.postenable = &iio_triggered_buffer_postenable,
	.predisable = &iio_triggered_buffer_predisable,
};

static void yas_remove_buffer(struct iio_dev *indio_dev)
{
	iio_buffer_unregister(indio_dev);
	iio_kfifo_free(indio_dev->buffer);
};

static int yas_probe_buffer(struct iio_dev *indio_dev)
{
	int ret;
	struct iio_buffer *buffer;

	buffer = iio_kfifo_allocate(indio_dev);
	if (!buffer) {
		ret = -ENOMEM;
		goto error_ret;
	}
	buffer->scan_timestamp = true;
	indio_dev->buffer = buffer;
	indio_dev->setup_ops = &yas_buffer_setup_ops;
	indio_dev->modes |= INDIO_BUFFER_TRIGGERED;
	ret = iio_buffer_register(indio_dev, indio_dev->channels,
			indio_dev->num_channels);
	if (ret)
		goto error_free_buf;
	iio_scan_mask_set(indio_dev, indio_dev->buffer, YAS_SCAN_MAGN_X);
	iio_scan_mask_set(indio_dev, indio_dev->buffer, YAS_SCAN_MAGN_Y);
	iio_scan_mask_set(indio_dev, indio_dev->buffer, YAS_SCAN_MAGN_Z);
	return 0;

error_free_buf:
	iio_kfifo_free(indio_dev->buffer);
error_ret:
	return ret;
}

static ssize_t yas_position_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int ret;
	mutex_lock(&st->lock);
	ret = st->mag.get_position();
	mutex_unlock(&st->lock);
	if (ret < 0)
		return -EFAULT;
	return sprintf(buf, "%d\n", ret);
}

static ssize_t yas_position_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int ret, position;
	sscanf(buf, "%d\n", &position);
	mutex_lock(&st->lock);
	ret = st->mag.set_position(position);
	mutex_unlock(&st->lock);
	if (ret < 0)
		return -EFAULT;
	return count;
}


static ssize_t yas_int_pin_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);

	D("%s: gpio_get_value(st->intr) = %d\n", __func__, gpio_get_value(st->intr));

	return scnprintf(buf, PAGE_SIZE, "%d\n", gpio_get_value(st->intr));
}

static ssize_t yas_int_pin_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	return count;
}

static ssize_t yas_sampling_frequency_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	return sprintf(buf, "%d\n", st->sampling_frequency);
}

static ssize_t yas_sampling_frequency_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int ret, data;
	int delay;
	ret = kstrtoint(buf, 10, &data);
	if (ret)
		return ret;
	if (data <= 0)
		return -EINVAL;
	mutex_lock(&st->lock);
	st->sampling_frequency = data;
	delay = MSEC_PER_SEC / st->sampling_frequency;
	st->mag.set_delay(delay);
	mutex_unlock(&st->lock);
	return count;
}

static ssize_t yas_hard_offset_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int8_t hard_offset[3];
	int ret;
	mutex_lock(&st->lock);
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS530
	ret = st->mag.ext(YAS530_GET_HW_OFFSET, hard_offset);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS532 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS533
	ret = st->mag.ext(YAS532_GET_HW_OFFSET, hard_offset);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
	ret = st->mag.ext(YAS537_GET_HW_OFFSET, hard_offset);
#endif
	mutex_unlock(&st->lock);
	if (ret < 0)
		return -EFAULT;
	return sprintf(buf, "%d %d %d\n", hard_offset[0], hard_offset[1],
			hard_offset[2]);
}

#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS530 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS532 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS533
static ssize_t yas_hard_offset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int32_t tmp[3];
	int8_t hard_offset[3];
	int ret, i;
	sscanf(buf, "%d %d %d\n", &tmp[0], &tmp[1], &tmp[2]);
	for (i = 0; i < 3; i++)
		hard_offset[i] = (int8_t)tmp[i];
	mutex_lock(&st->lock);
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS530
	ret = st->mag.ext(YAS530_SET_HW_OFFSET, hard_offset);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS532 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS533
	ret = st->mag.ext(YAS532_SET_HW_OFFSET, hard_offset);
#endif
	mutex_unlock(&st->lock);
	if (ret < 0)
		return -EFAULT;
	return count;
}
#endif

static ssize_t yas_static_matrix_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int16_t m[9];
	int ret;
	mutex_lock(&st->lock);
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS530
	ret = st->mag.ext(YAS530_GET_STATIC_MATRIX, m);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS532 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS533
	ret = st->mag.ext(YAS532_GET_STATIC_MATRIX, m);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
	ret = st->mag.ext(YAS537_GET_STATIC_MATRIX, m);
#endif
	mutex_unlock(&st->lock);
	if (ret < 0)
		return -EFAULT;
	return sprintf(buf, "%d %d %d %d %d %d %d %d %d\n",
			m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8]);
}

static ssize_t yas_static_matrix_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int16_t m[9];
	int ret;
	sscanf(buf, "%hd %hd %hd %hd %hd %hd %hd %hd %hd\n", &m[0], &m[1], &m[2], &m[3],
			&m[4], &m[5], &m[6], &m[7], &m[8]);
	mutex_lock(&st->lock);
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS530
	ret = st->mag.ext(YAS530_SET_STATIC_MATRIX, m);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS532 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS533
	ret = st->mag.ext(YAS532_SET_STATIC_MATRIX, m);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
	ret = st->mag.ext(YAS537_SET_STATIC_MATRIX, m);
#endif
	mutex_unlock(&st->lock);
	if (ret < 0)
		return -EFAULT;
	return count;
}

static ssize_t yas_self_test_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS530
	struct yas530_self_test_result r;
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS532 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS533
	struct yas532_self_test_result r;
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
	struct yas537_self_test_result r;
#endif
	int ret;
	mutex_lock(&st->lock);
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS530
	ret = st->mag.ext(YAS530_SELF_TEST, &r);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS532 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS533
	ret = st->mag.ext(YAS532_SELF_TEST, &r);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
	ret = st->mag.ext(YAS537_SELF_TEST, &r);
#endif
	mutex_unlock(&st->lock);

#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS530 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS532 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS533
	return sprintf(buf, "%d %d %d %d %d %d %d %d %d %d %d\n",
			ret, r.id, r.xy1y2[0], r.xy1y2[1], r.xy1y2[2],
			r.dir, r.sx, r.sy, r.xyz[0], r.xyz[1], r.xyz[2]);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
	return sprintf(buf, "%d %d %d %d %d %d %d %d\n", ret, r.id, r.dir,
			r.sx, r.sy, r.xyz[0], r.xyz[1], r.xyz[2]);
#endif
}

static ssize_t yas_self_test_noise_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int32_t xyz_raw[3];
	int ret;
	mutex_lock(&st->lock);
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS530
	ret = st->mag.ext(YAS530_SELF_TEST_NOISE, xyz_raw);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS532 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS533
	ret = st->mag.ext(YAS532_SELF_TEST_NOISE, xyz_raw);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
	ret = st->mag.ext(YAS537_SELF_TEST_NOISE, xyz_raw);
#endif
	mutex_unlock(&st->lock);
	if (ret < 0)
		return -EFAULT;
	return sprintf(buf, "%d %d %d\n", xyz_raw[0], xyz_raw[1], xyz_raw[2]);
}

#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
static ssize_t yas_mag_average_sample_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int8_t mag_average_sample;
	int ret;
	mutex_lock(&st->lock);
	ret = st->mag.ext(YAS537_GET_AVERAGE_SAMPLE, &mag_average_sample);
	mutex_unlock(&st->lock);
	if (ret < 0)
		return -EFAULT;
	return sprintf(buf, "%d\n", mag_average_sample);
}

static ssize_t yas_mag_average_sample_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int32_t tmp;
	int8_t mag_average_sample;
	int ret;
	sscanf(buf, "%d\n", &tmp);
	mag_average_sample = (int8_t)tmp;
	mutex_lock(&st->lock);
	ret = st->mag.ext(YAS537_SET_AVERAGE_SAMPLE, &mag_average_sample);
	mutex_unlock(&st->lock);
	if (ret < 0)
		return -EFAULT;
	return count;
}

static ssize_t yas_ouflow_thresh_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);
	int16_t thresh[6];
	int ret;
	mutex_lock(&st->lock);
	ret = st->mag.ext(YAS537_GET_OUFLOW_THRESH, thresh);
	mutex_unlock(&st->lock);
	if (ret < 0)
		return -EFAULT;
	return sprintf(buf, "%d %d %d %d %d %d\n", thresh[0], thresh[1],
			thresh[2], thresh[3], thresh[4], thresh[5]);
}

#endif

static int yas_read_raw(struct iio_dev *indio_dev,
		struct iio_chan_spec const *chan,
		int *val,
		int *val2,
		long mask) {
	struct yas_state  *st = iio_priv(indio_dev);
	int ret = -EINVAL;

	if (chan->type != IIO_MAGN)
		return -EINVAL;

	mutex_lock(&st->lock);

	switch (mask) {
	case 0:
		*val = st->compass_data[chan->channel2 - IIO_MOD_X];
		ret = IIO_VAL_INT;
		break;
	case IIO_CHAN_INFO_SCALE:
		/* Gain : counts / uT = 1000 [nT] */
		/* Scaling factor : 1000000 / Gain = 1000 */
		*val = 0;
		*val2 = 1000;
		ret = IIO_VAL_INT_PLUS_MICRO;
		break;
	}

	mutex_unlock(&st->lock);

	return ret;
}

static void yas_work_func(struct work_struct *work)
{
	struct yas_data mag[1];
	struct yas_state *st =
		container_of((struct delayed_work *)work,
				struct yas_state, work);
	uint32_t time_before, time_after;
	int32_t delay;
	int ret, i;

	time_before = jiffies_to_msecs(jiffies);
	mutex_lock(&st->lock);
	ret = st->mag.measure(mag, 1);
	if (ret == 1) {
		for (i = 0; i < 3; i++)
			st->compass_data[i] = mag[0].xyz.v[i];
	}
	mutex_unlock(&st->lock);
	if (ret == 1)
		irq_work_queue(&st->iio_irq_work);
	time_after = jiffies_to_msecs(jiffies);
	delay = MSEC_PER_SEC / st->sampling_frequency
		- (time_after - time_before);
	if (delay <= 0)
		delay = 1;
	schedule_delayed_work(&st->work, msecs_to_jiffies(delay));
}

#define YAS_MAGN_INFO_SHARED_MASK	(BIT(IIO_CHAN_INFO_SCALE))
#define YAS_MAGN_INFO_SEPARATE_MASK	(BIT(IIO_CHAN_INFO_RAW))

#define YAS_MAGNETOMETER_CHANNEL(axis)			\
{							\
	.type = IIO_MAGN,				\
	.modified = 1,					\
	.channel2 = IIO_MOD_##axis,			\
	.info_mask_separate = YAS_MAGN_INFO_SEPARATE_MASK,   \
	.info_mask_shared_by_type = YAS_MAGN_INFO_SHARED_MASK,\
	.scan_index = YAS_SCAN_MAGN_##axis,		\
	.scan_type = IIO_ST('s', 32, 32, 0)		\
}

static const struct iio_chan_spec yas_channels[] = {
	YAS_MAGNETOMETER_CHANNEL(X),
	YAS_MAGNETOMETER_CHANNEL(Y),
	YAS_MAGNETOMETER_CHANNEL(Z),
	IIO_CHAN_SOFT_TIMESTAMP(YAS_SCAN_TIMESTAMP)
};

static IIO_DEVICE_ATTR(sampling_frequency, S_IRUSR|S_IWUSR,
		yas_sampling_frequency_show,
		yas_sampling_frequency_store, 0);
static IIO_DEVICE_ATTR(position, S_IRUSR|S_IWUSR,
		yas_position_show, yas_position_store, 0);
static IIO_DEVICE_ATTR(yas53x_int_pin, S_IRUSR|S_IWUSR,
		yas_int_pin_show, yas_int_pin_store, 0);

#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS530 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS532 \
	|| YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS533
static IIO_DEVICE_ATTR(hard_offset, S_IRUSR|S_IWUSR,
		yas_hard_offset_show, yas_hard_offset_store, 0);
#endif
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
static IIO_DEVICE_ATTR(hard_offset, S_IRUSR, yas_hard_offset_show, NULL, 0);
#endif
static IIO_DEVICE_ATTR(static_matrix, S_IRUSR|S_IWUSR,
		yas_static_matrix_show, yas_static_matrix_store, 0);
static IIO_DEVICE_ATTR(self_test, S_IRUSR, yas_self_test_show, NULL, 0);
static IIO_DEVICE_ATTR(self_test_noise, S_IRUSR, yas_self_test_noise_show,
		NULL, 0);
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
static IIO_DEVICE_ATTR(mag_average_sample, S_IRUSR|S_IWUSR,
		yas_mag_average_sample_show, yas_mag_average_sample_store, 0);
static IIO_DEVICE_ATTR(ouflow_thresh, S_IRUSR, yas_ouflow_thresh_show, NULL, 0);
#endif

static struct attribute *yas_attributes[] = {
	&iio_dev_attr_sampling_frequency.dev_attr.attr,
	&iio_dev_attr_position.dev_attr.attr,
	&iio_dev_attr_yas53x_int_pin.dev_attr.attr,
	&iio_dev_attr_hard_offset.dev_attr.attr,
	&iio_dev_attr_static_matrix.dev_attr.attr,
	&iio_dev_attr_self_test.dev_attr.attr,
	&iio_dev_attr_self_test_noise.dev_attr.attr,
#if YAS_MAG_DRIVER == YAS_MAG_DRIVER_YAS537
	&iio_dev_attr_mag_average_sample.dev_attr.attr,
	&iio_dev_attr_ouflow_thresh.dev_attr.attr,
#endif
	NULL
};
static const struct attribute_group yas_attribute_group = {
	.attrs = yas_attributes,
};

static const struct iio_info yas_info = {
	.read_raw = &yas_read_raw,
	.attrs = &yas_attribute_group,
	.driver_module = THIS_MODULE,
};

#ifdef CONFIG_HAS_EARLYSUSPEND
static void yas_early_suspend(struct early_suspend *h)
{
	struct yas_state *st = container_of(h,
			struct yas_state, sus);
	if (atomic_read(&st->pseudo_irq_enable)) {
		cancel_delayed_work_sync(&st->work);
		st->mag.set_enable(0);
	}
}


static void yas_late_resume(struct early_suspend *h)
{
	struct yas_state *st = container_of(h,
			struct yas_state, sus);
	if (atomic_read(&st->pseudo_irq_enable)) {
		st->mag.set_enable(1);
		schedule_delayed_work(&st->work, 0);
	}
}
#endif

static int yas_parse_dt(struct device *dev, struct yas_platform_data *pdata) {
	struct property *prop = NULL;
	struct device_node *dt = dev->of_node;
	u32 buf = 0;
	uint32_t irq_gpio_flags;

	prop = of_find_property(dt, "compass_yas53x,placement", NULL);
	if (prop) {
		of_property_read_u32(dt, "compass_yas53x,placement", &buf);
		pdata->placement = buf;
		I("%s: placement = %d\n", __func__, pdata->placement);
	} else
		E("%s: compass_yas53x,placement not found\n", __func__);

	pdata->intr = of_get_named_gpio_flags(dt,
					      "compass_yas53x,intr",
					      0,
					      &irq_gpio_flags);
	if (pdata->intr < 0) {
		E("%s: of_get_named_gpio_flags fails: pdata->intr\n", __func__);
		return -EINVAL;
	}
	I("%s: pdata->intr = %d\n", __func__, pdata->intr);

	return 0;
}

static int create_sysfs_interfaces(struct yas_state *st)
{
	int res;

	st->sensor_class = class_create(THIS_MODULE, "htc_compass");
	if (st->sensor_class == NULL)
		goto custom_class_error;

	st->sensor_dev = device_create(st->sensor_class, NULL, 0, "%s",
					   "yas53x");
	if (st->sensor_dev == NULL)
		goto custom_device_error;

	res = sysfs_create_link(
				&st->sensor_dev->kobj,
				&st->indio_dev->dev.kobj,
				"iio");
	if (res < 0) {
		E("link create error, res = %d\n", res);
		goto err_fail_sysfs_create_link;
	}

	return 0;

err_fail_sysfs_create_link:
	if (st->sensor_dev)
		device_destroy(st->sensor_class, 0);
custom_device_error:
	if (st->sensor_class)
		class_destroy(st->sensor_class);
custom_class_error:
	dev_err(&st->client->dev, "%s:Unable to create class\n",
		__func__);
	return -1;
}

static int yas_probe(struct i2c_client *i2c, const struct i2c_device_id *id)
{
	struct yas_state *st;
	struct iio_dev *indio_dev;
	struct yas_platform_data *pdata;
	int ret, i;

	I("%s\n", __func__);

	this_client = i2c;
	indio_dev = iio_device_alloc(sizeof(*st));
	if (!indio_dev) {
		ret = -ENOMEM;
		goto error_ret;
	}
	i2c_set_clientdata(i2c, indio_dev);

	indio_dev->name = id->name;
	indio_dev->dev.parent = &i2c->dev;
	indio_dev->info = &yas_info;
	indio_dev->channels = yas_channels;
	indio_dev->num_channels = ARRAY_SIZE(yas_channels);
	indio_dev->modes = INDIO_DIRECT_MODE;
	I("%s: id->name = %s\n", __func__, id->name);

	st = iio_priv(indio_dev);
	st->client = i2c;
	st->sampling_frequency = 20;
	st->mag.callback.device_open = yas_device_open;
	st->mag.callback.device_close = yas_device_close;
	st->mag.callback.device_read = yas_device_read;
	st->mag.callback.device_write = yas_device_write;
	st->mag.callback.usleep = yas_usleep;
	st->mag.callback.current_time = yas_current_time;
	st->indio_dev = indio_dev;
	INIT_DELAYED_WORK(&st->work, yas_work_func);
	mutex_init(&st->lock);
#ifdef CONFIG_HAS_EARLYSUSPEND
	st->sus.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + 1;
	st->sus.suspend = yas_early_suspend;
	st->sus.resume = yas_late_resume;
	register_early_suspend(&st->sus);
#endif
	for (i = 0; i < 3; i++)
		st->compass_data[i] = 0;

	ret = yas_probe_buffer(indio_dev);
	if (ret)
		goto error_free_dev;
	ret = yas_probe_trigger(indio_dev);
	if (ret)
		goto error_remove_buffer;
	ret = iio_device_register(indio_dev);
	if (ret)
		goto error_remove_trigger;
	ret = yas_mag_driver_init(&st->mag);
	if (ret < 0) {
		ret = -EFAULT;
		goto error_unregister_iio;
	}
	ret = st->mag.init();
	if (ret < 0) {
		ret = -EFAULT;
		goto error_unregister_iio;
	}

	pdata = kzalloc(sizeof(*pdata), GFP_KERNEL);
	if (pdata == NULL)
		E("%s: memory allocation for pdata failed.", __func__);
	else
		yas_parse_dt(&i2c->dev , pdata);

	mutex_lock(&st->lock);
	if ((pdata->placement < 8) && (pdata->placement >= 0)) {
		ret = st->mag.set_position(pdata->placement);
		I("%s: set position = %d\n", __func__, pdata->placement);
	} else {
		ret = st->mag.set_position(5);
		D("%s: set default position = 5\n", __func__);
	}
	mutex_unlock(&st->lock);

	init_irq_work(&st->iio_irq_work, iio_trigger_work);
	g_st = st;

	ret = create_sysfs_interfaces(st);
	if (ret) {
		E("%s: create_sysfs_interfaces fail, ret = %d\n",
		  __func__, ret);
		goto err_create_fixed_sysfs;
	}

	st->intr = pdata->intr;
	ret = gpio_request(st->intr, "yas533_intr");
	if (ret) {
		E("%s : request intr gpio fail, intr = %d\n",
		  __func__, st->intr);
	}
	spin_lock_init(&st->spin_lock);
	return 0;

err_create_fixed_sysfs:
	kfree(pdata);
error_unregister_iio:
	iio_device_unregister(indio_dev);
error_remove_trigger:
	yas_remove_trigger(indio_dev);
error_remove_buffer:
	yas_remove_buffer(indio_dev);
error_free_dev:
#ifdef CONFIG_HAS_EARLYSUSPEND
	unregister_early_suspend(&st->sus);
#endif
	iio_device_free(indio_dev);
error_ret:
	i2c_set_clientdata(i2c, NULL);
	this_client = NULL;
	return ret;
}

static int yas_remove(struct i2c_client *i2c)
{
	struct iio_dev *indio_dev = i2c_get_clientdata(i2c);
	struct yas_state *st;
	if (indio_dev) {
		st = iio_priv(indio_dev);
#ifdef CONFIG_HAS_EARLYSUSPEND
		unregister_early_suspend(&st->sus);
#endif
		yas_pseudo_irq_disable(indio_dev);
		st->mag.term();
		iio_device_unregister(indio_dev);
		yas_remove_trigger(indio_dev);
		yas_remove_buffer(indio_dev);
		iio_device_free(indio_dev);
		this_client = NULL;
	}
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int yas_suspend(struct device *dev)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);

	I("%s++\n", __func__);

	if (atomic_read(&st->pseudo_irq_enable)) {
		cancel_delayed_work_sync(&st->work);
		st->mag.set_enable(0);
	}

	I("%s--\n", __func__);

	return 0;
}

static int yas_resume(struct device *dev)
{
	struct iio_dev *indio_dev = dev_get_drvdata(dev);
	struct yas_state *st = iio_priv(indio_dev);

	I("%s++\n", __func__);

	if (atomic_read(&st->pseudo_irq_enable)) {
		st->mag.set_enable(1);
		schedule_delayed_work(&st->work, 0);
	}

	I("%s--\n", __func__);

	return 0;
}

static SIMPLE_DEV_PM_OPS(yas_pm_ops, yas_suspend, yas_resume);
#define YAS_PM_OPS (&yas_pm_ops)
#else
#define YAS_PM_OPS NULL
#endif

static const struct i2c_device_id yas_id[] = {
	{"yas53x", 0},
	{ }
};
MODULE_DEVICE_TABLE(i2c, yas_id);

static struct of_device_id yas53x_match_table[] = {
	{.compatible = "htc_compass,yas53x" },
	{},
};

static struct i2c_driver yas_driver = {
	.driver = {
		.name	= "yas53x",
		.owner	= THIS_MODULE,
		.of_match_table = yas53x_match_table,
		.pm	= YAS_PM_OPS,
	},
	.probe		= yas_probe,
	.remove		= yas_remove,
	.id_table	= yas_id,
};
module_i2c_driver(yas_driver);

MODULE_DESCRIPTION("Yamaha Magnetometer I2C driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("5.4.1024");
