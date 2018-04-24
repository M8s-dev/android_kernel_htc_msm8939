/* Copyright (c) 2015, The Linux Foundation. All rights reserved.
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

#ifndef _LINUX_SOUNDWIRE_H
#define _LINUX_SOUNDWIRE_H
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/mod_devicetable.h>

extern struct bus_type soundwire_type;

#define SWR_MAX_CHANNEL_NUM	8
#define SWR_MAX_DEV_PORT_NUM	14
#define SWR_MAX_DEV_NUM		11
#define SWR_MAX_MSTR_PORT_NUM	(SWR_MAX_DEV_NUM * SWR_MAX_DEV_PORT_NUM)

struct swr_port_info {
	u8 dev_id;
	u8 port_en;
	u8 port_id;
	u8 offset1;
	u8 offset2;
	u8 sinterval;
	u8 ch_en;
	u8 num_ch;
	u32 ch_rate;
};

struct swr_params {
	u8 tid;
	u8 dev_id;
	u8 num_port;
	u8 port_id[SWR_MAX_DEV_PORT_NUM];
	u8 num_ch[SWR_MAX_DEV_PORT_NUM];
	u32 ch_rate[SWR_MAX_DEV_PORT_NUM];
	u8 ch_en[SWR_MAX_DEV_PORT_NUM];
};

/*
 * struct swr_reg - struct to handle soundwire slave register read/writes
 * @tid: transaction id for reg read/writes
 * @dev_id: logical device number of the soundwire slave device
 * @regaddr: 16 bit regaddr of soundwire slave
 * @buf: value to be written/read to/from regaddr
 * @len: length of the buffer buf
 */
struct swr_reg {
	u8  tid;
	u8  dev_id;
	u32 regaddr;
	u32 *buf;
	u32 len;
};

struct swr_master {
	struct device dev;
	struct list_head list;
	unsigned int bus_num;
	struct mutex mlock;
	struct list_head devices;
	struct swr_port_info port[SWR_MAX_MSTR_PORT_NUM];
	struct swr_params **port_txn;
	struct swr_reg **reg_txn;
	u8 last_tid;
	u8 num_port;
	u8 num_dev;
	int (*connect_port)(struct swr_master *mstr, struct swr_params *txn);
	int (*disconnect_port)(struct swr_master *mstr, struct swr_params *txn);
	int (*read)(struct swr_master *mstr, u8 dev_num, u16 reg_addr,
			void *buf, u32 len);
	int (*write)(struct swr_master *mstr, u8 dev_num, u16 reg_addr,
			const void *buf);
	int (*bulk_write)(struct swr_master *master, u8 dev_num, void *reg,
			  const void *buf, size_t len);
	int (*get_logical_dev_num)(struct swr_master *mstr, u64 dev_id,
				u8 *dev_num);
};

static inline struct swr_master *to_swr_master(struct device *dev)
{
	return dev ? container_of(dev, struct swr_master, dev) : NULL;
}

struct swr_device {
	char name[SOUNDWIRE_NAME_SIZE];
	struct swr_master *master;
	struct swr_driver *driver;
	struct list_head dev_list;
	u8               dev_num;
	struct device    dev;
	unsigned long    addr;
};

static inline struct swr_device *to_swr_device(struct device *dev)
{
	return dev ? container_of(dev, struct swr_device, dev) : NULL;
}

struct swr_driver {
	int	(*probe)(struct swr_device *swr);
	int	(*remove)(struct swr_device *swr);
	void	(*shutdown)(struct swr_device *swr);
	int	(*suspend)(struct swr_device *swr, pm_message_t pmesg);
	int	(*resume)(struct swr_device *swr);
	int	(*device_up)(struct swr_device *swr);
	int	(*device_down)(struct swr_device *swr);
	int	(*reset_device)(struct swr_device *swr);
	int	(*startup)(struct swr_device *swr);
	struct device_driver		driver;
	const struct swr_device_id	*id_table;
};

static inline struct swr_driver *to_swr_driver(struct device_driver *drv)
{
	return drv ? container_of(drv, struct swr_driver, driver) : NULL;
}

struct swr_boardinfo {
	char               name[SOUNDWIRE_NAME_SIZE];
	int                bus_num;
	u64		   addr;
	struct device_node *of_node;
	struct swr_device  *swr_slave;
};

static inline void *swr_get_ctrl_data(const struct swr_master *master)
{
	return master ? dev_get_drvdata(&master->dev) : NULL;
}

static inline void swr_set_ctrl_data(struct swr_master *master, void *data)
{
	dev_set_drvdata(&master->dev, data);
}

static inline void *swr_get_dev_data(const struct swr_device *dev)
{
	return dev ? dev_get_drvdata(&dev->dev) : NULL;
}

static inline void swr_set_dev_data(struct swr_device *dev, void *data)
{
	dev_set_drvdata(&dev->dev, data);
}

extern int swr_startup_devices(struct swr_device *swr_dev);

extern struct swr_device *swr_new_device(struct swr_master *master,
				struct swr_boardinfo const *info);

extern int of_register_swr_devices(struct swr_master *master);

extern void swr_port_response(struct swr_master *mstr, u8 tid);

extern int swr_get_logical_dev_num(struct swr_device *dev, u64 dev_id,
			u8 *dev_num);

extern int swr_read(struct swr_device *dev, u8 dev_num, u16 reg_addr,
			void *buf, u32 len);

extern int swr_write(struct swr_device *dev, u8 dev_num, u16 reg_addr,
			const void *buf);

extern int swr_bulk_write(struct swr_device *dev, u8 dev_num, void *reg_addr,
			  const void *buf, size_t len);

extern int swr_connect_port(struct swr_device *dev, u8 *port_id, u8 num_port,
				u8 *ch_mask, u32 *ch_rate, u8 *num_ch);

extern int swr_disconnect_port(struct swr_device *dev,
				u8 *port_id, u8 num_port);

extern int swr_driver_register(struct swr_driver *drv);

extern void swr_driver_unregister(struct swr_driver *drv);

extern int swr_add_device(struct swr_master *master,
				struct swr_device *swrdev);
extern void swr_remove_device(struct swr_device *swr);

extern void swr_master_add_boarddevices(struct swr_master *master);

extern void swr_unregister_master(struct swr_master *master);

extern int swr_register_master(struct swr_master *master);

extern int swr_device_up(struct swr_device *swr_dev);

extern int swr_device_down(struct swr_device *swr_dev);

extern int swr_reset_device(struct swr_device *swr_dev);

#endif 
