#ifndef __LINUX_REGMAP_H
#define __LINUX_REGMAP_H

/*
 * Register map access API
 *
 * Copyright 2011 Wolfson Microelectronics plc
 *
 * Author: Mark Brown <broonie@opensource.wolfsonmicro.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/err.h>
#include <linux/bug.h>

struct module;
struct device;
struct i2c_client;
struct irq_domain;
struct spi_device;
struct regmap;
struct regmap_range_cfg;
struct regmap_field;
struct swr_device;

enum regcache_type {
	REGCACHE_NONE,
	REGCACHE_RBTREE,
	REGCACHE_COMPRESSED,
	REGCACHE_FLAT,
};

struct reg_default {
	unsigned int reg;
	unsigned int def;
};

#ifdef CONFIG_REGMAP

enum regmap_endian {
	
	REGMAP_ENDIAN_DEFAULT = 0,
	REGMAP_ENDIAN_BIG,
	REGMAP_ENDIAN_LITTLE,
	REGMAP_ENDIAN_NATIVE,
};

struct regmap_range {
	unsigned int range_min;
	unsigned int range_max;
};

struct regmap_access_table {
	const struct regmap_range *yes_ranges;
	unsigned int n_yes_ranges;
	const struct regmap_range *no_ranges;
	unsigned int n_no_ranges;
};

typedef void (*regmap_lock)(void *);
typedef void (*regmap_unlock)(void *);

/**
 * Configuration for the register map of a device.
 *
 * @name: Optional name of the regmap. Useful when a device has multiple
 *        register regions.
 *
 * @reg_bits: Number of bits in a register address, mandatory.
 * @reg_stride: The register address stride. Valid register addresses are a
 *              multiple of this value. If set to 0, a value of 1 will be
 *              used.
 * @pad_bits: Number of bits of padding between register and value.
 * @val_bits: Number of bits in a register value, mandatory.
 *
 * @writeable_reg: Optional callback returning true if the register
 *		   can be written to. If this field is NULL but wr_table
 *		   (see below) is not, the check is performed on such table
 *                 (a register is writeable if it belongs to one of the ranges
 *                  specified by wr_table).
 * @readable_reg: Optional callback returning true if the register
 *		  can be read from. If this field is NULL but rd_table
 *		   (see below) is not, the check is performed on such table
 *                 (a register is readable if it belongs to one of the ranges
 *                  specified by rd_table).
 * @volatile_reg: Optional callback returning true if the register
 *		  value can't be cached. If this field is NULL but
 *		  volatile_table (see below) is not, the check is performed on
 *                such table (a register is volatile if it belongs to one of
 *                the ranges specified by volatile_table).
 * @precious_reg: Optional callback returning true if the rgister
 *		  should not be read outside of a call from the driver
 *		  (eg, a clear on read interrupt status register). If this
 *                field is NULL but precious_table (see below) is not, the
 *                check is performed on such table (a register is precious if
 *                it belongs to one of the ranges specified by precious_table).
 * @lock:	  Optional lock callback (overrides regmap's default lock
 *		  function, based on spinlock or mutex).
 * @unlock:	  As above for unlocking.
 * @lock_arg:	  this field is passed as the only argument of lock/unlock
 *		  functions (ignored in case regular lock/unlock functions
 *		  are not overridden).
 * @reg_read:	  Optional callback that if filled will be used to perform
 *           	  all the reads from the registers. Should only be provided for
 *		  devices whos read operation cannot be represented as a simple read
 *		  operation on a bus such as SPI, I2C, etc. Most of the devices do
 * 		  not need this.
 * @reg_write:	  Same as above for writing.
 * @fast_io:	  Register IO is fast. Use a spinlock instead of a mutex
 *	     	  to perform locking. This field is ignored if custom lock/unlock
 *	     	  functions are used (see fields lock/unlock of struct regmap_config).
 *		  This field is a duplicate of a similar file in
 *		  'struct regmap_bus' and serves exact same purpose.
 *		   Use it only for "no-bus" cases.
 * @max_register: Optional, specifies the maximum valid register index.
 * @wr_table:     Optional, points to a struct regmap_access_table specifying
 *                valid ranges for write access.
 * @rd_table:     As above, for read access.
 * @volatile_table: As above, for volatile registers.
 * @precious_table: As above, for precious registers.
 * @reg_defaults: Power on reset values for registers (for use with
 *                register cache support).
 * @num_reg_defaults: Number of elements in reg_defaults.
 *
 * @read_flag_mask: Mask to be set in the top byte of the register when doing
 *                  a read.
 * @write_flag_mask: Mask to be set in the top byte of the register when doing
 *                   a write. If both read_flag_mask and write_flag_mask are
 *                   empty the regmap_bus default masks are used.
 * @use_single_rw: If set, converts the bulk read and write operations into
 *		    a series of single read and write operations. This is useful
 *		    for device that does not support bulk read and write.
 * @can_multi_write: If set, the device supports the multi write mode of bulk
 *                   write operations, if clear multi write requests will be
 *                   split into individual write operations
 * @cache_type: The actual cache type.
 * @reg_defaults_raw: Power on reset values for registers (for use with
 *                    register cache support).
 * @num_reg_defaults_raw: Number of elements in reg_defaults_raw.
 * @reg_format_endian: Endianness for formatted register addresses. If this is
 *                     DEFAULT, the @reg_format_endian_default value from the
 *                     regmap bus is used.
 * @val_format_endian: Endianness for formatted register values. If this is
 *                     DEFAULT, the @reg_format_endian_default value from the
 *                     regmap bus is used.
 *
 * @ranges: Array of configuration entries for virtual address ranges.
 * @num_ranges: Number of range configuration entries.
 */
struct regmap_config {
	const char *name;

	int reg_bits;
	int reg_stride;
	int pad_bits;
	int val_bits;

	bool (*writeable_reg)(struct device *dev, unsigned int reg);
	bool (*readable_reg)(struct device *dev, unsigned int reg);
	bool (*volatile_reg)(struct device *dev, unsigned int reg);
	bool (*precious_reg)(struct device *dev, unsigned int reg);
	regmap_lock lock;
	regmap_unlock unlock;
	void *lock_arg;

	int (*reg_read)(void *context, unsigned int reg, unsigned int *val);
	int (*reg_write)(void *context, unsigned int reg, unsigned int val);

	bool fast_io;

	unsigned int max_register;
	const struct regmap_access_table *wr_table;
	const struct regmap_access_table *rd_table;
	const struct regmap_access_table *volatile_table;
	const struct regmap_access_table *precious_table;
	const struct reg_default *reg_defaults;
	unsigned int num_reg_defaults;
	enum regcache_type cache_type;
	const void *reg_defaults_raw;
	unsigned int num_reg_defaults_raw;

	u8 read_flag_mask;
	u8 write_flag_mask;

	bool use_single_rw;
	bool can_multi_write;
	enum regmap_endian reg_format_endian;
	enum regmap_endian val_format_endian;

	const struct regmap_range_cfg *ranges;
	unsigned int num_ranges;
};

struct regmap_range_cfg {
	const char *name;

	
	unsigned int range_min;
	unsigned int range_max;

	
	unsigned int selector_reg;
	unsigned int selector_mask;
	int selector_shift;

	
	unsigned int window_start;
	unsigned int window_len;
};

struct regmap_async;

typedef int (*regmap_hw_write)(void *context, const void *data,
			       size_t count);
typedef int (*regmap_hw_gather_write)(void *context,
				      const void *reg, size_t reg_len,
				      const void *val, size_t val_len);
typedef int (*regmap_hw_async_write)(void *context,
				     const void *reg, size_t reg_len,
				     const void *val, size_t val_len,
				     struct regmap_async *async);
typedef int (*regmap_hw_read)(void *context,
			      const void *reg_buf, size_t reg_size,
			      void *val_buf, size_t val_size);
typedef struct regmap_async *(*regmap_hw_async_alloc)(void);
typedef void (*regmap_hw_free_context)(void *context);

struct regmap_bus {
	bool fast_io;
	regmap_hw_write write;
	regmap_hw_gather_write gather_write;
	regmap_hw_async_write async_write;
	regmap_hw_read read;
	regmap_hw_free_context free_context;
	regmap_hw_async_alloc async_alloc;
	u8 read_flag_mask;
	enum regmap_endian reg_format_endian_default;
	enum regmap_endian val_format_endian_default;
};

struct regmap *regmap_init(struct device *dev,
			   const struct regmap_bus *bus,
			   void *bus_context,
			   const struct regmap_config *config);
struct regmap *regmap_init_i2c(struct i2c_client *i2c,
			       const struct regmap_config *config);
struct regmap *regmap_init_spi(struct spi_device *dev,
			       const struct regmap_config *config);
struct regmap *regmap_init_mmio_clk(struct device *dev, const char *clk_id,
				    void __iomem *regs,
				    const struct regmap_config *config);
struct regmap *regmap_init_swr(struct swr_device *dev,
			       const struct regmap_config *config);

struct regmap *devm_regmap_init(struct device *dev,
				const struct regmap_bus *bus,
				void *bus_context,
				const struct regmap_config *config);
struct regmap *devm_regmap_init_i2c(struct i2c_client *i2c,
				    const struct regmap_config *config);
struct regmap *devm_regmap_init_spi(struct spi_device *dev,
				    const struct regmap_config *config);
struct regmap *devm_regmap_init_mmio_clk(struct device *dev, const char *clk_id,
					 void __iomem *regs,
					 const struct regmap_config *config);
struct regmap *devm_regmap_init_swr(struct swr_device *dev,
				    const struct regmap_config *config);

static inline struct regmap *regmap_init_mmio(struct device *dev,
					void __iomem *regs,
					const struct regmap_config *config)
{
	return regmap_init_mmio_clk(dev, NULL, regs, config);
}

static inline struct regmap *devm_regmap_init_mmio(struct device *dev,
					void __iomem *regs,
					const struct regmap_config *config)
{
	return devm_regmap_init_mmio_clk(dev, NULL, regs, config);
}

void regmap_exit(struct regmap *map);
int regmap_reinit_cache(struct regmap *map,
			const struct regmap_config *config);
struct regmap *dev_get_regmap(struct device *dev, const char *name);
int regmap_write(struct regmap *map, unsigned int reg, unsigned int val);
int regmap_raw_write(struct regmap *map, unsigned int reg,
		     const void *val, size_t val_len);
int regmap_bulk_write(struct regmap *map, unsigned int reg, const void *val,
			size_t val_count);
int regmap_multi_reg_write(struct regmap *map, const struct reg_default *regs,
			int num_regs);
int regmap_multi_reg_write_bypassed(struct regmap *map,
				    const struct reg_default *regs,
				    int num_regs);
int regmap_raw_write_async(struct regmap *map, unsigned int reg,
			   const void *val, size_t val_len);
int regmap_read(struct regmap *map, unsigned int reg, unsigned int *val);
int regmap_raw_read(struct regmap *map, unsigned int reg,
		    void *val, size_t val_len);
int regmap_bulk_read(struct regmap *map, unsigned int reg, void *val,
		     size_t val_count);
int regmap_update_bits(struct regmap *map, unsigned int reg,
		       unsigned int mask, unsigned int val);
int regmap_update_bits_check(struct regmap *map, unsigned int reg,
			     unsigned int mask, unsigned int val,
			     bool *change);
int regmap_get_val_bytes(struct regmap *map);
int regmap_async_complete(struct regmap *map);
bool regmap_can_raw_write(struct regmap *map);

int regcache_sync(struct regmap *map);
int regcache_sync_region(struct regmap *map, unsigned int min,
			 unsigned int max);
void regcache_cache_only(struct regmap *map, bool enable);
void regcache_cache_bypass(struct regmap *map, bool enable);
void regcache_mark_dirty(struct regmap *map);

int regmap_register_patch(struct regmap *map, const struct reg_default *regs,
			  int num_regs);

static inline bool regmap_reg_in_range(unsigned int reg,
				       const struct regmap_range *range)
{
	return reg >= range->range_min && reg <= range->range_max;
}

bool regmap_reg_in_ranges(unsigned int reg,
			  const struct regmap_range *ranges,
			  unsigned int nranges);

struct regmap_irq {
	unsigned int reg_offset;
	unsigned int mask;
};

struct regmap_irq_chip {
	const char *name;

	unsigned int status_base;
	unsigned int mask_base;
	unsigned int ack_base;
	unsigned int wake_base;
	unsigned int irq_reg_stride;
	unsigned int mask_invert;
	unsigned int wake_invert;
	bool runtime_pm;

	int num_regs;

	const struct regmap_irq *irqs;
	int num_irqs;
};

struct regmap_irq_chip_data;

int regmap_add_irq_chip(struct regmap *map, int irq, int irq_flags,
			int irq_base, const struct regmap_irq_chip *chip,
			struct regmap_irq_chip_data **data);
void regmap_del_irq_chip(int irq, struct regmap_irq_chip_data *data);
int regmap_irq_chip_get_base(struct regmap_irq_chip_data *data);
int regmap_irq_get_virq(struct regmap_irq_chip_data *data, int irq);
struct irq_domain *regmap_irq_get_domain(struct regmap_irq_chip_data *data);

#else


static inline int regmap_write(struct regmap *map, unsigned int reg,
			       unsigned int val)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regmap_raw_write(struct regmap *map, unsigned int reg,
				   const void *val, size_t val_len)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regmap_raw_write_async(struct regmap *map, unsigned int reg,
					 const void *val, size_t val_len)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regmap_bulk_write(struct regmap *map, unsigned int reg,
				    const void *val, size_t val_count)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regmap_read(struct regmap *map, unsigned int reg,
			      unsigned int *val)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regmap_raw_read(struct regmap *map, unsigned int reg,
				  void *val, size_t val_len)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regmap_bulk_read(struct regmap *map, unsigned int reg,
				   void *val, size_t val_count)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regmap_update_bits(struct regmap *map, unsigned int reg,
				     unsigned int mask, unsigned int val)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regmap_update_bits_check(struct regmap *map,
					   unsigned int reg,
					   unsigned int mask, unsigned int val,
					   bool *change)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regmap_get_val_bytes(struct regmap *map)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regcache_sync(struct regmap *map)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline int regcache_sync_region(struct regmap *map, unsigned int min,
				       unsigned int max)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline void regcache_cache_only(struct regmap *map, bool enable)
{
	WARN_ONCE(1, "regmap API is disabled");
}

static inline void regcache_cache_bypass(struct regmap *map, bool enable)
{
	WARN_ONCE(1, "regmap API is disabled");
}

static inline void regcache_mark_dirty(struct regmap *map)
{
	WARN_ONCE(1, "regmap API is disabled");
}

static inline void regmap_async_complete(struct regmap *map)
{
	WARN_ONCE(1, "regmap API is disabled");
}

static inline int regmap_register_patch(struct regmap *map,
					const struct reg_default *regs,
					int num_regs)
{
	WARN_ONCE(1, "regmap API is disabled");
	return -EINVAL;
}

static inline struct regmap *dev_get_regmap(struct device *dev,
					    const char *name)
{
	return NULL;
}

#endif

#endif
