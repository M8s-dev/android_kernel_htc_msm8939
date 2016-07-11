/*
 * include/linux/ncp6951_flashlight.h - The NCP6951 flashlight header
 *
 * Copyright (C) 2014 HTC Corporation.
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
 */
#ifndef __NCP6951_FLASHLIGHT_H
#define __NCP6951_FLASHLIGHT_H

struct ncp6951_flt_platform_data {
	uint32_t flash_timeout_sw;	/* ms, max sw flashing duration */
	uint32_t flash_timeout_hw;	/* ms, max hw flashing duration */
	uint32_t flash_timeout_inhibit; /* ms, min interval between 2 flashes */
	uint32_t flash_timeout_inhibit_en;	/* switch of inhibit timer */
	uint32_t flash_timeout_red_eye_en;	/* switch of pre-flash timeout protection */

	uint32_t flash_current_max;	/* mA, max flash current */
	uint32_t flash_current_reduced;	/* mA, reduced flash current */
	uint32_t flash_current_red_eye;	/* mA, pre-flash current */
	uint32_t torch_current_max;	/* mA, max torch current */

	uint32_t flash_count_red_eye;	/* # of pre-flash */

	uint32_t ncp6951_pin_flen;	/* flash enable */
	uint32_t ncp6951_pin_flsel;	/* flash in reduced current immediately
					   when PA transmit burst (Optional) */
};

#undef __NCP6951_FLASHLIGHT_H
#endif

