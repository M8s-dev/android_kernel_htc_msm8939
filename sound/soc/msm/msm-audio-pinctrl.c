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

#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/platform_device.h>
#include "msm-audio-pinctrl.h"

struct cdc_pinctrl_info {
	struct pinctrl *pinctrl;
	struct pinctrl_state **cdc_lines;
	int active_set;
};

struct cdc_gpioset_info {
	char **gpiosets;
	char **gpiosets_comb_names;
	uint8_t *gpioset_state;
	int gpiosets_max;
	int gpiosets_comb_max;
};

static struct cdc_pinctrl_info pinctrl_info[MAX_PINCTRL_CLIENT];
static struct cdc_gpioset_info gpioset_info[MAX_PINCTRL_CLIENT];

int msm_get_gpioset_index(enum pinctrl_client client, char *keyword)
{
	int i;

	for (i = 0; i < gpioset_info[client].gpiosets_max; i++) {
		if (!(strcmp(gpioset_info[client].gpiosets[i], keyword)))
			break;
	}
	
	if (i != gpioset_info[client].gpiosets_max)
		return i;
	else
		return -EINVAL;
}

int msm_gpioset_initialize(enum pinctrl_client client,
				struct device *dev)
{
	struct pinctrl *pinctrl;
	const char *gpioset_names = "qcom,msm-gpios";
	const char *gpioset_combinations = "qcom,pinctrl-names";
	const char *gpioset_names_str = NULL;
	const char *gpioset_comb_str = NULL;
	int num_strings = 0;
	int ret = 0;
	int i = 0;

	pr_debug("%s\n", __func__);
	pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR(pinctrl)) {
		pr_err("%s: Unable to get pinctrl handle\n",
				__func__);
		return -EINVAL;
	}
	pinctrl_info[client].pinctrl = pinctrl;

	
	num_strings = of_property_count_strings(dev->of_node,
						gpioset_names);
	if (num_strings < 0) {
		dev_err(dev,
			"%s: missing %s in dt node or length is incorrect\n",
				__func__, gpioset_names);
		goto err;
	}
	gpioset_info[client].gpiosets_max = num_strings;
	gpioset_info[client].gpiosets = devm_kzalloc(dev,
				gpioset_info[client].gpiosets_max *
					sizeof(char *), GFP_KERNEL);
	if (!gpioset_info[client].gpiosets) {
		dev_err(dev, "Can't allocate memory for gpio set names\n");
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < num_strings; i++) {
		ret = of_property_read_string_index(dev->of_node,
					gpioset_names, i, &gpioset_names_str);

		gpioset_info[client].gpiosets[i] = devm_kzalloc(dev,
				(strlen(gpioset_names_str) + 1), GFP_KERNEL);

		if (!gpioset_info[client].gpiosets[i]) {
			dev_err(dev, "%s: Can't allocate gpiosets[%d] data\n",
						__func__, i);
			ret = -ENOMEM;
			goto err;
		}
		strlcpy(gpioset_info[client].gpiosets[i],
				gpioset_names_str, strlen(gpioset_names_str)+1);
		gpioset_names_str = NULL;
	}
	num_strings = 0;

	
	gpioset_info[client].gpioset_state = devm_kzalloc(dev,
				gpioset_info[client].gpiosets_max *
				sizeof(uint8_t), GFP_KERNEL);
	if (!gpioset_info[client].gpioset_state) {
		dev_err(dev, "Can't allocate memory for gpio set counter\n");
		ret = -ENOMEM;
		goto err;
	}

	
	num_strings = of_property_count_strings(dev->of_node,
						gpioset_combinations);
	if (num_strings < 0) {
		dev_err(dev,
			"%s: missing %s in dt node or length is incorrect\n",
			__func__, gpioset_combinations);
		goto err;
	}
	gpioset_info[client].gpiosets_comb_max = num_strings;
	gpioset_info[client].gpiosets_comb_names = devm_kzalloc(dev,
				num_strings * sizeof(char *), GFP_KERNEL);
	if (!gpioset_info[client].gpiosets_comb_names) {
		dev_err(dev, "Can't allocate gpio set combination names data\n");
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < gpioset_info[client].gpiosets_comb_max; i++) {
		ret = of_property_read_string_index(dev->of_node,
				gpioset_combinations, i, &gpioset_comb_str);

		gpioset_info[client].gpiosets_comb_names[i] = devm_kzalloc(dev,
				(strlen(gpioset_comb_str) + 1), GFP_KERNEL);
		if (!gpioset_info[client].gpiosets_comb_names[i]) {
			dev_err(dev, "%s: Can't allocate combinations[%d] data\n",
					__func__, i);
			ret = -ENOMEM;
			goto err;
		}

		strlcpy(gpioset_info[client].gpiosets_comb_names[i],
					gpioset_comb_str,
					strlen(gpioset_comb_str)+1);
		pr_debug("%s: GPIO configuration %s\n",
				__func__,
				gpioset_info[client].gpiosets_comb_names[i]);
		gpioset_comb_str = NULL;
	}

	
	pinctrl_info[client].cdc_lines = devm_kzalloc(dev,
		num_strings * sizeof(char *), GFP_KERNEL);
	if (!pinctrl_info[client].cdc_lines) {
		dev_err(dev, "Can't allocate pinctrl_info.cdc_lines data\n");
		ret = -ENOMEM;
		goto err;
	}

	
	for (i = 0; i < num_strings; i++) {
		pinctrl_info[client].cdc_lines[i] = pinctrl_lookup_state(
								pinctrl,
					(const char *)gpioset_info[client].
							gpiosets_comb_names[i]);
		if (IS_ERR(pinctrl_info[client].cdc_lines[i]))
			pr_err("%s: Unable to get pinctrl handle for %s\n",
				__func__, gpioset_info[client].
						gpiosets_comb_names[i]);
	}
	goto success;

err:
	
	for (i = 0; i < gpioset_info[client].gpiosets_max; i++) {
		if (NULL != gpioset_info[client].gpiosets[i])
			devm_kfree(dev, gpioset_info[client].gpiosets[i]);
	}
	if (NULL != gpioset_info[client].gpiosets)
		devm_kfree(dev, gpioset_info[client].gpiosets);

	
	for (i = 0; i < gpioset_info[client].gpiosets_comb_max; i++) {
		if (NULL != gpioset_info[client].gpiosets_comb_names[i])
			devm_kfree(dev,
			gpioset_info[client].gpiosets_comb_names[i]);
	}
	if (NULL != gpioset_info[client].gpiosets_comb_names)
		devm_kfree(dev, gpioset_info[client].gpiosets_comb_names);

	
	if (NULL != pinctrl_info[client].cdc_lines)
		devm_kfree(dev, pinctrl_info[client].cdc_lines);

	
	if (NULL != gpioset_info[client].gpioset_state)
		devm_kfree(dev, gpioset_info[client].gpioset_state);

success:
	return ret;
}

int msm_gpioset_activate(enum pinctrl_client client, char *keyword)
{
	int ret = 0;
	int gp_set = 0;
	int active_set = 0;

	gp_set = msm_get_gpioset_index(client, keyword);
	if (gp_set < 0) {
		pr_err("%s: gpio set name does not exist\n",
				__func__);
		return gp_set;
	}

	if (!gpioset_info[client].gpioset_state[gp_set]) {
		active_set = pinctrl_info[client].active_set;
		if (IS_ERR(pinctrl_info[client].cdc_lines[active_set]))
			return 0;

		pinctrl_info[client].active_set |= (1 << gp_set);
		active_set = pinctrl_info[client].active_set;
		pr_debug("%s: pinctrl.active_set: %d\n", __func__, active_set);

		
		ret =  pinctrl_select_state(pinctrl_info[client].pinctrl,
			pinctrl_info[client].cdc_lines[active_set]);
	}
	gpioset_info[client].gpioset_state[gp_set]++;

	return ret;
}

int msm_gpioset_suspend(enum pinctrl_client client, char *keyword)
{
	int ret = 0;
	int gp_set = 0;
	int active_set = 0;

	gp_set = msm_get_gpioset_index(client, keyword);
	if (gp_set < 0) {
		pr_err("%s: gpio set name does not exist\n",
				__func__);
		return gp_set;
	}

	if (1 == gpioset_info[client].gpioset_state[gp_set]) {
		pinctrl_info[client].active_set &= ~(1 << gp_set);
		active_set = pinctrl_info[client].active_set;
		if (IS_ERR(pinctrl_info[client].cdc_lines[active_set]))
			return -EINVAL;

		pr_debug("%s: pinctrl.active_set: %d\n", __func__,
				pinctrl_info[client].active_set);
		
		ret =  pinctrl_select_state(pinctrl_info[client].pinctrl,
			pinctrl_info[client].cdc_lines[pinctrl_info[client].
								active_set]);
	}
	if (!(gpioset_info[client].gpioset_state[gp_set])) {
		pr_err("%s: Invalid call to de activate gpios: %d\n", __func__,
				gpioset_info[client].gpioset_state[gp_set]);
		return -EINVAL;
	}

	gpioset_info[client].gpioset_state[gp_set]--;

	return ret;
}
