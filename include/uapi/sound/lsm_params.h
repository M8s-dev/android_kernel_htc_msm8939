#ifndef _UAPI_LSM_PARAMS_H__
#define _UAPI_LSM_PARAMS_H__

#include <linux/types.h>
#include <sound/asound.h>

#define SNDRV_LSM_VERSION SNDRV_PROTOCOL_VERSION(0, 1, 0)

#define LSM_OUT_FORMAT_PCM (0)
#define LSM_OUT_FORMAT_ADPCM (1 << 0)

#define LSM_OUT_DATA_RAW (0)
#define LSM_OUT_DATA_PACKED (1)

#define LSM_OUT_DATA_EVENTS_DISABLED (0)
#define LSM_OUT_DATA_EVENTS_ENABLED (1)

#define LSM_OUT_TRANSFER_MODE_RT (0)
#define LSM_OUT_TRANSFER_MODE_FTRT (1)

enum lsm_app_id {
	LSM_VOICE_WAKEUP_APP_ID = 1,
	LSM_VOICE_WAKEUP_APP_ID_V2 = 2,
};

enum lsm_detection_mode {
	LSM_MODE_KEYWORD_ONLY_DETECTION = 1,
	LSM_MODE_USER_KEYWORD_DETECTION
};

enum lsm_vw_status {
	LSM_VOICE_WAKEUP_STATUS_RUNNING = 1,
	LSM_VOICE_WAKEUP_STATUS_DETECTED,
	LSM_VOICE_WAKEUP_STATUS_END_SPEECH,
	LSM_VOICE_WAKEUP_STATUS_REJECTED
};

enum LSM_PARAM_TYPE {
	LSM_ENDPOINT_DETECT_THRESHOLD = 0,
	LSM_OPERATION_MODE,
	LSM_GAIN,
	LSM_MIN_CONFIDENCE_LEVELS,
	LSM_REG_SND_MODEL,
	LSM_DEREG_SND_MODEL,
	LSM_CUSTOM_PARAMS,
	
	LSM_PARAMS_MAX,
};

struct snd_lsm_ep_det_thres {
	__u32 epd_begin;
	__u32 epd_end;
};

struct snd_lsm_detect_mode {
	enum lsm_detection_mode mode;
	bool detect_failure;
};

struct snd_lsm_gain {
	__u16 gain;
};


struct snd_lsm_sound_model_v2 {
	__u8 __user *data;
	__u8 *confidence_level;
	__u32 data_size;
	enum lsm_detection_mode detection_mode;
	__u8 num_confidence_levels;
	bool detect_failure;
};

struct snd_lsm_session_data {
	enum lsm_app_id app_id;
};

struct snd_lsm_event_status {
	__u16 status;
	__u16 payload_size;
	__u8 payload[0];
};

struct snd_lsm_detection_params {
	__u8 *conf_level;
	enum lsm_detection_mode detect_mode;
	__u8 num_confidence_levels;
	bool detect_failure;
};

struct lsm_params_info {
	__u32 module_id;
	__u32 param_id;
	__u32 param_size;
	__u8 __user *param_data;
	enum LSM_PARAM_TYPE param_type;
};

struct snd_lsm_module_params {
	__u8 __user *params;
	__u32 num_params;
	__u32 data_size;
};

struct snd_lsm_output_format_cfg {
	__u8 format;
	__u8 packing;
	__u8 events;
	__u8 mode;
};

#define SNDRV_LSM_DEREG_SND_MODEL _IOW('U', 0x01, int)
#define SNDRV_LSM_EVENT_STATUS	_IOW('U', 0x02, struct snd_lsm_event_status)
#define SNDRV_LSM_ABORT_EVENT	_IOW('U', 0x03, int)
#define SNDRV_LSM_START		_IOW('U', 0x04, int)
#define SNDRV_LSM_STOP		_IOW('U', 0x05, int)
#define SNDRV_LSM_SET_SESSION_DATA _IOW('U', 0x06, struct snd_lsm_session_data)
#define SNDRV_LSM_REG_SND_MODEL_V2 _IOW('U', 0x07,\
					struct snd_lsm_sound_model_v2)
#define SNDRV_LSM_LAB_CONTROL	_IOW('U', 0x08, uint32_t)
#define SNDRV_LSM_STOP_LAB	_IO('U', 0x09)
#define SNDRV_LSM_SET_PARAMS	_IOW('U', 0x0A, \
					struct snd_lsm_detection_params)
#define SNDRV_LSM_SET_MODULE_PARAMS	_IOW('U', 0x0B, \
					struct snd_lsm_module_params)
#define SNDRV_LSM_OUT_FORMAT_CFG _IOW('U', 0x0C, \
				      struct snd_lsm_output_format_cfg)
#define SNDRV_LSM_SET_PORT	_IO('U', 0x0D)

#endif
