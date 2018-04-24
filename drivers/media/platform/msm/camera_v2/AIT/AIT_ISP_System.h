/*************************************************************************************************/
/* AIT ISP Host API                                                                              */
/* All rights reserved by Alpah Image Technology Corp                                            */
/*-----------------------------------------------------------------------------------------------*/
/* File name: AIT_ISP_System.h                                                                   */
/* Description: ISP Host API hardware dependent layer                                            */
/*                                                                                               */
/* Version 0.01   20141209                                                                       */
/*************************************************************************************************/

#ifndef _AIT_ISP_SYSTEM_
#define _AIT_ISP_SYSTEM_


#include "AIT_ISP_project.h"


/*************************************************************************************************/
/* Venus : Definition                                                                            */
/*************************************************************************************************/
#define V3_FORCE_TO_DOWNLOAD_FW				1
#define V3_FORCE_TO_SKIP_DOWNLOAD_FW		0
#define V3_AUTO_DOWNLOAD_FW                 0   /* if boot from SIF fail, then download FW from Host */

#define V3_FORCE_TO_SKIP_FW_BURNING			0

/* for FW downloading */
#define V3_FW_DOWNLOAD_SIZE_PER_PART		0x1000 /* (4KB) */
#define V3_FW_DOWNLOAD_PARTS_PER_BANK		(0x8000 / V3_FW_DOWNLOAD_SIZE_PER_PART) // (32KB / 4KB = 8)
#define V3_FW_DOWNLOAD_DELAY_PER_PART		1
#define V3_FW_DOWNLOAD_CHECK				0/* 1 */

/* for IQ downloading */
#define V3_IQ_DOWNLOAD_EN					0

/* for FW updating */
#define V3_FW_UPDATE_SIZE_PER_PART			0x1000 // (4KB) */
#define V3_FW_UPDATE_PARTS_PER_BANK			(0x8000 / V3_FW_DOWNLOAD_SIZE_PER_PART) // (32KB / 4KB = 8)
#define V3_FW_UPDATE_DELAY_PER_PART			1
#define V3_FW_UPDATE_CHECK					0

#define V3_SAVE_REARRANGED_FW				0/* 1 */

#define V3_FW_FLASH_RW_RECHECK_CNT			50

#define V3_TIMEOUT_CNT						300

#define V3_FW_SIZE							0x10000 /* (64KB) */

#define CreateTempArray(x)						uint8 TempArray[x]
/*************************************************************************************************/
/* Venus : Extern Variables                                                                      */
/*************************************************************************************************/
/* for preview */
extern uint8 V3_NeedInitSensor;

/* for firmware download & update */
extern uint8 *V3_FirmwareBinPtr;
extern uint32 V3_FirmwareBinSize;
extern uint8 VA_FirmwareUpdateStatus;
extern uint8 VA_FirmwareOffset;
extern uint32 gIQtableAddr;
extern uint16 gIQtableSize;

/*************************************************************************************************/
/* Venus : Sample Functions                                                                      */
/*************************************************************************************************/

void V3A_SetFW_DLmode(uint8 mode);
uint8 V3A_GetFW_DLmode(void);

void VA_DelayMS(uint16 ms);
uint8 V3A_ChipEnable(void);
uint8 V3A_ChipReset(void);

uint8 V3A_PowerOn(void);
uint8 V3A_PowerOff(void);
uint8 V3A_PLLOn(void);
uint8 V3A_PowerUp(uint8 *fw_ptr, uint32 fw_size, uint8 *Cali_ptr, uint32 Cali_size);
uint8 V3A_FirmwareStart(uint8 *fw_ptr, uint32 fw_size, uint8 *Cali_ptr, uint32 Cali_size);
uint8 V3A_DownloadFirmware(uint8 *fw_ptr, uint32 fw_size);

uint8 V3A_DownloadCaliTable(uint8 *Cali_ptr, uint32 Cali_size);

/*************************************************************************************************/
/* Venus : Memory                                                                                */
/*************************************************************************************************/
uint8 V3A_ReadMemAddr(uint32 addr);
uint8 V3A_WriteMemAddr(uint32 addr, uint8 value);
uint8 V3A_GetMemB(uint32 addr);
uint16 V3A_GetMemW(uint32 addr);
uint32 V3A_GetMemL(uint32 addr);
void   V3A_SetMemB(uint32 addr, uint8 data);
void V3A_SetMemW(uint32 addr, uint16 data16);
void V3A_SetMemL(uint32 addr, uint32 data32);
//HTC_START
#if 0
void V3A_GetMemMultiBytes(uint32 dst, uint32 src, uint32 len);
void V3A_SetMemMultiBytes(uint32 dst, uint32 src, uint32 len);
#endif
//HTC_END
void V3A_ClearMemMultiBytes(uint32 dst, uint32 len);

#endif /* _AIT_ISP_SYSTEM_ */

