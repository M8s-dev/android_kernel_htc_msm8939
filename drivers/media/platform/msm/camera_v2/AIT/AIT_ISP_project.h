/*************************************************************************************************/
/* AIT ISP Host API                                                                              */
/* All rights reserved by Alpah Image Technology Corp                                            */
/*-----------------------------------------------------------------------------------------------*/
/* File name: AIT_ISP_project.h                                                                    */
/* Description: ISP Host API project related definition                                          */
/*                                                                                               */
/* Version 0.01   20141209                                                                       */
/*************************************************************************************************/

#ifndef _AIT_ISP_PROJECT_H_
#define _AIT_ISP_PROJECT_H_

#include <linux/kernel.h>//HTC Add

#define FW_DRAM_LOAD_FROM_FLASH				0
#define FW_DRAM_LOAD_FROM_SRAM_ONCE			1
#define FW_DRAM_LOAD_FROM_DRAM				2
#define FW_DRAM_LOAD_FROM_SRAM_BY_RINGBUF	3	

#define FW_DRAM_LOAD_DEFAULT_MODE		FW_DRAM_LOAD_FROM_SRAM_ONCE

#define VENUS_MALLOC_MEM				(0x03000000L)

/*************************************************************************************************/
/* Venus : Typedefinition                                                                        */
/*************************************************************************************************/
typedef unsigned char			uint8;
typedef unsigned short			uint16;
//HTC_START
#if 1
typedef unsigned int			uint32;
#else
typedef unsigned long			uint32;
#endif
//HTC_END
typedef char					int8;
typedef short					int16;
//HTC_START
#if 1
typedef int					int32;
#else
typedef long					int32;
#endif
//HTC_END



/*************************************************************************************************/
/* Venus : Message                                                                               */
/*************************************************************************************************/
//HTC_START
#if 1
#define VA_MSG(...)				//printf(""          ## __VA_ARGS__)
#define VA_INFO(...)			//printf("  INFO: "  ## __VA_ARGS__)
#define VA_ERR(fmt, args...) pr_err("[CAM][AIT] : " fmt, ##args)
#define VA_HIGH(fmt, args...) pr_info("[CAM][AIT] : " fmt, ##args)
#else
#define VA_MSG(...)				/* printf(""          ## __VA_ARGS__) */
#define VA_INFO(...)			/* printf("  INFO: "  ## __VA_ARGS__) */
#define VA_ERR(...)				/* printf("  ERROR: " ## __VA_ARGS__) */
#define VA_HIGH(...)			/* printf("-##- "     ## __VA_ARGS__) */
#endif
//HTC_END
#define VA_CLOCK(...)           /* clock(__VA_ARGS__) */


#endif /* _AIT_ISP_PROJECT_H_ */
