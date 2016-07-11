/*************************************************************************************************/
/* AIT ISP Host API                                                                              */
/* All rights reserved by Alpah Image Technology Corp                                            */
/*-----------------------------------------------------------------------------------------------*/
/* File name: AIT_ISP_spi_ctl.c                                                                  */
/* Description: ISP Host API SPI routines abstraction layer                                      */
/*                                                                                               */
/* Version 0.01   20141209                                                                       */
/*************************************************************************************************/

#include "AIT_ISP_spi_ctl.h"


/*************************************************************************************************/
/* SPI Implementation                                                                            */
/*************************************************************************************************/
extern void SetVenusRegB(uint16 Addr, uint8 Val);
extern void SetVenusRegW(uint16 Addr, uint16 Val);
extern void SetVenusMultiBytes(uint8* dataPtr, uint16 startAddr, uint16 length);
extern uint8 GetVenusRegB(uint16 Addr);
extern uint16 GetVenusRegW(uint16 Addr);
extern void GetVenusMultiBytes(uint8* dataPtr, uint16 startAddr, uint16 length);

void transmit_byte_via_SPI(uint16 addr, uint8 data)
{
/* The code is platform dependent. It should be implemented by platform porting. */
 SetVenusRegB(addr, data); 
}

void transmit_word_via_SPI(uint16 addr, uint16 data)
{
/* The code is platform dependent. It should be implemented by platform porting. */
 SetVenusRegW(addr, data);
}

void transmit_multibytes_via_SPI(uint8* ptr, uint16 addr, uint16 length)
{
/* The code is platform dependent. It should be implemented by platform porting. */
SetVenusMultiBytes(ptr, addr, length); 
}

uint8 receive_byte_via_SPI(uint16 addr)
{	
//	uint8 receive_byte_value = 0;
/* The code is platform dependent. It should be implemented by platform porting. */
/* return GetVenusRegB(addr);  or  receive_byte_value = GetVenusRegB(addr); */
//	return receive_byte_value;
    return GetVenusRegB(addr);
}

uint16 receive_word_via_SPI(uint16 addr)
{	
//	uint16 receive_word_value = 0;
/* The code is platform dependent. It should be implemented by platform porting. */
/* return GetVenusRegW(addr);  or  receive_word_value = GetVenusRegW(addr); */
//	return receive_word_value;
    return GetVenusRegW(addr);
}

void receive_multibytes_via_SPI(uint8* ptr, uint16 addr, uint16 length)
{
/* The code is platform dependent. It should be implemented by platform porting. */
GetVenusMultiBytes(ptr, addr, length); 
}
