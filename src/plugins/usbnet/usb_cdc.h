/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#ifndef _USB_CDC_H_
#define _USB_CDC_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

#define USB_CDC_SUBCLASS_ECM 0x06
#define USB_CDC_SUBCLASS_MBIM 0x0e

#define USB_CDC_DESC_TYPE_CS_INTERFACE 0x24
#define USB_CDC_DESC_TYPE_CS_ENDPOINT  0x25

#define USB_CDC_DESC_SUBTYPE_HEADER   0x00
#define USB_CDC_DESC_SUBTYPE_UNION    0x06
#define USB_CDC_DESC_SUBTYPE_ETHERNET 0x0f

typedef struct
{
  u8 bFunctionLength;
  u8 bDescriptorType;
  u8 bDescriptorSubtype;
  u8 data[0];
} __clib_packed usb_cdc_desc_hdr_t;
STATIC_ASSERT_SIZEOF (usb_cdc_desc_hdr_t, 3);

typedef struct
{
  usb_cdc_desc_hdr_t hdr;
  u16 bcdCDC;
} __clib_packed usb_cdc_header_desc_t;

STATIC_ASSERT_SIZEOF (usb_cdc_header_desc_t, 5);

typedef struct
{
  usb_cdc_desc_hdr_t hdr;
  u8 bControlInterface;
  u8 bSubordinateInterface[1];
} __clib_packed usb_cdc_union_desc_t;

STATIC_ASSERT_SIZEOF (usb_cdc_union_desc_t, 5);

typedef struct
{
  usb_cdc_desc_hdr_t hdr;
  u8 iMACAddress;
  u32 bmEthernetStatistics;
  u16 wMaxSegmentSize;
  u8 bNumberPowerFilters;
  u16 wNumberMCFilters;
} __clib_packed usb_cdc_ethernet_desc_t;

STATIC_ASSERT_SIZEOF (usb_cdc_ethernet_desc_t, 13);

#endif /* _USB_CDC_H_ */
