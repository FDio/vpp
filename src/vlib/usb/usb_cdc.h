/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#ifndef _USB_CDC_H_
#define _USB_CDC_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

#define USB_CDC_SUBCLASS_ECM  0x06
#define USB_CDC_SUBCLASS_MBIM 0x0e

#define USB_CDC_DESC_TYPE_CS_INTERFACE 0x24
#define USB_CDC_DESC_TYPE_CS_ENDPOINT  0x25

#define USB_CDC_DESC_SUBTYPE_HEADER	   0x00
#define USB_CDC_DESC_SUBTYPE_UNION	   0x06
#define USB_CDC_DESC_SUBTYPE_ETHERNET	   0x0f
#define USB_CDC_DESC_SUBTYPE_MBIM_FUNC	   0x1b
#define USB_CDC_DESC_SUBTYPE_MBIM_EXT_FUNC 0x1c

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

#define foreach_usb_cdc_ethernet_desc_t                                       \
  _ (u8, iMACAddress)                                                         \
  _ (u32, bmEthernetStatistics)                                               \
  _ (u16, wMaxSegmentSize)                                                    \
  _ (u8, bNumberPowerFilters)                                                 \
  _ (u16, wNumberMCFilters)

typedef struct
{
  usb_cdc_desc_hdr_t hdr;
#define _(t, n) t n;
  foreach_usb_cdc_ethernet_desc_t
#undef _
} __clib_packed usb_cdc_ethernet_desc_t;

STATIC_ASSERT_SIZEOF (usb_cdc_ethernet_desc_t, 13);

/* CDC-NCM */

#define CDC_SEND_ENCAPSULATED_COMMAND 0x00
#define CDC_GET_ENCAPSULATED_RESPONSE 0x01
#define CDC_NCM_GET_NTB_PARAMETERS    0x80

#define MBIM_CLASS_RESET_FUNCTION 0x05

#define foreach_cdc_ncm_ntb_parameters                                        \
  _ (u16, wLength)                                                            \
  _ (u16, bmNtbFormatsSupported)                                              \
  _ (u32, dwNtbInMaxSize)                                                     \
  _ (u16, wNdpInDivisor)                                                      \
  _ (u16, wNdpInPayloadRemainder)                                             \
  _ (u16, wNdpInAlignment)                                                    \
  _ (u16, _reserved)                                                          \
  _ (u32, dwNtbOutMaxSize)                                                    \
  _ (u16, wNdpOutDivisor)                                                     \
  _ (u16, wNdpOutPayloadRemainder)                                            \
  _ (u16, wNdpOutAlignment)                                                   \
  _ (u16, wNtbOutMaxDatagrams)

typedef struct
{
#define _(t, n) t n;
  foreach_cdc_ncm_ntb_parameters
#undef _
} cdc_ncm_ntb_parameters_t;

STATIC_ASSERT_SIZEOF (cdc_ncm_ntb_parameters_t, 28);

/* CDC-MBIM */

#define foreach_usb_cdc_mbim_func_desc_t                                      \
  _ (u16, bcmMBIMVersion)                                                     \
  _ (u16, wMaxControlMessage)                                                 \
  _ (u8, bNumberFilters)                                                      \
  _ (u8, bMaxFilterSize)                                                      \
  _ (u16, wMaxSegmentSize)                                                    \
  _ (u8, bmNetworkCapabilities)

#define foreach_usb_cdc_mbim_ext_func_desc_t                                  \
  _ (u16, bcdMBIMExtendedVersion)                                             \
  _ (u8, bMaxOutstandingCommandMessages)                                      \
  _ (u16, wMTU)

typedef struct
{
  usb_cdc_desc_hdr_t hdr;
#define _(t, n) t n;
  foreach_usb_cdc_mbim_func_desc_t
#undef _
} __clib_packed usb_cdc_mbim_func_desc_t;

STATIC_ASSERT_SIZEOF (usb_cdc_mbim_func_desc_t, 12);

typedef struct
{
  usb_cdc_desc_hdr_t hdr;
#define _(t, n) t n;
  foreach_usb_cdc_mbim_ext_func_desc_t
#undef _
} __clib_packed usb_cdc_mbim_ext_func_desc_t;

STATIC_ASSERT_SIZEOF (usb_cdc_mbim_ext_func_desc_t, 8);

#endif /* _USB_CDC_H_ */
