/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#ifndef _USB_DESCRIPTORS_H_
#define _USB_DESCRIPTORS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

#define foreach_vlib_usb_desc_type                                            \
  _ (0x01, DEVICE)                                                            \
  _ (0x02, CONFIG)                                                            \
  _ (0x03, STRING)                                                            \
  _ (0x04, INTERFACE)                                                         \
  _ (0x05, ENDPOINT)                                                          \
  _ (0x06, DEVICE_QUALIFIER)                                                  \
  _ (0x07, OTHER_SPEED_CONFIG)                                                \
  _ (0x08, INTERFACE_POWER)                                                   \
  _ (0x09, OTG)                                                               \
  _ (0x0a, DEBUG)                                                             \
  _ (0x0b, INTERFACE_ASSOCIATION)                                             \
  _ (0x0c, SECURITY)                                                          \
  _ (0x0d, KEY)                                                               \
  _ (0x0e, ENCRYPTION_TYPE)                                                   \
  _ (0x0f, BOS)                                                               \
  _ (0x10, DEVICE_CAPABILITY)                                                 \
  _ (0x11, WIRELESS_ENDPOINT_COMP)                                            \
  _ (0x21, WIRE_ADAPTER)                                                      \
  _ (0x22, RPIPE)                                                             \
  _ (0x23, CS_RADIO_CONTROL)                                                  \
  _ (0x24, PIPE_USAGE)                                                        \
  _ (0x30, SS_ENDPOINT_COMP)                                                  \
  _ (0x31, SSP_ISOC_ENDPOINT_COMP)

typedef enum
{
#define _(v, n) VLIB_USB_DT_##n = (v),
  foreach_vlib_usb_desc_type
#undef _
} __clib_packed vlib_usb_descriptor_type_t;

#define foreach_vlib_usb_desc_class                                           \
  _ (0x00, PER_INTERFACE)                                                     \
  _ (0x01, AUDIO)                                                             \
  _ (0x02, COMM)                                                              \
  _ (0x03, HID)                                                               \
  _ (0x05, PHYSICAL)                                                          \
  _ (0x06, STILL_IMAGE)                                                       \
  _ (0x07, PRINTER)                                                           \
  _ (0x08, MASS_STORAGE)                                                      \
  _ (0x09, HUB)                                                               \
  _ (0x0a, CDC_DATA)                                                          \
  _ (0x0b, CSCID)                                                             \
  _ (0x0d, CONTENT_SEC)                                                       \
  _ (0x0e, VIDEO)                                                             \
  _ (0xe0, WIRELESS_CONTROLLER)                                               \
  _ (0x0f, PERSONAL_HEALTHCARE)                                               \
  _ (0x10, AUDIO_VIDEO)                                                       \
  _ (0x11, BILLBOARD)                                                         \
  _ (0x12, USB_TYPE_C_BRIDGE)                                                 \
  _ (0xef, MISC)                                                              \
  _ (0xfe, APP_SPEC)                                                          \
  _ (0xff, VENDOR_SPEC)

typedef enum
{
#define _(v, n) VLIB_USB_CLASS_##n = (v),
  foreach_vlib_usb_desc_class
#undef _
} __clib_packed vlib_usb_class_t;

typedef struct
{
  u8 bLength;
  vlib_usb_descriptor_type_t bDescriptorType;
} __clib_packed vlib_usb_descriptor_header_t;

STATIC_ASSERT_SIZEOF (vlib_usb_descriptor_header_t, 2);

typedef struct
{
  u8 bLength;
  vlib_usb_descriptor_type_t bDescriptorType;

  u16 bcdUSB;
  vlib_usb_class_t bDeviceClass;
  u8 bDeviceSubClass;
  u8 bDeviceProtocol;
  u8 bMaxPacketSize0;
  u16 idVendor;
  u16 idProduct;
  u16 bcdDevice;
  u8 iManufacturer;
  u8 iProduct;
  u8 iSerialNumber;
  u8 bNumConfigurations;
} __clib_packed vlib_usb_device_descriptor_t;

STATIC_ASSERT_SIZEOF (vlib_usb_device_descriptor_t, 18);

typedef struct
{
  u8 bLength;
  vlib_usb_descriptor_type_t bDescriptorType;
  u16 wTotalLength;
  u8 bNumInterfaces;
  u8 bConfigurationValue;
  u8 iConfiguration;
  u8 bmAttributes;
  u8 bMaxPower;
} __clib_packed vlib_usb_config_descriptor_t;

STATIC_ASSERT_SIZEOF (vlib_usb_config_descriptor_t, 9);

typedef struct
{
  u8 bLength;
  vlib_usb_descriptor_type_t bDescriptorType;
  u8 bInterfaceNumber;
  u8 bAlternateSetting;
  u8 bNumEndpoints;
  vlib_usb_class_t bInterfaceClass;
  u8 bInterfaceSubClass;
  u8 bInterfaceProtocol;
  u8 iInterface;
} __clib_packed vlib_usb_interface_descriptor_t;

typedef struct
{
  u8 bLength;
  vlib_usb_descriptor_type_t bDescriptorType;
  u16 wData[0];
} __clib_packed vlib_usb_string_descriptor_t;

STATIC_ASSERT_SIZEOF (vlib_usb_string_descriptor_t, 2);

typedef enum
{
  VLIB_USB_EP_TYPE_CONTROL = 0,
  VLIB_USB_EP_TYPE_ISOCHRONUS = 1,
  VLIB_USB_EP_TYPE_BULK = 2,
  VLIB_USB_EP_TYPE_INTERRUPT = 3,
} vlib_usb_ep_type_t;

typedef enum
{
  VLIB_USB_EP_DIR_OUT = 0,
  VLIB_USB_EP_DIR_IN = 1,
} vlib_usb_ep_direction_t;

typedef struct
{
  u8 bLength;
  vlib_usb_descriptor_type_t bDescriptorType;

  union
  {
    u8 bEndpointAddress;
    struct
    {
      u8 number : 4;
      u8 _Reserved : 3;
      u8 direction : 1;
    } ep_address;
  };

  union
  {
    u8 bmAttributes;
    struct
    {
      u8 type : 2;
      u8 synchronisation : 2;
      u8 usage_type : 2;
    } attribute;
  };
  u16 wMaxPacketSize;
  u8 bInterval;
} __clib_packed vlib_usb_endpoint_descriptor_t;

STATIC_ASSERT_SIZEOF (vlib_usb_endpoint_descriptor_t, 7);

typedef struct
{
  u8 bLength;
  vlib_usb_descriptor_type_t bDescriptorType;
  u8 bEndpointAddress;
  u8 bmAttributes;
  u16 wMaxPacketSize;
  u8 bInterval;
  u8 bRefresh;
  u8 bSynchAddress;
} __clib_packed vlib_usb_endpoint_audio_descriptor_t;

STATIC_ASSERT_SIZEOF (vlib_usb_endpoint_audio_descriptor_t, 9);

typedef struct
{
  u8 bLength;
  vlib_usb_descriptor_type_t bDescriptorType;
  u8 bFirstInterface;
  u8 bInterfaceCount;
  vlib_usb_class_t bFunctionClass;
  u8 bFunctionSubClass;
  u8 bFunctionProtocol;
  u8 iFunction;
} __clib_packed vlib_usb_interface_assoc_descriptor_t;

STATIC_ASSERT_SIZEOF (vlib_usb_interface_assoc_descriptor_t, 8);

typedef enum
{
#define foreach_vllib_usb_req_type                                            \
  _ (0, 0, 0, STANDARD_DEVICE_OUT)                                            \
  _ (0, 0, 1, STANDARD_INTERFACE_OUT)                                         \
  _ (0, 0, 2, STANDARD_ENDPOINT_OUT)                                          \
  _ (0, 1, 0, CLASS_DEVICE_OUT)                                               \
  _ (0, 1, 1, CLASS_INTERFACE_OUT)                                            \
  _ (0, 1, 2, CLASS_ENDPOINT_OUT)                                             \
  _ (0, 2, 0, VENDOR_DEVICE_OUT)                                              \
  _ (0, 2, 1, VENDOR_INTERFACE_OUT)                                           \
  _ (0, 2, 2, VENDOR_ENDPOINT_OUT)                                            \
  _ (1, 0, 0, STANDARD_DEVICE_IN)                                             \
  _ (1, 0, 1, STANDARD_INTERFACE_IN)                                          \
  _ (1, 0, 2, STANDARD_ENDPOINT_IN)                                           \
  _ (1, 1, 0, CLASS_DEVICE_IN)                                                \
  _ (1, 1, 1, CLASS_INTERFACE_IN)                                             \
  _ (1, 1, 2, CLASS_ENDPOINT_IN)                                              \
  _ (1, 2, 0, VENDOR_DEVICE_IN)                                               \
  _ (1, 2, 1, VENDOR_INTERFACE_IN)                                            \
  _ (1, 2, 2, VENDOR_ENDPOINT_IN)

#define _(direction, type, recipient, name)                                   \
  VLIB_USB_REQ_TYPE_##name = ((direction) << 7) | ((type) << 5) | (recipient),
  foreach_vllib_usb_req_type
#undef _
} __clib_packed vlib_usb_req_type_t;

typedef struct
{
  vlib_usb_req_type_t bmRequestType;
  u8 bRequest;
  u16 wValue;
  u16 wIndex;
  u16 wLength;
} vlib_usb_req_t;
STATIC_ASSERT_SIZEOF (vlib_usb_req_t, 8);

typedef struct
{
  vlib_usb_req_t req;
  f64 timeout;
  void *data;
  u16 bytes_received;
} vlib_usb_ctrl_xfer_t;

#endif /* _USB_DESCRIPTORS_H_ */
