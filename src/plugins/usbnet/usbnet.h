/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#ifndef _USBNET_H_
#define _USBNET_H_

#include <vlib/vlib.h>
#include <libusb-1.0/libusb.h>

typedef enum
{
  USBNET_DEV_TYPE_UNKNOWN,
  USBNET_DEV_TYPE_CDC_ECM,
  USBNET_DEV_TYPE_CDC_MBIM,
} usbnet_device_type_t;

typedef struct
{
  u8 busnum;
  u8 devnum;
  usbnet_device_type_t type : 8;
  u8 ctrl_if;
  u8 data_if;
  libusb_device_handle *dh;

  /* internal flags */
  u8 dev_is_open : 1;
  u8 ctrl_if_claimed : 1;
  u8 data_if_claimed : 1;

  u8 mac_addr[6];
  u8 *name;
  u32 sw_if_index;
  u32 dev_index;

} usbnet_dev_t;

typedef struct
{
  usbnet_dev_t **devices;
  libusb_context *libusb_ctx;
} usbnet_main_t;

typedef struct
{
  u8 busnum, devnum;
  u16 vid, pid;
  u8 *name;

  /* return */
  u32 sw_if_index;
} usbnet_create_if_args_t;

clib_error_t *usbnet_create_if (vlib_main_t *vm,
				usbnet_create_if_args_t *args);
clib_error_t *usbnet_delete_if (vlib_main_t *vm, u32 sw_if_index);

#endif /* _USBNET_H_ */
