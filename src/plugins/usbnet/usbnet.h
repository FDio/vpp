/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#ifndef _USBNET_H_
#define _USBNET_H_

#include <vlib/vlib.h>
#include <vlib/usb/usb.h>

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
  u8 config;
  u8 ctrl_if;
  u8 ctrl_int_ep;
  u8 data_if;
  u8 data_bulk_in_ep;
  u8 data_bulk_out_ep;
  vlib_usb_dev_handle_t dh;

  /* internal flags */
  u8 ctrl_if_claimed : 1;
  u8 data_if_claimed : 1;

  u8 mac_addr[6];
  u8 *name;
  u32 sw_if_index;
  u32 dev_index;

  u32 clib_file_index;

  /* mbim */
  u32 mbim_trans_id;

} usbnet_dev_t;

typedef struct
{
  usbnet_dev_t **devices;
} usbnet_main_t;

typedef struct
{
  u8 busnum, devnum;
  u16 vid, pid;
  u8 n_ports, ports[VLIB_USB_N_TIERS - 1];
  u8 *name;

  /* return */
  u32 sw_if_index;
} usbnet_create_if_args_t;

clib_error_t *usbnet_create_if (vlib_main_t *vm,
				usbnet_create_if_args_t *args);
clib_error_t *usbnet_delete_if (vlib_main_t *vm, u32 sw_if_index);

/* format.c */

/* usb.c */
u8 *usbnet_get_string_desc (usbnet_dev_t *ud, u8 desc_idx);

/* mbim.c */
clib_error_t *usbnet_mbim_reset (vlib_main_t *vm, usbnet_dev_t *ud);
clib_error_t *usbnet_mbim_open (vlib_main_t *vm, usbnet_dev_t *ud);
clib_error_t *usbnet_mbim_close (vlib_main_t *vm, usbnet_dev_t *ud);

#endif /* _USBNET_H_ */
