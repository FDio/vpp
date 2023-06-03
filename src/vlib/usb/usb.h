/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#ifndef _USB_H_
#define _USB_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>

#include <linux/usb/ch9.h>
#include <vlib/usb/usb_cdc.h>

typedef struct vlib_usb_desc_t
{
  struct vlib_usb_desc_t *next, *prev, *parent, *child;
  union
  {
    u8 desc[0];
    struct usb_descriptor_header hdr;
    struct usb_device_descriptor device;
    struct usb_config_descriptor config;
    struct usb_interface_descriptor interface;
    struct usb_endpoint_descriptor endpoint;
  };
} vlib_usb_desc_t;

typedef struct
{
  vlib_usb_desc_t **all;
} vlib_usb_desc_tree_t;

typedef struct
{
  int fd;
} vlib_usb_dev_t;

clib_error_t *
vlib_usb_device_open_by_bus_and_device (vlib_main_t *vm, u8 busnum, u8 devnum,
					vlib_usb_dev_t **usbdevp);
void vlib_usb_device_close (vlib_main_t *vm, vlib_usb_dev_t *ud);
int vlib_usb_get_dev_desc (vlib_usb_dev_t *d, u8 desc_type, u8 desc_index,
			   void *data, u16 len);
int vlib_usb_get_if_desc (vlib_usb_dev_t *d, u8 desc_type, u8 desc_index,
			  void *data, u16 len);
vlib_usb_desc_tree_t *vlib_usb_device_config_get (vlib_usb_dev_t *ud);
void vlib_usb_free_desc_tree (vlib_usb_desc_tree_t *d);

clib_error_t *vlib_usb_get_active_config (vlib_main_t *vm, vlib_usb_dev_t *d,
					  u8 *active_config);
clib_error_t *vlib_usb_set_active_config (vlib_main_t *vm, vlib_usb_dev_t *d,
					  u8 active_config);
u8 *vlib_usb_get_string_desc (vlib_usb_dev_t *d, u8 desc_idx);

format_function_t format_vlib_usb_string_desc;
format_function_t format_usb_device_config;
format_function_t format_usb_desc;

#define foreach_vlib_usb_desc_in_tree(d, tree, desc_type)                     \
  for (vlib_usb_desc_t **__dp = ((tree)->all), *(d) = __dp[0];                \
       __dp - (tree)->all < vec_len ((tree)->all); __dp++, (d) = __dp[0])     \
    if ((d)->hdr.bDescriptorType == (desc_type))

#endif /* _USB_H_ */
