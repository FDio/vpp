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

typedef u32 vlib_usb_dev_handle_t;

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
    usb_cdc_desc_hdr_t cs_interface;
  };
} vlib_usb_desc_t;

typedef struct
{
  vlib_usb_desc_t **all;
} vlib_usb_desc_tree_t;

typedef union
{
  uword uword;
  void *ptr;
} vlib_interrupt_user_data_t;

typedef union
{
  u8 ep;
  vlib_usb_dev_handle_t dh;
  vlib_interrupt_user_data_t user_data;
  ;
} vlib_usb_completion_t;

typedef void (*vlib_usb_callback_fn) (vlib_usb_completion_t *cfg);

typedef struct
{
  u8 once : 1; /* don't rearm */
  vlib_usb_callback_fn callback_fn;
  vlib_interrupt_user_data_t user_data;
} vlib_usb_interrupt_config_t;

clib_error_t *
vlib_usb_device_open_by_bus_and_device (vlib_main_t *vm, u8 busnum, u8 devnum,
					vlib_usb_dev_handle_t *dhp);
void vlib_usb_device_close (vlib_main_t *vm, vlib_usb_dev_handle_t dh);
int vlib_usb_get_dev_desc (vlib_usb_dev_handle_t d, u8 desc_type,
			   u8 desc_index, void *data, u16 len);
int vlib_usb_get_if_desc (vlib_usb_dev_handle_t d, u8 desc_type, u8 desc_index,
			  void *data, u16 len);
vlib_usb_desc_tree_t *vlib_usb_device_config_get (vlib_usb_dev_handle_t dh);
void vlib_usb_free_desc_tree (vlib_usb_desc_tree_t *d);
clib_error_t *vlib_usb_enable_interrupt (vlib_main_t *vm,
					 vlib_usb_dev_handle_t d, u8 ep,
					 vlib_usb_interrupt_config_t *cfg);
clib_error_t *vlib_usb_disable_interrupt (vlib_main_t *vm,
					  vlib_usb_dev_handle_t dh, u8 ep);

clib_error_t *vlib_usb_get_active_config (vlib_main_t *vm,
					  vlib_usb_dev_handle_t dh,
					  u8 *active_config);
clib_error_t *vlib_usb_set_active_config (vlib_main_t *vm,
					  vlib_usb_dev_handle_t d,
					  u8 active_config);
clib_error_t *vlib_usb_claim_interface (vlib_main_t *vm,
					vlib_usb_dev_handle_t dh, u8 ifnum);
clib_error_t *vlib_usb_set_interface_altsetting (vlib_main_t *vm,
						 vlib_usb_dev_handle_t dh,
						 u8 ifnum, u8 altsetting);
u8 *vlib_usb_get_string_desc (vlib_usb_dev_handle_t d, u8 desc_idx);

format_function_t format_vlib_usb_string_desc;
format_function_t format_usb_device_config;
format_function_t format_usb_desc;

#define foreach_vlib_usb_desc_in_tree(d, tree, desc_type)                     \
  for (vlib_usb_desc_t **__dp = ((tree)->all), *(d) = __dp[0];                \
       __dp - (tree)->all < vec_len ((tree)->all); __dp++, (d) = __dp[0])     \
    if ((d)->hdr.bDescriptorType == (desc_type))

#endif /* _USB_H_ */
