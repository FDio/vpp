/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#ifndef _USB_H_
#define _USB_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>

#include <vlib/usb/usb_cdc.h>
#include <vlib/usb/usb_descriptors.h>

#define VLIB_USB_N_TIERS 7

typedef u32 vlib_usb_dev_handle_t;

typedef struct vlib_usb_desc_t
{
  struct vlib_usb_desc_t *next, *prev, *parent, *child;
  u8 depth;
  union
  {
    u8 desc[0];
    vlib_usb_descriptor_header_t hdr;
    vlib_usb_device_descriptor_t device;
    vlib_usb_config_descriptor_t config;
    vlib_usb_interface_descriptor_t interface;
    vlib_usb_endpoint_descriptor_t endpoint;
    usb_cdc_desc_hdr_t cs_interface;
  };
} vlib_usb_desc_t;

typedef union
{
  uword uword;
  void *ptr;
} vlib_interrupt_user_data_t;

typedef struct
{
  u8 ep;
  vlib_usb_dev_handle_t dh;
  vlib_interrupt_user_data_t user_data;
  void *data;
  u32 data_size;
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
clib_error_t *
vlib_usb_device_open_by_bus_and_ports (vlib_main_t *vm, u8 busnum, u8 *ports,
				       u8 n_ports, vlib_usb_dev_handle_t *dhp);
void vlib_usb_device_close (vlib_main_t *vm, vlib_usb_dev_handle_t dh);
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
clib_error_t *vlib_usb_ctrl_xfer (vlib_main_t *vm, vlib_usb_dev_handle_t dh,
				  vlib_usb_ctrl_xfer_t *xfer);
u8 *vlib_usb_get_string_desc (vlib_usb_dev_handle_t d, u8 desc_idx);

format_function_t format_vlib_usb_desc_tree;
format_function_t format_vlib_usb_string_desc;
format_function_t format_usb_device_config;
format_function_t format_usb_desc;
format_function_t format_vlib_usb_cdc_ncm_ntb_parameters;
format_function_t format_vlib_usb_req_type;
format_function_t format_vlib_usb_req;

void vlib_usb_desc_free_with_childs (vlib_usb_desc_t *desc);
vlib_usb_desc_t *vlib_usb_create_desc_tree (u8 *data, int n_bytes);
vlib_usb_desc_t *vlib_usb_get_device_desc (vlib_usb_dev_handle_t dh);

static_always_inline vlib_usb_desc_t *
_foreach_vlib_usb_desc_helper (vlib_usb_desc_t *root_desc,
			       vlib_usb_desc_t **cp, vlib_usb_desc_t **np)
{
  vlib_usb_desc_t *c;

  while (*np)
    {
      int last_is_child = *cp && (*cp)->parent == *np;
      *cp = c = *np;

      if ((*np)->child && last_is_child == 0)
	*np = (*np)->child;
      else if ((*np)->next)
	*np = (*np)->next;
      else
	*np = (*np)->parent == root_desc ? 0 : (*np)->parent;

      if (!last_is_child)
	return *cp;
    }

  return 0;
}

#define foreach_vlib_usb_child_desc(d, root)                                  \
  for (vlib_usb_desc_t *__curr = 0, *__next = root->child, *(d);              \
       ((d) = _foreach_vlib_usb_desc_helper (root, &(__curr), &(__next)));)

#define foreach_vlib_usb_child_desc_of_type(d, root, type)                    \
  foreach_vlib_usb_child_desc (d, root)                                       \
    if ((d)->hdr.bDescriptorType == (type))

#endif /* _USB_H_ */
