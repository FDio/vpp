/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>
#include <vlib/usb/usb.h>

#include <fcntl.h>
#include <sys/ioctl.h>

void
vlib_usb_desc_free_with_childs (vlib_usb_desc_t *root)
{
  vlib_usb_desc_t **dp, **dv = 0;

  foreach_vlib_usb_child_desc (d, root)
    vec_add1 (dv, d);
  vec_add1 (dv, root);

  vec_foreach (dp, dv)
    clib_mem_free (dp[0]);
  vec_free (dv);
}

vlib_usb_desc_t *
vlib_usb_create_desc_tree (u8 *data, int n_bytes)
{
  vlib_usb_desc_t *root = 0, *d, *dd = 0, *cd = 0, *id = 0, *icd;
  u32 hdr_sz = STRUCT_OFFSET_OF (vlib_usb_desc_t, desc);

  while (n_bytes > 0)
    {
      vlib_usb_descriptor_header_t *h = (typeof (h)) data;
      u8 len = h->bLength;
      d = clib_mem_alloc (hdr_sz + len);
      clib_memset (d, 0, hdr_sz);
      clib_memcpy (d->desc, data, len);
      if (root == 0)
	root = d;

      switch (((vlib_usb_descriptor_header_t *) data)->bDescriptorType)
	{
	case VLIB_USB_DT_DEVICE:
	  if (dd)
	    goto error;
	  dd = d;
	  d->depth = 0;
	  break;
	case VLIB_USB_DT_CONFIG:
	  if (cd)
	    cd->next = d;
	  else
	    dd->child = d;
	  d->parent = dd;
	  d->prev = cd;
	  cd = d;
	  id = 0;
	  icd = 0;
	  d->depth = 1;
	  break;
	case VLIB_USB_DT_INTERFACE:
	  if (id)
	    id->next = d;
	  else
	    cd->child = d;
	  d->parent = cd;
	  d->prev = id;
	  id = d;
	  icd = 0;
	  d->depth = 2;
	  break;
	default:
	  if (icd)
	    icd->next = d;
	  else
	    id->child = d;
	  d->parent = id;
	  d->prev = icd;
	  icd = d;
	  d->depth = 3;
	  break;
	}
      n_bytes -= len;
      data += len;
    }
  if (n_bytes != 0)
    goto error;

  return root;
error:
  vlib_usb_desc_free_with_childs (root);
  return 0;
}
