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
vlib_usb_free_desc_tree (vlib_usb_desc_tree_t *d)
{
  vlib_usb_desc_t **dp;
  vec_foreach (dp, d->all)
    clib_mem_free (*dp);
  vec_free (d->all);
  clib_mem_free (d);
}

static vlib_usb_desc_t *
usb_desc_add (vlib_usb_desc_tree_t *dc, u8 *p)
{
  struct usb_descriptor_header *h = (typeof (h)) p;
  u32 hdr_sz = STRUCT_OFFSET_OF (vlib_usb_desc_t, desc);
  vlib_usb_desc_t *d = clib_mem_alloc (hdr_sz + h->bLength);
  clib_memset (d, 0, hdr_sz);
  clib_memcpy (d->desc, p, h->bLength);
  vec_add1 (dc->all, d);
  return d;
}

vlib_usb_desc_tree_t *
vlib_usb_device_config_get (vlib_usb_dev_t *ud)
{
  u8 buffer[1024];
  vlib_usb_desc_tree_t *dc;
  vlib_usb_desc_t *d, *dd, *cd = 0, *id = 0, *icd;

  dc = clib_mem_alloc (sizeof (*dc));
  clib_memset (dc, 0, sizeof (*dc));

  vlib_usb_get_dev_desc (ud, USB_DT_DEVICE, 0, buffer, sizeof (buffer));
  dd = usb_desc_add (dc, buffer);

  for (u8 cfg_idx = 0; cfg_idx < dd->device.bNumConfigurations; cfg_idx++)
    {
      u8 *next = buffer;

      int len = vlib_usb_get_dev_desc (ud, USB_DT_CONFIG, cfg_idx, buffer,
				       sizeof (buffer));

      if (len < sizeof (struct usb_config_descriptor))
	continue;

      while (next - buffer < len)
	{
	  d = usb_desc_add (dc, next);
	  switch (((struct usb_descriptor_header *) next)->bDescriptorType)
	    {
	    case USB_DT_CONFIG:
	      if (cd)
		cd->next = d;
	      else
		dd->child = d;
	      d->parent = dd;
	      d->prev = cd;
	      cd = d;
	      id = 0;
	      icd = 0;
	      break;
	    case USB_DT_INTERFACE:
	      if (id)
		id->next = d;
	      else
		cd->child = d;
	      d->parent = cd;
	      d->prev = id;
	      id = d;
	      icd = 0;
	      break;
	    default:
	      if (icd)
		icd->next = d;
	      else
		id->child = d;
	      d->parent = id;
	      d->prev = icd;
	      icd = d;
	      break;
	    }
	  next += ((struct usb_descriptor_header *) next)->bLength;
	}
      if (next - buffer != len)
	goto error;
    }
  return dc;
error:
  vlib_usb_free_desc_tree (dc);
  return 0;
}
