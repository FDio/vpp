/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>
#include <vlib/usb/usb.h>

#include <fcntl.h>
#include <sys/ioctl.h>

clib_error_t *
vlib_usb_device_open_by_bus_and_device (vlib_main_t *vm, u8 busnum, u8 devnum,
					vlib_usb_dev_t **usbdevp)
{
  u8 *fmt = 0;
  int fd;
  vlib_usb_dev_t *d;

  fmt = format (fmt, "/dev/bus/usb/%03u/%03u%c", busnum, devnum, 0);

  fd = open ((char *) fmt, O_RDWR);
  vec_free (fmt);

  if (fd < 0)
    return clib_error_return_unix (0, "unable to open USB device %u/%u",
				   busnum, devnum);

  d = clib_mem_alloc_aligned (sizeof (*d), CLIB_CACHE_LINE_BYTES);
  d->fd = fd;

  usbdevp[0] = d;
  return 0;
}

void
vlib_usb_device_close (vlib_main_t *vm, vlib_usb_dev_t *ud)
{
  close (ud->fd);
  clib_mem_free (ud);
}

int
vlib_usb_get_dev_desc (vlib_usb_dev_t *d, u8 desc_type, u8 desc_index,
		       void *data, u16 len)
{
  struct usbdevfs_ctrltransfer ct = {
    .bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
    .bRequest = USB_REQ_GET_DESCRIPTOR,
    .wValue = (u16) desc_type << 8 | desc_index,
    .wIndex = 0,
    .wLength = len,
    .timeout = 200,
    .data = data,
  };

  return ioctl (d->fd, USBDEVFS_CONTROL, &ct);
}

clib_error_t *
vlib_usb_get_active_config (vlib_main_t *vm, vlib_usb_dev_t *d,
			    u8 *active_config)
{
  int rv;
  struct usbdevfs_ctrltransfer ct = {
    .bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
    .bRequest = USB_REQ_GET_CONFIGURATION,
    .wValue = 0,
    .wIndex = 0,
    .data = active_config,
    .wLength = 1,
    .timeout = 200,
  };

  if ((rv = ioctl (d->fd, USBDEVFS_CONTROL, &ct)) < 0)
    return clib_error_return (0, "ioctl(USBDEVFS_CONTROL) failed [rv %d]", rv);
  return 0;
}

clib_error_t *
vlib_usb_set_active_config (vlib_main_t *vm, vlib_usb_dev_t *d,
			    u8 active_config)
{
  int rv;
  if ((rv = ioctl (d->fd, USBDEVFS_SETCONFIGURATION, &active_config)) < 0)
    return clib_error_return (
      0, "ioctl(USBDEVFS_SETCONFIGURATION) failed [rv %d]", rv);
  return 0;
}

int
vlib_usb_get_if_desc (vlib_usb_dev_t *d, u8 desc_type, u8 desc_index,
		      void *data, u16 len)
{
  struct usbdevfs_ctrltransfer ct = {
    .bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_INTERFACE,
    .bRequest = USB_REQ_GET_DESCRIPTOR,
    .wValue = (u16) desc_type << 8 | desc_index,
    .wIndex = 0,
    .wLength = len,
    .timeout = 200,
    .data = data,
  };

  return ioctl (d->fd, USBDEVFS_CONTROL, &ct);
}

u8 *
vlib_usb_get_string_desc (vlib_usb_dev_t *d, u8 desc_idx)
{
  u8 *s = 0;
  int len;
  struct
  {
    struct usb_string_descriptor desc;
    u16 buffer[USB_MAX_STRING_LEN - 1];
  } data;

  if ((len = vlib_usb_get_dev_desc (d, USB_DT_STRING, desc_idx, &data, 255)) <
      4)
    return 0;

  for (u16 *wc = data.desc.wData; (u8 *) wc - (u8 *) &data < len; wc++)
    vec_add1 (s, wc[0] > 255 ? '.' : wc[0]);

  return s;
}
