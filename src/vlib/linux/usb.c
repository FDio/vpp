/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include "vppinfra/clib.h"
#include "vppinfra/error.h"
#include <vlib/vlib.h>
#include <vppinfra/file.h>
#include <vppinfra/linux/sysfs.h>

#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>
#include <vlib/usb/usb.h>
#include <vlib/unix/unix.h>
#include <linux/usb/ch9.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>

VLIB_REGISTER_LOG_CLASS (usb_linux_dev, static) = {
  .class_name = "usb",
  .subclass_name = "linux",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define USB_TIMEOUT  1000
#define SYSFS_PREFIX "/sys/bus/usb/devices/"

typedef struct
{
  u32 submitted : 1;
  u32 rearm : 1;
  vlib_usb_dev_handle_t dev_handle;
  u32 dh;
  int fd;
  vlib_usb_completion_t completion;
  vlib_usb_callback_fn callback_fn;
  struct usbdevfs_urb urb;
} linux_usb_xfer_t;

typedef struct
{
  int fd;
  u8 busnum;
  u8 devnum;
  u8 *path;
  u32 clib_file_index;
  vlib_usb_desc_t *device_desc;
  linux_usb_xfer_t *ctrl_xfer;
} linux_usb_device_t;

linux_usb_device_t *devices = 0; /* pool of active usb devices */

static u8 *
log_device_id (vlib_usb_dev_handle_t dh)
{
  if (dh != -1)
    {
      linux_usb_device_t *d = pool_elt_at_index (devices, dh);
      return d->path;
    }
  return 0;
}

#define log_debug(dh, fmt, ...)                                               \
  vlib_log_debug (usb_linux_dev.class, "[%v]: " fmt, log_device_id (dh),      \
		  __VA_ARGS__)
#define log_notice(dh, fmt, ...)                                              \
  vlib_log_notice (usb_linux_dev.class, "[%v]: " fmt, log_device_id (dh),     \
		   __VA_ARGS__)
#define log_warn(dh, fmt, ...)                                                \
  vlib_log_warn (usb_linux_dev.class, "[%v]: " fmt, log_device_id (dh),       \
		 __VA_ARGS__)
#define log_err(dh, fmt, ...)                                                 \
  vlib_log_err (usb_linux_dev.class, "[%v]: " fmt, log_device_id (dh),        \
		__VA_ARGS__)

clib_error_t *
vlib_usb_error (vlib_usb_dev_handle_t dh, int rv, char *fmt, ...)
{
  clib_error_t *err;
  u8 *s;

  va_list va;
  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  if (rv < 0)
    s = format (s, " [errno %d]", rv);

  log_err (dh, "%v", s);

  err = clib_error_return (0, "%v", s);
  vec_free (s);
  return err;
}

static clib_error_t *
linux_usb_read_ready (clib_file_t *uf)
{
  log_warn (uf->private_data, "unexpected read ready event", 0);
  return 0;
}

static linux_usb_xfer_t *
linux_usb_xfer_alloc (linux_usb_device_t *d, int buffer_size)
{
  linux_usb_xfer_t *xfer = 0;
  u32 sz = sizeof (linux_usb_xfer_t) + buffer_size;
  xfer = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
  clib_memset (xfer, 0, sz);

  if (buffer_size)
    {
      xfer->urb.buffer = xfer + 1;
      xfer->completion.data = xfer + 1;
      xfer->urb.buffer_length = buffer_size;
    }

  xfer->fd = d->fd;

  return xfer;
}

static void
linux_usb_xfer_free (linux_usb_xfer_t *xfer)
{
  if (xfer->submitted)
    {
      int rv = ioctl (xfer->fd, USBDEVFS_DISCARDURB, &xfer->urb);
      if (rv < 0)
	log_err (xfer->dev_handle, "ioctl(USBDEVFS_DISCARDURB) failed", 0);
    }

  clib_mem_free (xfer);
}

static clib_error_t *
linux_usb_write_ready (clib_file_t *uf)
{
  vlib_usb_dev_handle_t dh = uf->private_data;
  linux_usb_xfer_t *xfer;
  struct usbdevfs_urb *urb;

  int rv = ioctl (uf->file_descriptor, USBDEVFS_REAPURBNDELAY, &urb);
  if (rv < 0)
    return vlib_usb_error (
      dh, rv, "write_ready: ioctl(USBDEVFS_REAPURBNDELAY) failed");

  xfer = (linux_usb_xfer_t *) ((u8 *) urb -
			       STRUCT_OFFSET_OF (linux_usb_xfer_t, urb));
  log_debug (xfer->dev_handle,
	     "urb %p completed, status %d actual_length %d error_count %d",
	     urb, urb->status, urb->actual_length, urb->error_count);

  if (urb->actual_length)
    log_debug (dh, "%U", format_vlib_usb_req, urb->buffer);
  log_debug (dh, "%U", format_hexdump, urb->buffer, urb->actual_length);

  if (xfer->callback_fn)
    {
      xfer->completion.data_size = urb->actual_length;
      xfer->callback_fn (&xfer->completion);
    }

  if (xfer->rearm)
    {
      urb->actual_length = 0;
      log_warn (dh, "urb %U", format_hexdump, urb, sizeof (*urb));
      rv = ioctl (uf->file_descriptor, USBDEVFS_SUBMITURB, urb);
      log_notice (dh, "USBDEVFS_SUBMITURB %p rv %d", xfer, rv);
      if (rv < 0)
	return vlib_usb_error (
	  dh, rv, "write_ready: ioctl(USBDEVFS_SUBMITURB) failed");
    }
  return 0;
}

vlib_usb_desc_t *
vlib_usb_get_device_desc (vlib_usb_dev_handle_t dh)
{
  return pool_elt_at_index (devices, dh)->device_desc;
}

static clib_error_t *
linux_usb_error_ready (clib_file_t *uf)
{
  log_warn (uf->private_data, "unexpected error event", 0);
  return 0;
}

clib_error_t *
vlib_usb_device_open_by_bus_and_device (vlib_main_t *vm, u8 busnum, u8 devnum,
					vlib_usb_dev_handle_t *dhp)
{
  u8 buffer[1024], *s = 0;
  int fd, rv;
  linux_usb_device_t *d;
  vlib_usb_dev_handle_t dh;
  struct usbdevfs_conninfo_ex ci = {};

  s = format (s, "/dev/bus/usb/%03u/%03u%c", busnum, devnum, 0);

  fd = open ((char *) s, O_RDWR);
  vec_free (s);

  if (fd < 0)
    return vlib_usb_error (-1, 0, "unable to open USB device %u/%u", busnum,
			   devnum);

  if ((rv = ioctl (fd, USBDEVFS_CONNINFO_EX (sizeof (ci)), &ci)) < 0)
    return vlib_usb_error (-1, rv, "ioctl (USBDEVFS_CONNINFO_EX) failed");

  pool_get_zero (devices, d);
  d->fd = fd;
  d->busnum = ci.busnum;
  d->path = format (0, "%u-%u", ci.busnum, ci.ports[0]);
  for (int i = 1; i < ci.num_ports; i++)
    d->path = format (d->path, ".%u", ci.ports[i]);

  dhp[0] = dh = d - devices;
  log_debug (dh, "open: dev_handle %u speed %d", dh, ci.speed);

  d->clib_file_index = clib_file_add (
    &file_main,
    &(clib_file_t){ .private_data = dh,
		    .description = format (0, "USB device %v", d->path),
		    .file_descriptor = fd,
		    .error_function = linux_usb_error_ready,
		    .read_function = linux_usb_read_ready,
		    .write_function = linux_usb_write_ready,
		    .flags = UNIX_FILE_DATA_AVAILABLE_TO_WRITE });

  do
    {
      rv = read (fd, buffer, sizeof (buffer));
      if (rv > 0)
	vec_add (s, buffer, rv);
    }
  while (rv == sizeof (buffer));

  d->device_desc = vlib_usb_create_desc_tree (buffer, rv);
  vec_free (s);

  d->ctrl_xfer = linux_usb_xfer_alloc (d, 64);

  log_debug (dh, "%U", format_vlib_usb_desc_tree, d->device_desc);
  return 0;
}

clib_error_t *
vlib_usb_device_open_by_bus_and_ports (vlib_main_t *vm, u8 busnum, u8 *ports,
				       u8 n_ports, vlib_usb_dev_handle_t *dhp)
{
  clib_error_t *err;
  u32 devnum;
  u8 *path;
  path = format (0, SYSFS_PREFIX "%u-%u", busnum, ports[0]);
  for (int i = 1; i < n_ports; i++)
    path = format (path, ".%u", ports[i]);
  path = format (path, "/devnum%c", 0);
  err = clib_sysfs_read ((char *) path, "%u", &devnum);
  vec_free (path);
  if (err)
    return err;
  return vlib_usb_device_open_by_bus_and_device (vm, busnum, devnum, dhp);
}

void
vlib_usb_device_close (vlib_main_t *vm, vlib_usb_dev_handle_t dh)
{
  linux_usb_device_t *d;
  if (pool_is_free_index (devices, dh))
    return;

  d = pool_elt_at_index (devices, dh);
  linux_usb_xfer_free (d->ctrl_xfer);
  close (d->fd);
  vec_free (d->path);
  vlib_usb_desc_free_with_childs (d->device_desc);
  pool_put_index (devices, dh);
}

clib_error_t *
vlib_usb_claim_interface (vlib_main_t *vm, vlib_usb_dev_handle_t dh, u8 ifnum)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);

  log_debug (dh, "set_claim_interface: interface %u", ifnum);

  int rv2 = ioctl (d->fd, USBDEVFS_DISCONNECT_CLAIM,
		   &(struct usbdevfs_disconnect_claim){ .interface = ifnum });
  if (rv2 < 0)
    return vlib_usb_error (dh, rv2, "ioctl(USBDEVFS_DISCONNECT) failed");

  int rv = ioctl (d->fd, USBDEVFS_CLAIMINTERFACE, &(unsigned int){ ifnum });
  if (rv < 0)
    return vlib_usb_error (dh, rv, "ioctl(USBDEVFS_CLAIMINTERFACE) failed");
  return 0;
}

clib_error_t *
vlib_usb_set_interface_altsetting (vlib_main_t *vm, vlib_usb_dev_handle_t dh,
				   u8 ifnum, u8 altsetting)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);

  log_debug (dh, "set_interface_altsetting: interface %u altsetting %u", ifnum,
	     altsetting);

  int rv = ioctl (d->fd, USBDEVFS_SETINTERFACE,
		  &(struct usbdevfs_setinterface){ .interface = ifnum,
						   .altsetting = altsetting });
  if (rv < 0)
    return vlib_usb_error (dh, rv, "ioctl(USBDEVFS_SETINTERFACE) failed");
  return 0;
}

int
vlib_usb_get_dev_desc (vlib_usb_dev_handle_t dh, u8 desc_type, u8 desc_index,
		       void *data, u16 len)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
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
vlib_usb_ctrl_xfer (vlib_main_t *vm, vlib_usb_dev_handle_t dh,
		    vlib_usb_ctrl_xfer_t *xfer)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
  int rv;
  struct usbdevfs_ctrltransfer ct = {
    .bRequestType = xfer->req.bmRequestType,
    .bRequest = xfer->req.bRequest,
    .wValue = xfer->req.wValue,
    .wIndex = xfer->req.wIndex,
    .wLength = xfer->req.wLength,
    .timeout = xfer->timeout != 0 ? (u32) (xfer->timeout * 1000) : 200,
    .data = xfer->data,
  };

  if ((rv = ioctl (d->fd, USBDEVFS_CONTROL, &ct)) < 0)
    {
      vlib_usb_error (dh, rv, "ioctl(USBDEVFS_CONTROL) failed");
      return clib_error_return (0, "ioctl(USBDEVFS_CONTROL) failed [errno %d]",
				errno);
    }

  xfer->bytes_received = rv;

  return 0;
}

clib_error_t *
vlib_usb_get_active_config (vlib_main_t *vm, vlib_usb_dev_handle_t dh,
			    u8 *active_config)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
  clib_error_t *err;
  u8 *path;
  u32 v;

  path = format (0, SYSFS_PREFIX "%v/bConfigurationValue%c", d->path, 0);
  err = clib_sysfs_read ((char *) path, "%u", &v);
  vec_free (path);
  if (err)
    return err;
  *active_config = v;
  log_debug (dh, "get_active_config: %u", v);

  return 0;
}

clib_error_t *
vlib_usb_set_active_config (vlib_main_t *vm, vlib_usb_dev_handle_t dh,
			    u8 active_config)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
  clib_error_t *err;
  u8 *path;

  log_debug (dh, "set_active_config: %u", active_config);

  path = format (0, SYSFS_PREFIX "%v/bConfigurationValue%c", d->path, 0);
  err = clib_sysfs_write ((char *) path, "%u", active_config);
  vec_free (path);
  if (err)
    return err;
  return 0;
}

u8 *
vlib_usb_get_string_desc (vlib_usb_dev_handle_t dh, u8 desc_idx)
{
  clib_error_t *err;
  vlib_main_t *vm = vlib_get_main ();
  u8 *s = 0;

  struct
  {
    vlib_usb_string_descriptor_t desc;
    u16 wchars[126];
  } data;

  vlib_usb_ctrl_xfer_t xfer = {
    .req = { .bmRequestType = VLIB_USB_REQ_TYPE_STANDARD_DEVICE_IN,
	     .bRequest = USB_REQ_GET_DESCRIPTOR,
	     .wValue = VLIB_USB_DT_STRING << 8 | desc_idx,
	     .wLength = sizeof (data) },
    .data = &data
  };

  err = vlib_usb_ctrl_xfer (vm, dh, &xfer);

  if (err)
    {
      log_err (dh, "%U", format_clib_error, err);
      clib_error_free (err);
      return 0;
    }

  if (xfer.bytes_received > sizeof (vlib_usb_string_descriptor_t) + 2)
    {
      u16 n = xfer.bytes_received - sizeof (vlib_usb_string_descriptor_t);
      for (u16 i = 0; i < (n >> 1); i++)
	vec_add1 (s, data.wchars[i] > 255 ? '?' : data.wchars[i]);
    }

  return s;
}

clib_error_t *
vlib_usb_enable_interrupt (vlib_main_t *vm, vlib_usb_dev_handle_t dh, u8 ep,
			   vlib_usb_interrupt_config_t *cfg)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
  linux_usb_xfer_t *xfer = linux_usb_xfer_alloc (d, 32);
  int rv;

  xfer->urb.type = USBDEVFS_URB_TYPE_INTERRUPT;
  xfer->urb.endpoint = ep;
  xfer->dev_handle = dh;
  xfer->completion.ep = ep;
  xfer->completion.user_data = cfg->user_data;
  xfer->callback_fn = cfg->callback_fn;
  xfer->rearm = 1;

  log_warn (dh, "urb %U", format_hexdump, &xfer->urb, sizeof (xfer->urb));
  rv = ioctl (d->fd, USBDEVFS_SUBMITURB, &xfer->urb);
  log_notice (dh, "USBDEVFS_SUBMITURB %p rv %d", xfer, rv);

  return 0;
}

clib_error_t *
vlib_usb_disable_interrupt (vlib_main_t *vm, vlib_usb_dev_handle_t dh, u8 ep)
{
  return 0;
}
