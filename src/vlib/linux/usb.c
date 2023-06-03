/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include "vppinfra/clib.h"
#include "vppinfra/pool.h"
#include <vlib/vlib.h>

#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>
#include <vlib/usb/usb.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>

VLIB_REGISTER_LOG_CLASS (usb_linux_dev, static) = {
  .class_name = "usb",
  .subclass_name = "linux",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define USB_TIMEOUT 1000

#define log_debug(dh, fmt, ...)                                               \
  vlib_log_debug (usb_linux_dev.class, "[%u] %s: " fmt, dh, __func__,         \
		  __VA_ARGS__)
#define log_notice(dh, fmt, ...)                                              \
  vlib_log_notice (usb_linux_dev.class, "[%u]: " fmt, dh, __VA_ARGS__)
#define log_warn(dh, fmt, ...)                                                \
  vlib_log_warn (usb_linux_dev.class, "[%u]: " fmt, dh, __VA_ARGS__)
#define log_err(dh, fmt, ...)                                                 \
  vlib_log_err (usb_linux_dev.class, "[%u]: " fmt, dh, __VA_ARGS__)

typedef struct
{
  int fd;
} linux_usb_device_t;

linux_usb_device_t *devices = 0; /* pool of active usb devices */

clib_error_t *
vlib_usb_device_open_by_bus_and_device (vlib_main_t *vm, u8 busnum, u8 devnum,
					vlib_usb_dev_handle_t *dhp)
{
  u8 *fmt = 0;
  int fd;
  linux_usb_device_t *d;

  fmt = format (fmt, "/dev/bus/usb/%03u/%03u%c", busnum, devnum, 0);

  fd = open ((char *) fmt, O_RDWR);
  vec_free (fmt);

  if (fd < 0)
    return clib_error_return_unix (0, "unable to open USB device %u/%u",
				   busnum, devnum);

  pool_get_zero (devices, d);
  d->fd = fd;

  dhp[0] = d - devices;
  return 0;
}

void
vlib_usb_device_close (vlib_main_t *vm, vlib_usb_dev_handle_t dh)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
  close (d->fd);
  pool_put_index (devices, dh);
}

clib_error_t *
vlib_usb_claim_interface (vlib_main_t *vm, vlib_usb_dev_handle_t dh, u8 ifnum)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
  int rv = ioctl (d->fd, USBDEVFS_CLAIMINTERFACE, &(unsigned int){ ifnum });
  if (rv < 0)
    return clib_error_return (
      0, "ioctl(USBDEVFS_CLAIMINTERFACE) failed [errno = %d]", rv);
  return 0;
}

clib_error_t *
vlib_usb_set_interface_altsetting (vlib_main_t *vm, vlib_usb_dev_handle_t dh,
				   u8 ifnum, u8 altsetting)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
  int rv = ioctl (d->fd, USBDEVFS_SETINTERFACE,
		  &(struct usbdevfs_setinterface){ .interface = ifnum,
						   .altsetting = altsetting });
  if (rv < 0)
    return clib_error_return (
      0, "ioctl(USBDEVFS_SETINTERFACE) failed [errno = %d]", rv);
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
vlib_usb_get_active_config (vlib_main_t *vm, vlib_usb_dev_handle_t dh,
			    u8 *active_config)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
  u8 v = 0;
  int rv;
  struct usbdevfs_ctrltransfer ct = {
    .bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
    .bRequest = USB_REQ_GET_CONFIGURATION,
    .wValue = 0,
    .wIndex = 0,
    .data = &v,
    .wLength = 1,
    .timeout = 200,
  };

  if ((rv = ioctl (d->fd, USBDEVFS_CONTROL, &ct)) < 1)
    return clib_error_return (0, "ioctl(USBDEVFS_CONTROL) failed [rv %d]", rv);
  *active_config = v;
  return 0;
}

clib_error_t *
vlib_usb_set_active_config (vlib_main_t *vm, vlib_usb_dev_handle_t dh,
			    u8 active_config)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
  unsigned int v = active_config;
  int rv;
  if ((rv = ioctl (d->fd, USBDEVFS_SETCONFIGURATION, &v)) < 0)
    return clib_error_return (
      0, "ioctl(USBDEVFS_SETCONFIGURATION) failed [rv %d]", rv);
  return 0;
}

int
vlib_usb_get_if_desc (vlib_usb_dev_handle_t dh, u8 desc_type, u8 desc_index,
		      void *data, u16 len)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);
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
vlib_usb_get_string_desc (vlib_usb_dev_handle_t dh, u8 desc_idx)
{
  u8 *s = 0;
  int len;
  struct
  {
    struct usb_string_descriptor desc;
    u16 buffer[USB_MAX_STRING_LEN - 1];
  } data;

  if ((len = vlib_usb_get_dev_desc (dh, USB_DT_STRING, desc_idx, &data, 255)) <
      4)
    return 0;

  for (u16 *wc = data.desc.wData; (u8 *) wc - (u8 *) &data < len; wc++)
    vec_add1 (s, wc[0] > 255 ? '.' : wc[0]);

  return s;
}

static int signum = 0;

u8 data[1024] = {};

typedef struct
{
  vlib_usb_dev_handle_t dev_handle;
  int pipefd;
  int devfd;

  struct usbdevfs_urb urb;
} my_urb_t;

typedef struct
{
  my_urb_t *urb;
  int si_code;
} my_pipe_msg_t;

my_urb_t myurb = { .urb = {
		     .type = USBDEVFS_URB_TYPE_INTERRUPT,
		     .endpoint = 0x81,
		     .buffer = data,
		     .buffer_length = 8,
		   } };

void
vlib_usb_signal_handler (int signum, siginfo_t *info, void *context)
{
  my_urb_t *urb =
    (my_urb_t *) ((u8 *) info->si_addr - STRUCT_OFFSET_OF (my_urb_t, urb));

  // my_pipe_msg_t msg = { .urb = urb, .si_code = info->si_code };

  fprintf (
    stderr, "SSSSSSSS signum %d si_code %d si_signo %d si_addr %pfd %d\n",
    signum, info->si_code, info->si_signo, info->si_addr, urb->dev_handle);

  // int rv = write (urb->pipefd, &msg, sizeof (msg));
  // fprintf (stderr, "SSSSSSSS rv %d\n", rv);
}

clib_error_t *
vlib_usb_enable_interrupt (vlib_main_t *vm, vlib_usb_dev_handle_t dh, u8 ep,
			   vlib_usb_interrupt_config_t *cfg)
{
  linux_usb_device_t *d = pool_elt_at_index (devices, dh);

  if (signum == 0)
    {
      int rv;
      struct sigaction sigact;

      signum = SIGRTMIN + 7;

      sigemptyset (&sigact.sa_mask);
      sigact.sa_sigaction = vlib_usb_signal_handler;
      sigact.sa_flags = SA_SIGINFO;
      sigact.sa_restorer = 0;
      rv = sigaction (signum, &sigact, NULL);
      log_notice (dh, "sigaction signum %d rv %d", signum, rv);
    }

  myurb.urb.signr = signum;
  myurb.urb.endpoint = ep;
  myurb.dev_handle = dh;

  int rv;
  rv = ioctl (d->fd, USBDEVFS_SUBMITURB, &myurb.urb);
  log_notice (dh, "USBDEVFS_SUBMITURB %p rv %d", &myurb, rv);

  return 0;
}

clib_error_t *
vlib_usb_disable_interrupt (vlib_main_t *vm, vlib_usb_dev_handle_t dh, u8 ep)
{
  return 0;
}
