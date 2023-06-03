/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include "vnet/error.h"
#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include "vppinfra/pool.h"
#include <vlib/vlib.h>
#include <usbnet/usbnet.h>
#include <usbnet/usb_cdc.h>

VLIB_REGISTER_LOG_CLASS (usbnet_dev, static) = {
  .class_name = "usbnet",
  .subclass_name = "device",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(d, fmt, ...)                                                \
  vlib_log_debug (usbnet_dev.class, "%s[%03u:%03u]: " fmt, __func__,          \
		  d->busnum, d->devaddr, __VA_ARGS__)
#define log_err(d, fmt, ...)                                                  \
  vlib_log_err (usbnet_dev.class, "[%03u:%03u]: " fmt, d->busnum, d->devaddr, \
		__VA_ARGS__)

usbnet_main_t usbnet_main;

clib_error_t *
usbnet_delete_if_internal (vlib_main_t *vm, usbnet_dev_t *ud)
{
  usbnet_main_t *um = &usbnet_main;

  pool_put_index (um->devices, ud->dev_index);
  clib_mem_free (ud);
  if (pool_elts (um->devices) == 0 && um->libusb_ctx)
    {
      libusb_exit (um->libusb_ctx);
      um->libusb_ctx = 0;
    }
  return 0;
}

u8 *
format_libusb_string_desc (u8 *s, va_list *args)
{
  libusb_device_handle *dh = va_arg (*args, libusb_device_handle *);
  u8 desc_index = va_arg (*args, u32);
  u8 buffer[256];
  int rv;

  rv = libusb_get_string_descriptor_ascii (dh, desc_index, buffer,
					   sizeof (buffer));
  if (rv > 0)
    s = format (s, "%s", buffer);
  return s;
}

#define ERR_DONE(e, ...)                                                      \
  {                                                                           \
    err = vnet_error (e, __VA_ARGS__);                                        \
    goto done;                                                                \
  }

clib_error_t *
usbnet_create_if (vlib_main_t *vm, usbnet_create_if_args_t *args)
{
  usbnet_main_t *um = &usbnet_main;
  usbnet_dev_t *ud, **udp;
  libusb_device **list = 0, *found = 0;
  struct libusb_config_descriptor *cd = 0;
  clib_error_t *err = 0;
  u8 active_configuration;
  int rv;

  pool_get (um->devices, udp);
  udp[0] = ud =
    clib_mem_alloc_aligned (sizeof (usbnet_dev_t), CLIB_CACHE_LINE_BYTES);
  clib_memset (ud, 0, sizeof (usbnet_dev_t));
  ud->dev_index = udp - um->devices;

  if (um->libusb_ctx == 0 && (rv = libusb_init (&um->libusb_ctx)) < 0)
    ERR_DONE (VNET_ERR_INIT_FAILED, "Failed to init libusb: %s",
	      libusb_strerror (rv));

  if ((rv = libusb_get_device_list (um->libusb_ctx, &list)) < 0)
    ERR_DONE (VNET_ERR_SYSCALL_ERROR_1,
	      "Failed to obtain list of USB devices: %s",
	      libusb_strerror (rv));

  struct libusb_device_descriptor dd;
  const struct libusb_interface_descriptor *id;

  for (u32 i = 0, n = rv; i < n; i++)
    {
      ud->busnum = libusb_get_bus_number (list[i]);
      ud->devaddr = libusb_get_device_address (list[i]);
      rv = libusb_get_device_descriptor (list[i], &dd);
      for (u32 j = 0; j < dd.bNumConfigurations; j++)
	{
	  if (cd)
	    {
	      libusb_free_config_descriptor (cd);
	      cd = 0;
	    }

	  if (libusb_get_config_descriptor (list[i], j, &cd) >= 0)
	    {
	      for (u32 k = 0; k < cd->bNumInterfaces; k++)
		{
		  id = cd->interface[k].altsetting;

		  if (id->bInterfaceClass != LIBUSB_CLASS_COMM)
		    continue;

		  found = list[i];
		  goto found;
		}
	    }
	}
    }
found:

  if (found == 0)
    {
      err = vnet_error (VNET_ERR_NO_SUCH_ENTRY, "USB device not found");
      goto done;
    }

  if (id->extra_length)
    {
      usb_cdc_desc_hdr_t *h = (usb_cdc_desc_hdr_t *) id->extra;
      int bytes_left = id->extra_length;
      u16 cdc_ver = 0;

      while (bytes_left > 0)
	{
	  if (h->bDescriptorType == 0x24 &&
	      h->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_HEADER)
	    {
	      usb_cdc_heder_desc_t *d = (usb_cdc_heder_desc_t *) h;
	      cdc_ver = d->bcdCDC;
	    }
	  else
	    {
	      log_debug (ud,
			 "unknown interface descriptor: type 0x%02x subtype "
			 "0x%02x len %u data %U",
			 h->bDescriptorType, h->bDescriptorSubtype,
			 h->bFunctionLength, format_hexdump, h->data,
			 h->bFunctionLength - sizeof (*h));
	    }
	  bytes_left -= h->bFunctionLength;
	  h = (usb_cdc_desc_hdr_t *) ((u8 *) h + h->bFunctionLength);
	}

      if (cdc_ver != 0x0110)
	ERR_DONE (VNET_ERR_UNSUPPORTED, "Unsupported CDC version");
    }
  else
    ERR_DONE (VNET_ERR_INVALID_VALUE, "Missing CDC descriptors");

  if ((rv = libusb_open (found, &ud->dh)) < 0)
    ERR_DONE (VNET_ERR_SYSCALL_ERROR_2, "failed to open device: %s",
	      libusb_strerror (rv));

  if ((rv = libusb_set_auto_detach_kernel_driver (ud->dh, 1)) < 0)
    ERR_DONE (VNET_ERR_SYSCALL_ERROR_3,
	      "Unable to enable auto-detach Interface: %s",
	      libusb_strerror (rv));

  if ((rv = libusb_control_transfer (ud->dh, LIBUSB_ENDPOINT_IN,
				     LIBUSB_REQUEST_GET_CONFIGURATION, 0, 0,
				     &active_configuration, 1, 1000)) != 1)
    ERR_DONE (VNET_ERR_INIT_FAILED,
	      "Unable to get USB active configuration: %s",
	      libusb_strerror (rv));

  log_debug (ud, "cfg %u if %u subclass %u prot %u active_cfg %u",
	     cd->bConfigurationValue, id->bInterfaceNumber,
	     id->bInterfaceSubClass, id->bInterfaceProtocol,
	     active_configuration);

  if (cd->bConfigurationValue != active_configuration)
    {
      struct libusb_config_descriptor *acd;
      libusb_get_active_config_descriptor (found, &acd);
      for (int i = 0; i < acd->bNumInterfaces; i++)
	{
	  rv = libusb_detach_kernel_driver (
	    ud->dh, acd->interface[i].altsetting[0].bInterfaceNumber);
	  log_err (ud, "rv %d if %u\n", rv,
		   acd->interface[i].altsetting[0].bInterfaceNumber);
	}
      libusb_free_config_descriptor (acd);

      if ((rv = libusb_set_configuration (ud->dh, cd->bConfigurationValue)) <
	  0)
	ERR_DONE (VNET_ERR_INIT_FAILED,
		  "Unable to set USB active configuration: %s",
		  libusb_strerror (rv));
    }

  log_debug (ud, "%04x:%04x name %v", args->vid, args->pid, args->name);

#if 0
  log_debug (ud, "manufacturer '%U' product '%U' serial '%U'",
	     format_libusb_string_desc, dh, d.iManufacturer,
	     format_libusb_string_desc, dh, d.iProduct,
	     format_libusb_string_desc, dh, d.iSerialNumber);
#endif

done:
  if (list)
    libusb_free_device_list (list, 1);
  if (cd)
    libusb_free_config_descriptor (cd);

  if (err)
    {
      clib_error_t *err2;
      log_err (ud, "%U", format_clib_error, err);
      if ((err2 = usbnet_delete_if_internal (vm, ud)))
	{
	  log_err (ud, "%U", format_clib_error, err2);
	  clib_error_free (err2);
	}
    }
  return err;
}

clib_error_t *
usbnet_delete_if (vlib_main_t *vm, u32 sw_if_index)
{
  return 0;
}
