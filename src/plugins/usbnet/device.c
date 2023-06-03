/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include "vnet/error.h"
#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include "vppinfra/pool.h"
#include <libusb-1.0/libusb.h>
#include <vlib/vlib.h>
#include <usbnet/usbnet.h>
#include <usbnet/usb_cdc.h>

VLIB_REGISTER_LOG_CLASS (usbnet_dev, static) = {
  .class_name = "usbnet",
  .subclass_name = "device",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(d, fmt, ...)                                                \
  vlib_log_debug (usbnet_dev.class, "%s[%u/%u]: " fmt, __func__, d->busnum,   \
		  d->devnum, __VA_ARGS__)
#define log_warn(d, fmt, ...)                                                 \
  vlib_log_warn (usbnet_dev.class, "[%u/%u]: " fmt, d->busnum, d->devnum,     \
		 __VA_ARGS__)
#define log_err(d, fmt, ...)                                                  \
  vlib_log_err (usbnet_dev.class, "[%u/%u]: " fmt, d->busnum, d->devnum,      \
		__VA_ARGS__)

usbnet_main_t usbnet_main;

clib_error_t *
usbnet_delete_if_internal (vlib_main_t *vm, usbnet_dev_t *ud)
{
  usbnet_main_t *um = &usbnet_main;

  if (ud->dev_is_open)
    libusb_close (ud->dh);

  pool_put_index (um->devices, ud->dev_index);
  clib_mem_free (ud);
  if (pool_elts (um->devices) == 0 && um->libusb_ctx)
    {
      libusb_exit (um->libusb_ctx);
      um->libusb_ctx = 0;
    }
  return 0;
}

static u8 *
format_libusb_string_desc (u8 *s, va_list *args)
{
  usbnet_dev_t *ud = va_arg (*args, usbnet_dev_t *);
  u8 desc_index = va_arg (*args, u32);
  u8 buffer[256];
  int rv;

  rv = libusb_get_string_descriptor_ascii (ud->dh, desc_index, buffer,
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

static int
usbnet_device_in_use (u8 busnum, u8 devnum)
{
  usbnet_main_t *um = &usbnet_main;
  usbnet_dev_t **udp;

  pool_foreach (udp, um->devices)
    if (udp[0]->busnum == busnum && udp[0]->devnum == devnum)
      return 1;
  return 0;
}

clib_error_t *
usbnet_create_if (vlib_main_t *vm, usbnet_create_if_args_t *args)
{
  usbnet_main_t *um = &usbnet_main;
  usbnet_dev_t *ud, **udp;
  libusb_device **list = 0, *dev = 0;
  struct libusb_config_descriptor *cd = 0, *acd;
  struct libusb_device_descriptor dd;
  const struct libusb_interface_descriptor *id;
  clib_error_t *err = 0;
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

  if (args->devnum && args->busnum &&
      usbnet_device_in_use (args->devnum, args->busnum))
    ERR_DONE (VNET_ERR_INSTANCE_IN_USE, "usb device %u/%u already in use",
	      args->busnum, args->devnum);

  for (u32 i = 0, n = rv; i < n; i++)
    {
      u8 busnum = libusb_get_bus_number (list[i]);
      u8 devnum = libusb_get_device_address (list[i]);

      if (libusb_get_device_descriptor (list[i], &dd) < 0)
	continue;

      if (args->devnum && args->busnum &&
	  (args->busnum != busnum || args->devnum != devnum))
	continue;

      if (args->vid && args->pid &&
	  (args->vid != dd.idVendor || args->pid != dd.idProduct))
	continue;

      if (usbnet_device_in_use (args->devnum, args->busnum))
	continue;

      ud->busnum = busnum;
      ud->devnum = devnum;
      dev = list[i];
    }

  if (dev == 0)
    {
      err = vnet_error (VNET_ERR_NO_SUCH_ENTRY, "USB device not found");
      goto done;
    }

  /* find supported configuration and device type */
  for (u8 cfg_index = 0; cfg_index < dd.bNumConfigurations; cfg_index++)
    {
      if (cd)
	{
	  libusb_free_config_descriptor (cd);
	  cd = 0;
	}

      if (libusb_get_config_descriptor (dev, cfg_index, &cd) < 0)
	{
	  log_warn (ud, "Unable to read USB configuration %u", cfg_index);
	  continue;
	}

      for (u32 k = 0; k < cd->bNumInterfaces; k++)
	{
	  id = cd->interface[k].altsetting;
	  usbnet_device_type_t type = 0;

	  if (id->bInterfaceClass != LIBUSB_CLASS_COMM)
	    continue;

	  if (id->bInterfaceSubClass == USB_CDC_SUBCLASS_ECM)
	    type = USBNET_DEV_TYPE_CDC_ECM;
	  else if (id->bInterfaceClass == USB_CDC_SUBCLASS_MBIM &&
		   id->bInterfaceProtocol == 0)
	    type = USBNET_DEV_TYPE_CDC_MBIM;

	  if (type > ud->type)
	    ud->type = type;
	}
    }

  if (ud->type == USBNET_DEV_TYPE_UNKNOWN)
    ERR_DONE (VNET_ERR_UNSUPPORTED, "unsupported device");

  if (libusb_get_active_config_descriptor (dev, &acd) < 0)
    ERR_DONE (VNET_ERR_SYSCALL_ERROR_4,
	      "Unable to read active USB configuration");

  if (acd->bConfigurationValue != cd->bConfigurationValue)
    {
      log_debug (ud, "configuration change needed (%u -> %u)",
		 cd->bConfigurationValue, acd->bConfigurationValue);

      for (int i = 0; i < acd->bNumInterfaces; i++)
	{
	  rv = libusb_detach_kernel_driver (
	    ud->dh, acd->interface[i].altsetting[0].bInterfaceNumber);
	  log_err (ud, "rv %d if %u\n", rv,
		   acd->interface[i].altsetting[0].bInterfaceNumber);
	}

      if ((rv = libusb_set_configuration (ud->dh, cd->bConfigurationValue)) <
	  0)
	ERR_DONE (VNET_ERR_INIT_FAILED,
		  "Unable to set USB active configuration: %s",
		  libusb_strerror (rv));
    }
  libusb_free_config_descriptor (acd);

  if ((rv = libusb_open (dev, &ud->dh)) < 0)
    ERR_DONE (VNET_ERR_SYSCALL_ERROR_2, "failed to open device: %s",
	      libusb_strerror (rv));
  ud->dev_is_open = 1;

  log_debug (ud, "manufacturer '%U' product '%U' serial '%U'",
	     format_libusb_string_desc, ud, dd.iManufacturer,
	     format_libusb_string_desc, ud, dd.iProduct,
	     format_libusb_string_desc, ud, dd.iSerialNumber);

  if (ud->type == USBNET_DEV_TYPE_CDC_ECM ||
      ud->type == USBNET_DEV_TYPE_CDC_MBIM)
    {
      usb_cdc_union_desc_t *union_desc = 0;
      usb_cdc_ethernet_desc_t *eth_desc = 0;
      usb_cdc_desc_hdr_t *h = (usb_cdc_desc_hdr_t *) id->extra;
      usb_cdc_header_desc_t *hdr_desc = (usb_cdc_header_desc_t *) h;
      int bytes_left = id->extra_length;

      if (id->extra_length == 0)
	ERR_DONE (VNET_ERR_INVALID_VALUE, "Missing CDC descriptors");

      if (hdr_desc->hdr.bDescriptorType == USB_CDC_DESC_TYPE_CS_INTERFACE &&
	  hdr_desc->hdr.bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_HEADER)
	log_debug (ud, "usb_cdc_header_desc: bcdCDC 0x%04x", hdr_desc->bcdCDC);
      else
	ERR_DONE (VNET_ERR_UNSUPPORTED,
		  "Failed to find CDC header descriptor");

      if (hdr_desc->bcdCDC != 0x0110)
	ERR_DONE (VNET_ERR_UNSUPPORTED, "Unsupported CDC version");

      bytes_left -= hdr_desc->hdr.bFunctionLength;
      h = (usb_cdc_desc_hdr_t *) ((u8 *) h + h->bFunctionLength);

      while (bytes_left > 0)
	{
	  if (h->bDescriptorType == USB_CDC_DESC_TYPE_CS_INTERFACE &&
	      h->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_UNION)
	    {
	      union_desc = (usb_cdc_union_desc_t *) h;
	      ud->ctrl_if = union_desc->bControlInterface;
	      ud->data_if = union_desc->bSubordinateInterface[0];
	      log_debug (ud,
			 "usb_cdc_union_desc: bControlInterface %u "
			 "bSubordinateInterface[0] %u",
			 union_desc->bControlInterface,
			 union_desc->bSubordinateInterface[0]);
	    }
	  else if (h->bDescriptorType == USB_CDC_DESC_TYPE_CS_INTERFACE &&
		   h->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_ETHERNET)
	    {
	      eth_desc = (usb_cdc_ethernet_desc_t *) h;
	      log_debug (ud,
			 "usb_cdc_ethernet_desc: wMaxSegmentSize %u "
			 "wNumberMCFilters %u iMACAddress %u "
			 "bNumberPowerFilters %u bmEthernetStatistics 0x%x",
			 eth_desc->wMaxSegmentSize, eth_desc->wNumberMCFilters,
			 eth_desc->iMACAddress, eth_desc->bNumberPowerFilters,
			 eth_desc->bmEthernetStatistics);
	    }
	  else
	    {
	      log_debug (ud,
			 "unknown interface descriptor: type 0x%02x subtype "
			 "0x%02x len %u data %U",
			 h->bDescriptorType, h->bDescriptorSubtype,
			 h->bFunctionLength, format_hex_bytes_no_wrap, h->data,
			 h->bFunctionLength - sizeof (*h));
	    }
	  bytes_left -= h->bFunctionLength;
	  h = (usb_cdc_desc_hdr_t *) ((u8 *) h + h->bFunctionLength);
	}

      if (!union_desc)
	ERR_DONE (VNET_ERR_UNSUPPORTED, "missing CDC union descriptor");
      if (ud->type == USBNET_DEV_TYPE_CDC_ECM)
	{
	  rv = 0;
	  if (eth_desc)
	    rv = libusb_get_string_descriptor (ud->dh, eth_desc->iMACAddress,
					       0, ud->mac_addr,
					       sizeof (ud->mac_addr));
	  if (rv != 6)
	    ERR_DONE (VNET_ERR_INVALID_VALUE,
		      "Unable to retrieve MAC address");
	}
    }

  if ((rv = libusb_set_auto_detach_kernel_driver (ud->dh, 1)) < 0)
    ERR_DONE (VNET_ERR_SYSCALL_ERROR_3,
	      "unable to enable auto detach of kernel driver",
	      libusb_strerror (rv));

#if 0
  if ((rv = libusb_control_transfer (ud->dh, LIBUSB_ENDPOINT_IN,
				     LIBUSB_REQUEST_GET_CONFIGURATION, 0, 0,
				     &active_configuration, 1, 1000)) != 1)
    ERR_DONE (VNET_ERR_INIT_FAILED,
	      "Unable to get USB active configuration: %s",
	      libusb_strerror (rv));
#endif

  log_debug (ud, "%04x:%04x name %v", args->vid, args->pid, args->name);

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
