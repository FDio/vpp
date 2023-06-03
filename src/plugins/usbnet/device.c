/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include "vnet/error.h"
#include "vppinfra/cache.h"
#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include "vppinfra/mem.h"
#include "vppinfra/pool.h"
#include "vppinfra/file.h"
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <usbnet/usbnet.h>
#include <vlib/usb/usb.h>
#include <vnet/ethernet/ethernet.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>

VLIB_REGISTER_LOG_CLASS (usbnet_dev, static) = {
  .class_name = "usbnet",
  .subclass_name = "device",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define USB_TIMEOUT 1000

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
usbnet_ctrl_in (vlib_main_t *vm, usbnet_dev_t *ud, u8 req, void *data, u16 len)
{
  int rv = 0;
  ASSERT (ud->ctrl_if_claimed);

  struct usbdevfs_ctrltransfer ct = {
    .bRequestType = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
    .bRequest = req,
    .wValue = 0,
    .wIndex = ud->ctrl_if,
    .data = data,
    .wLength = len,
    .timeout = 200,
  };

  rv = ioctl (ud->usbdev->fd, USBDEVFS_CONTROL, &ct);
  fformat (stderr, "rv %d len %u\n", rv, ct.wLength);

  if (rv < 0)
    return vnet_error (VNET_ERR_SYSCALL_ERROR_5, "usbnet_ctrl_in: %d", rv);
  return 0;
}

clib_error_t *
usbnet_delete_if_internal (vlib_main_t *vm, usbnet_dev_t *ud)
{
  usbnet_main_t *um = &usbnet_main;

  // if (ud->data_if_claimed) libusb_release_interface (ud->dh, ud->data_if);

  // if (ud->ctrl_if_claimed) libusb_release_interface (ud->dh, ud->ctrl_if);

  if (ud->usbdev)
    vlib_usb_device_close (vm, ud->usbdev);

  pool_put_index (um->devices, ud->dev_index);
  clib_mem_free (ud);
  return 0;
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
  struct usb_device_descriptor dd;
  vlib_usb_desc_tree_t *dt = 0;
  vlib_usb_desc_t *ctrl_desc = 0;
  clib_error_t *err = 0, *ue = 0;
  u8 required_config;

  pool_get (um->devices, udp);
  udp[0] = ud =
    clib_mem_alloc_aligned (sizeof (usbnet_dev_t), CLIB_CACHE_LINE_BYTES);
  clib_memset (ud, 0, sizeof (usbnet_dev_t));
  ud->dev_index = udp - um->devices;

  if (args->devnum && args->busnum &&
      usbnet_device_in_use (args->devnum, args->busnum))
    ERR_DONE (VNET_ERR_INSTANCE_IN_USE, "usb device %u/%u already in use",
	      args->busnum, args->devnum);

  if ((err = vlib_usb_device_open_by_bus_and_device (vm, args->busnum, args->devnum,
						&ud->usbdev)))
    goto done;

  vlib_usb_get_dev_desc (ud->usbdev, USB_DT_DEVICE, 0, &dd, sizeof (dd));

  log_debug (ud, "%U", format_usb_desc, &dd);
  log_debug (ud, "iManufacturer '%U' iProduct '%U' iSerialNumber '%U'",
	     format_vlib_usb_string_desc, ud->usbdev, dd.iManufacturer,
	     format_vlib_usb_string_desc, ud->usbdev, dd.iProduct,
	     format_vlib_usb_string_desc, ud->usbdev, dd.iSerialNumber);

  dt = vlib_usb_device_config_get (ud->usbdev);

  if (!ud)
    ERR_DONE (VNET_ERR_BUG, "xxxx");

  foreach_vlib_usb_desc_in_tree (d, dt, USB_DT_INTERFACE)
    {
      usbnet_device_type_t type = USBNET_DEV_TYPE_UNKNOWN;
      if (d->interface.bInterfaceClass != USB_CLASS_COMM)
	continue;

      if (d->interface.bInterfaceSubClass == USB_CDC_SUBCLASS_ECM)
	type = USBNET_DEV_TYPE_CDC_ECM;
      else if (d->interface.bInterfaceSubClass == USB_CDC_SUBCLASS_MBIM &&
	       d->interface.bInterfaceProtocol == 0)
	type = USBNET_DEV_TYPE_CDC_MBIM;

      if (type > ud->type)
	{
	  ud->type = type;
	  ASSERT (d->parent->hdr.bDescriptorType == USB_DT_CONFIG);
	  required_config = d->parent->config.bConfigurationValue;
	  ctrl_desc = d;
	}
    }

  if (ud->type == USBNET_DEV_TYPE_UNKNOWN)
    ERR_DONE (VNET_ERR_UNSUPPORTED, "unsupported device");

  /* Change active configuration if needed */
  if (dd.bNumConfigurations > 1)
    {
      u8 active_config;

      ue = vlib_usb_get_active_config (vm, ud->usbdev, &active_config);
      if (ue)
	ERR_DONE (VNET_ERR_INIT_FAILED,
		  "Unable to get USB active configuration: %U",
		  format_clib_error, ue);

      if (active_config != required_config)
	{
	  ue = vlib_usb_set_active_config (vm, ud->usbdev, required_config);
	  if (ue)
	    ERR_DONE (VNET_ERR_INIT_FAILED,
		      "Unable to set USB active configuration: %U",
		      format_clib_error, ue);
	}
    }

  if (ud->type == USBNET_DEV_TYPE_CDC_ECM ||
      ud->type == USBNET_DEV_TYPE_CDC_MBIM)
    {
      for (vlib_usb_desc_t *d = ctrl_desc->child; d->next; d = d->next)
	{
	  log_debug(ud, "%U", format_usb_desc, &d->desc);
	}
    }
#if 0
      usb_cdc_union_desc_t *union_desc = 0;
      usb_cdc_ethernet_desc_t *eth_desc = 0;
      usb_cdc_mbim_func_desc_t *mbim_func = 0;
      usb_cdc_mbim_ext_func_desc_t *mbim_ext_func = 0;
      usb_cdc_desc_hdr_t *h = (usb_cdc_desc_hdr_t *) ctrl_if_desc->extra;
      usb_cdc_header_desc_t *hdr_desc = (usb_cdc_header_desc_t *) h;
      int bytes_left = ctrl_if_desc->extra_length;

      if (bytes_left < sizeof (usb_cdc_header_desc_t) ||
	  hdr_desc->hdr.bDescriptorType != USB_CDC_DESC_TYPE_CS_INTERFACE ||
	  hdr_desc->hdr.bDescriptorSubtype != USB_CDC_DESC_SUBTYPE_HEADER)
	ERR_DONE (VNET_ERR_UNSUPPORTED, "Cannot find CDC header descriptor");

      log_debug (ud, "usb_cdc_header_desc: bcdCDC 0x%04x", hdr_desc->bcdCDC);

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
	      log_debug (ud, "\nusb_cdc_ethernet_desc:\n  %U",
			 format_usb_cdc_ethernet_desc, eth_desc);
	    }
	  else if (h->bDescriptorType == USB_CDC_DESC_TYPE_CS_INTERFACE &&
		   h->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_MBIM_FUNC)
	    {
	      mbim_func = (typeof (mbim_func)) h;
	      log_debug (ud, "\nusb_cdc_mbim_func_desc:\n  %U",
			 format_usb_cdc_mbim_func_desc, mbim_func);
	    }
	  else if (h->bDescriptorType == USB_CDC_DESC_TYPE_CS_INTERFACE &&
		   h->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_MBIM_EXT_FUNC)
	    {
	      mbim_ext_func = (typeof (mbim_ext_func)) h;
	      log_debug (ud, "\nusb_cdc_mbim_ext_func_desc:\n  %U",
			 format_usb_cdc_mbim_ext_func_desc, mbim_ext_func);
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
	  log_debug (ud, "iMACAddress %U", format_ethernet_address,
		     ud->mac_addr);
	}
    }

  /* find control interface interrupt endpoint */
  for (ep = ctrl_if_desc->endpoint;
       ep - ctrl_if_desc->endpoint < ctrl_if_desc->bNumEndpoints; ep++)
    {
      if ((ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) !=
	  LIBUSB_ENDPOINT_TRANSFER_TYPE_INTERRUPT)
	continue;

      ud->ctrl_int_ep = rv = ep->bEndpointAddress;
      log_debug (ud,
		 "ctrl interrupt bEndpointAddress 0x%02x wMaxPacketSize %u",
		 ep->bEndpointAddress, ep->wMaxPacketSize);
      break;
    }

  if (ep - ctrl_if_desc->endpoint == ctrl_if_desc->bNumEndpoints)
    ERR_DONE (VNET_ERR_SYSCALL_ERROR_3, "unable to find control interrupt EP");

  if ((rv = libusb_set_auto_detach_kernel_driver (ud->dh, 1)) < 0)
    ERR_DONE (VNET_ERR_SYSCALL_ERROR_3,
	      "unable to enable auto detach of kernel driver",
	      libusb_strerror (rv));

  if ((rv = libusb_claim_interface (ud->dh, ud->ctrl_if)) < 0)
    ERR_DONE (VNET_ERR_SYSCALL_ERROR_6,
	      "Unable to claim Control Interface: %s", libusb_strerror (rv));
  ud->ctrl_if_claimed = 1;

  if (ud->type == USBNET_DEV_TYPE_CDC_MBIM)
    {
      cdc_ncm_ntb_parameters_t ntb_param;
      if ((err = usbnet_ctrl_in (vm, ud, CDC_NCM_GET_NTB_PARAMETERS,
				 &ntb_param, sizeof (ntb_param))))
	goto done;

      log_debug (ud, "ntb_parameters: wNtbOutMaxDatagrams %u",
		 ntb_param.wNtbOutMaxDatagrams);
    }
#endif

done:
  if (ue)
    clib_error_free (ue);
  if (err)
    {
      log_err (ud, "%U", format_clib_error, err);
      if ((ue = usbnet_delete_if_internal (vm, ud)))
	{
	  log_err (ud, "%U", format_clib_error, ue);
	  clib_error_free (ue);
	}
    }
  vlib_usb_free_desc_tree (dt);
  return err;
}

clib_error_t *
usbnet_delete_if (vlib_main_t *vm, u32 sw_if_index)
{
  return 0;
}
