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

VLIB_REGISTER_LOG_CLASS (usbnet_dev, static) = {
  .class_name = "usbnet",
  .subclass_name = "device",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define USB_TIMEOUT 1000

#define log_debug(d, fmt, ...)                                                \
  vlib_log_debug (usbnet_dev.class, "%s[%u/%u]: " fmt, __func__, d->busnum,   \
		  d->devnum, __VA_ARGS__)
#define log_notice(d, fmt, ...)                                               \
  vlib_log_notice (usbnet_dev.class, "[%u/%u]: " fmt, d->busnum, d->devnum,   \
		   __VA_ARGS__)
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

#if 0
  struct usbdevfs_ctrltransfer ct = {
    .bRequestType = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
    .bRequest = req,
    .wValue = 0,
    .wIndex = ud->ctrl_if,
    .data = data,
    .wLength = len,
    .timeout = 200,
  };

  //rv = ioctl (ud->usbdev->fd, USBDEVFS_CONTROL, &ct);
  //fformat (stderr, "rv %d len %u\n", rv, ct.wLength);
#endif

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

  vlib_usb_device_close (vm, ud->dh);

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

static void
string_to_mac_addr (u8 mac_addr[6], u8 *s)
{
  u8 d = 0;
  for (int i = 0; i < 12; i++)
    {
      u8 c = s[i];
      if (c >= '0' && c <= '9')
	c -= '0';
      else if (c >= 'a' && c <= 'f')
	c -= 'a' - 10;
      else if (c >= 'A' && c <= 'F')
	c -= 'A' - 10;
      else
	c = 0;

      d = 16 * d + c;
      if (i % 2)
	{
	  mac_addr[i / 2] = d;
	  d = 0;
	}
    }
}

clib_error_t *
usbnet_create_if (vlib_main_t *vm, usbnet_create_if_args_t *args)
{
  usbnet_main_t *um = &usbnet_main;
  usbnet_dev_t *ud, **udp;
  vlib_usb_desc_t *dd;
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

  if ((err = vlib_usb_device_open_by_bus_and_device (vm, args->busnum,
						     args->devnum, &ud->dh)))
    goto done;

  dd = vlib_usb_get_device_desc (ud->dh);

  log_debug (ud, "%U", format_usb_desc, &dd);
  log_debug (ud, "iManufacturer '%U' iProduct '%U' iSerialNumber '%U'",
	     format_vlib_usb_string_desc, ud->dh, dd->device.iManufacturer,
	     format_vlib_usb_string_desc, ud->dh, dd->device.iProduct,
	     format_vlib_usb_string_desc, ud->dh, dd->device.iSerialNumber);

  foreach_vlib_usb_desc (d, dd)
    {
      usbnet_device_type_t type = USBNET_DEV_TYPE_UNKNOWN;

      if ((d->hdr.bDescriptorType != USB_DT_INTERFACE) ||
	  (d->interface.bInterfaceClass != USB_CLASS_COMM))
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
  if (dd->device.bNumConfigurations > 1)
    {
      u8 active_config = 2;

      ue = vlib_usb_claim_interface (vm, ud->dh, 0);
      if (ue)
	ERR_DONE (VNET_ERR_INIT_FAILED, "Unable to claim interface 0: %U",
		  format_clib_error, ue);

      ue = vlib_usb_get_active_config (vm, ud->dh, &active_config);
      if (ue)
	ERR_DONE (VNET_ERR_INIT_FAILED,
		  "Unable to get USB active configuration: %U",
		  format_clib_error, ue);

      if (active_config != required_config)
	{
	  log_notice (ud, "Changing active usb configuration from %u to %u",
		      active_config, required_config);

	  ue = vlib_usb_set_active_config (vm, ud->dh, required_config);
	  if (ue)
	    ERR_DONE (VNET_ERR_INIT_FAILED,
		      "Unable to set USB active configuration: %U",
		      format_clib_error, ue);
	}
    }

  ue = vlib_usb_claim_interface (vm, ud->dh,
				 ctrl_desc->interface.bInterfaceNumber);
  if (ue)
    ERR_DONE (VNET_ERR_INIT_FAILED, "Unable to claim control interface %u: %U",
	      ctrl_desc->interface.bInterfaceNumber, format_clib_error, ue);

  if (ud->type == USBNET_DEV_TYPE_CDC_ECM ||
      ud->type == USBNET_DEV_TYPE_CDC_MBIM)
    {
      usb_cdc_header_desc_t *header_desc = 0;
      usb_cdc_union_desc_t *union_desc = 0;
      usb_cdc_ethernet_desc_t *eth_desc = 0;
      usb_cdc_mbim_func_desc_t *mbim_func_desc = 0;
      usb_cdc_mbim_ext_func_desc_t *mbim_ext_func_desc = 0;

      for (vlib_usb_desc_t *d = ctrl_desc->child; d->next; d = d->next)
	{
	  u8 subtype = d->cs_interface.bDescriptorSubtype;
	  if (d->hdr.bDescriptorType == USB_CDC_DESC_TYPE_CS_INTERFACE)
	    {
	      if (subtype == USB_CDC_DESC_SUBTYPE_HEADER)
		header_desc = (typeof (header_desc)) d->desc;
	      else if (subtype == USB_CDC_DESC_SUBTYPE_UNION)
		union_desc = (typeof (union_desc)) d->desc;
	      else if (subtype == USB_CDC_DESC_SUBTYPE_ETHERNET)
		eth_desc = (typeof (eth_desc)) d->desc;
	      else if (subtype == USB_CDC_DESC_SUBTYPE_MBIM_FUNC)
		mbim_func_desc = (typeof (mbim_func_desc)) d->desc;
	      else if (subtype == USB_CDC_DESC_SUBTYPE_MBIM_EXT_FUNC)
		mbim_ext_func_desc = (typeof (mbim_ext_func_desc)) d->desc;
	    }

	  log_debug (ud, "%U", format_usb_desc, &d->desc);
	}

      if (header_desc == 0 || union_desc == 0)
	ERR_DONE (VNET_ERR_UNSUPPORTED,
		  "Cannot find CDC header and/or union descriptor");
      log_debug (ud, "%U", format_usb_desc, header_desc);
      if (header_desc->bcdCDC != 0x0110)
	ERR_DONE (VNET_ERR_UNSUPPORTED, "Unsupported CDC version");
      log_debug (ud, "%U", format_usb_desc, union_desc);

      ud->ctrl_if = union_desc->bControlInterface;
      ud->data_if = union_desc->bSubordinateInterface[0];

      if (eth_desc)
	{
	  log_debug (ud, "%U", format_usb_desc, eth_desc);
	  u8 *s = vlib_usb_get_string_desc (ud->dh, eth_desc->iMACAddress);
	  if (vec_len (s) != 12)
	    {
	      vec_free (s);
	      ERR_DONE (VNET_ERR_INVALID_VALUE,
			"Unable to retrieve MAC address");
	    }
	  else
	    {
	      string_to_mac_addr (ud->mac_addr, s);
	      vec_free (s);
	    }
	  log_debug (ud, "iMACAddress %U", format_ethernet_address,
		     ud->mac_addr);
	}
      if (mbim_func_desc)
	log_debug (ud, "%U", format_usb_desc, mbim_func_desc);

      if (mbim_ext_func_desc)
	log_debug (ud, "%U", format_usb_desc, mbim_ext_func_desc);
    }

  if (ud->type == USBNET_DEV_TYPE_CDC_MBIM)
    {
      cdc_ncm_ntb_parameters_t ntb_param;
      if ((err = usbnet_ctrl_in (vm, ud, CDC_NCM_GET_NTB_PARAMETERS,
				 &ntb_param, sizeof (ntb_param))))
	goto done;

      log_debug (ud, "ntb_parameters: wNtbOutMaxDatagrams %u",
		 ntb_param.wNtbOutMaxDatagrams);
    }

  ue = vlib_usb_claim_interface (vm, ud->dh, 0);
  log_notice (ud, "claim %u rv %d", 0, format_clib_error, ue);

  ue = vlib_usb_enable_interrupt (
    vm, ud->dh, 0x81,
    &(vlib_usb_interrupt_config_t){
      .callback_fn = 0, .once = 1, .user_data.uword = 0x12345678 });

  vlib_usb_claim_interface (vm, ud->dh, 1);
  vlib_usb_set_interface_altsetting (vm, ud->dh, 1, 1);

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
  return err;
}

clib_error_t *
usbnet_delete_if (vlib_main_t *vm, u32 sw_if_index)
{
  return 0;
}
