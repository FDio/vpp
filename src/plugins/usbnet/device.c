/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include "vlib/usb/usb_descriptors.h"
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
  vlib_usb_dev_handle_t dh;
  vlib_usb_desc_t *device_desc, *ctrl_desc = 0;
  clib_error_t *err = 0, *ue = 0;
  u8 required_config;

  pool_get (um->devices, udp);
  ud = clib_mem_alloc_aligned (sizeof (usbnet_dev_t), CLIB_CACHE_LINE_BYTES);
  clib_memset (ud, 0, sizeof (usbnet_dev_t));
  udp[0] = ud;
  ud->dev_index = udp - um->devices;

  if (args->devnum && args->busnum &&
      usbnet_device_in_use (args->devnum, args->busnum))
    ERR_DONE (VNET_ERR_INSTANCE_IN_USE, "usb device %u/%u already in use",
	      args->busnum, args->devnum);

  if (args->n_ports)
    {
      if ((ue = vlib_usb_device_open_by_bus_and_ports (
	     vm, args->busnum, args->ports, args->n_ports, &dh)))
	goto done;
    }
  else
    {
      if ((ue = vlib_usb_device_open_by_bus_and_device (vm, args->busnum,
							args->devnum, &dh)))
	goto done;
    }

  ud->dh = dh;

  device_desc = vlib_usb_get_device_desc (dh);
  __builtin_dump_struct (device_desc, &printf);

  log_debug (ud, "%U", format_usb_desc, device_desc->desc);
  log_debug (ud, "iManufacturer '%U' iProduct '%U' iSerialNumber '%U'",
	     format_vlib_usb_string_desc, dh,
	     device_desc->device.iManufacturer, format_vlib_usb_string_desc,
	     dh, device_desc->device.iProduct, format_vlib_usb_string_desc, dh,
	     device_desc->device.iSerialNumber);

  foreach_vlib_usb_child_desc (d, device_desc)
    {
      usbnet_device_type_t type = USBNET_DEV_TYPE_UNKNOWN;

      if ((d->hdr.bDescriptorType != VLIB_USB_DT_INTERFACE) ||
	  (d->interface.bInterfaceClass != VLIB_USB_CLASS_COMM))
	continue;

      if (d->interface.bInterfaceSubClass == USB_CDC_SUBCLASS_ECM)
	type = USBNET_DEV_TYPE_CDC_ECM;
      else if (d->interface.bInterfaceSubClass == USB_CDC_SUBCLASS_MBIM &&
	       d->interface.bInterfaceProtocol == 0)
	type = USBNET_DEV_TYPE_CDC_MBIM;

      if (type > ud->type)
	{
	  ud->type = type;
	  ASSERT (d->parent->hdr.bDescriptorType == VLIB_USB_DT_CONFIG);
	  required_config = d->parent->config.bConfigurationValue;
	  ctrl_desc = d;
	}
    }

  if (ud->type == USBNET_DEV_TYPE_UNKNOWN)
    ERR_DONE (VNET_ERR_UNSUPPORTED, "unsupported device");

  /* Change active configuration if needed */
  if (device_desc->device.bNumConfigurations > 1)
    {
      u8 active_config = 2;

      if ((ue = vlib_usb_claim_interface (vm, dh, 0)))
	goto done;

      if ((ue = vlib_usb_get_active_config (vm, dh, &active_config)))
	goto done;

      if (active_config != required_config)
	{
	  log_notice (ud, "Changing active usb configuration from %u to %u",
		      active_config, required_config);

	  if ((ue = vlib_usb_set_active_config (vm, dh, required_config)))
	    goto done;
	}
    }

  if ((ue = vlib_usb_claim_interface (vm, dh,
				      ctrl_desc->interface.bInterfaceNumber)))
    goto done;

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
	  u8 *s = vlib_usb_get_string_desc (dh, eth_desc->iMACAddress);
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

  if ((ue = vlib_usb_claim_interface (vm, dh, ud->data_if)))
    goto done;

  if ((ue = vlib_usb_enable_interrupt (
	 vm, dh, 0x87,
	 &(vlib_usb_interrupt_config_t){
	   .callback_fn = 0, .once = 1, .user_data.uword = 0x12345678 })))
    goto done;

  if ((vlib_usb_set_interface_altsetting (vm, dh, ud->data_if, 1)))
    goto done;

  if (ud->type == USBNET_DEV_TYPE_CDC_MBIM)
    {
      cdc_ncm_ntb_parameters_t ntb_param;
      vlib_usb_ctrl_xfer_t ct = {
	.req = { .bmRequestType = VLIB_USB_REQ_TYPE_CLASS_INTERFACE_IN,
		 .bRequest = CDC_NCM_GET_NTB_PARAMETERS,
		 .wIndex = ud->ctrl_if,
		 .wLength = sizeof (ntb_param) },
	.data = &ntb_param,
	.timeout = 0.2f
      };

      if ((err = vlib_usb_ctrl_xfer (vm, dh, &ct)))
	goto done;

      log_debug (ud, "ntb_parameters: %U",
		 format_vlib_usb_cdc_ncm_ntb_parameters, &ntb_param);
    }

  fformat (stderr, "==================\n%U\n", format_vlib_usb_desc_tree,
	   device_desc);

done:
  if (ue)
    {
      clib_error_free (err);
      err = vnet_error (VNET_ERR_UNSPECIFIED, "USB error: %U",
			format_clib_error, ue);
      clib_error_free (ue);
    }
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
