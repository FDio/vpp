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

#define CDC_NOTIF_NETWORK_CONNECTION	  0x00
#define CDC_NOTIF_CONNECTION_SPEED_CHANGE 0x2a

typedef struct
{
  u32 DLBitRate;
  u32 ULBitRate;
} cdc_connection_speed_change_notif_t;

void
cdc_int_callback_fn (vlib_usb_completion_t *cfg)
{
  vlib_usb_req_t *req = cfg->data;
  usbnet_dev_t *ud =
    pool_elt_at_index (usbnet_main.devices, cfg->user_data.uword)[0];

  if (req->bmRequestType == VLIB_USB_REQ_TYPE_CLASS_INTERFACE_IN &&
      req->bRequest == CDC_NOTIF_NETWORK_CONNECTION)
    {
      log_debug (ud, "notification: NETWORK_CONNECTION %s",
		 req->wValue ? "CONNECTED" : "DISCONNECTED");
    }
  else if (req->bmRequestType == VLIB_USB_REQ_TYPE_CLASS_INTERFACE_IN &&
	   req->bRequest == CDC_NOTIF_CONNECTION_SPEED_CHANGE)
    {
      cdc_connection_speed_change_notif_t *cscn =
	(cdc_connection_speed_change_notif_t *) (req + 1);
      log_debug (
	ud, "notification: CONNECTION_SPEED_CHANGE DLBitRate %u ULBitRate %u",
	cscn->DLBitRate, cscn->ULBitRate);
    }
  else
    {
      log_debug (ud, "unknown notification: %U", format_vlib_usb_req, req);
      if (cfg->data_size > 8)
	log_debug (ud, "data:  %U", format_hexdump, req, +1,
		   cfg->data_size - 8);
    }
}

clib_error_t *
usbnet_create_if (vlib_main_t *vm, usbnet_create_if_args_t *args)
{
  usbnet_main_t *um = &usbnet_main;
  usbnet_dev_t *ud, **udp;
  vlib_usb_dev_handle_t dh;
  vlib_usb_desc_t *device_desc, *config_desc = 0, *ctrl_desc = 0,
				*data_desc = 0;
  clib_error_t *err = 0, *ue = 0;

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
	  config_desc = d->parent;
	  ctrl_desc = d;
	}
    }

  if (ud->type == USBNET_DEV_TYPE_UNKNOWN)
    ERR_DONE (VNET_ERR_UNSUPPORTED, "unsupported device");

  /* Change active configuration if needed */
  if (device_desc->device.bNumConfigurations > 1)
    {
      u8 active_config;
      u8 required_config = config_desc->config.bConfigurationValue;

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

      foreach_vlib_usb_child_desc (d, ctrl_desc)
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
	{
	  log_debug (ud, "%U", format_usb_desc, mbim_func_desc);
	  if (mbim_func_desc->bcmMBIMVersion != 0x0100)
	    ERR_DONE (VNET_ERR_UNSUPPORTED, "unsupported MBIM version");
	}

      if (mbim_ext_func_desc)
	{
	  log_debug (ud, "%U", format_usb_desc, mbim_ext_func_desc);
	  if (mbim_ext_func_desc->bcdMBIMExtendedVersion != 0x0100)
	    ERR_DONE (VNET_ERR_UNSUPPORTED, "unsupported MBIM version");
	}
    }

  if ((ue = vlib_usb_claim_interface (vm, dh, ud->data_if)))
    goto done;

  foreach_vlib_usb_child_desc_of_type (d, ctrl_desc, VLIB_USB_DT_ENDPOINT)
    if (d->endpoint.attribute.type == VLIB_USB_EP_TYPE_INTERRUPT &&
	d->endpoint.ep_address.direction == VLIB_USB_EP_DIR_IN)
      {
	ud->ctrl_int_ep = d->endpoint.bEndpointAddress;
	break;
      }

  if (ud->ctrl_int_ep == 0)
    ERR_DONE (VNET_ERR_NO_SUCH_ENTRY,
	      "Unable to find control interface interrupt endpoint");

  foreach_vlib_usb_child_desc_of_type (d, config_desc, VLIB_USB_DT_INTERFACE)
    {
      if (d->interface.bInterfaceNumber != ud->data_if)
	continue;
      if (d->interface.bNumEndpoints != 2)
	continue;
      data_desc = d;
      break;
    }

  if (data_desc == 0)
    ERR_DONE (VNET_ERR_NO_SUCH_ENTRY,
	      "unable to find data interface descriptor");

  foreach_vlib_usb_child_desc_of_type (d, data_desc, VLIB_USB_DT_ENDPOINT)
    if (d->endpoint.attribute.type == VLIB_USB_EP_TYPE_BULK)
      {
	if (d->endpoint.ep_address.direction == VLIB_USB_EP_DIR_IN)
	  ud->data_bulk_in_ep = d->endpoint.bEndpointAddress;
	else if (d->endpoint.ep_address.direction == VLIB_USB_EP_DIR_OUT)
	  ud->data_bulk_out_ep = d->endpoint.bEndpointAddress;
      }

  if (ud->data_bulk_in_ep == 0 || ud->data_bulk_out_ep == 0)
    ERR_DONE (VNET_ERR_NO_SUCH_ENTRY,
	      "unable to find data interface bulk endpoint(s)");

  if ((ue = vlib_usb_enable_interrupt (
	 vm, dh, ud->ctrl_int_ep,
	 &(vlib_usb_interrupt_config_t){ .callback_fn = cdc_int_callback_fn,
					 .once = 1,
					 .user_data.uword = ud->dev_index })))
    goto done;

  if ((vlib_usb_set_interface_altsetting (
	vm, dh, ud->data_if, data_desc->interface.bAlternateSetting)))
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

      log_debug (ud, "ntb_parameters:\n%U",
		 format_vlib_usb_cdc_ncm_ntb_parameters, &ntb_param);

      if ((err = usbnet_mbim_open (vm, ud)))
	; // goto done;

      if ((err = usbnet_mbim_open (vm, ud)))
	; // goto done;
      // if ((err = usbnet_mbim_close (vm, ud)))
      //	;//goto done;

      if ((err = usbnet_mbim_reset (vm, ud)))
	;
    }
  else if (ud->type == USBNET_DEV_TYPE_CDC_ECM)
    {
    }

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
