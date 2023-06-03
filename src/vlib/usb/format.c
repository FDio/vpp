/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include "vlib/usb/usb_cdc.h"
#include "vppinfra/format.h"
#include <vlib/vlib.h>

#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>
#include <vlib/usb/usb.h>

#include <fcntl.h>
#include <sys/ioctl.h>

u8 *
format_vlib_usb_string_desc (u8 *s, va_list *args)
{
  vlib_usb_dev_handle_t dh = va_arg (*args, vlib_usb_dev_handle_t);
  u32 desc_index = va_arg (*args, u32);
  u8 *str = vlib_usb_get_string_desc (dh, desc_index);

  vec_append (s, str);
  vec_free (str);
  return s;
}

u8 *
format_vlib_usb_desc_tree (u8 *s, va_list *args)
{
  vlib_usb_desc_t *root = va_arg (*args, vlib_usb_desc_t *);
  u32 indent = format_get_indent (s) + 2;

  s = format (s, "\n%U", format_usb_desc, &root->desc);
  foreach_vlib_usb_child_desc (d, root)
    s = format (s, "\n%U%U", format_white_space,
		indent + (d->depth - root->depth) * 4, format_usb_desc,
		&d->desc);
  return s;
}

u8 *
format_usb_bcd (u8 *s, va_list *args)
{
  u16 *p = va_arg (*args, u16 *);
  u32 v = *p;

  if (v & 0xf000)
    vec_add1 (s, '0' + ((v >> 12) & 0x0f));
  vec_add1 (s, '0' + ((v >> 8) & 0x0f));
  vec_add1 (s, '.');
  vec_add1 (s, '0' + ((v >> 4) & 0x0f));
  if (v & 0x000f)
    vec_add1 (s, '0' + ((v >> 4) & 0x0f));
  s = format (s, " (0x%04x)", v);

  return s;
}

u8 *
format_usb_desc_type (u8 *s, va_list *args)
{
  u32 type = va_arg (*args, u32);

  char *desc_names[] = {
#define _(t, n) [t] = #n,
    foreach_vlib_usb_desc_type
#undef _
  };

  if (type >= ARRAY_LEN (desc_names) || desc_names[type] == 0)
    return format (s, "UNKNOWN(0x%02x)", type);

  s = format (s, "%s", desc_names[type]);

  return s;
}

u8 *
format_usb_desc (u8 *s, va_list *args)
{
  vlib_usb_descriptor_header_t *h =
    va_arg (*args, vlib_usb_descriptor_header_t *);
  u32 indent = format_get_indent (s);
  u8 type = h->bDescriptorType;

#define _(n, ...)                                                             \
  s = format (s, "\n%U%-32s: ", format_white_space, indent + 2, #n);          \
  if (__VA_ARGS__ + 0)                                                        \
    s = format (s, "%U", __VA_ARGS__ + 0, &d->n);                             \
  else if (d->n < 10)                                                         \
    s = format (s, "%u", d->n);                                               \
  else if (sizeof (d->n) == 1)                                                \
    s = format (s, "0x%02x (%u)", d->n, d->n);                                \
  else if (sizeof (d->n) == 2)                                                \
    s = format (s, "0x%04x (%u)", d->n, d->n);                                \
  else                                                                        \
    s = format (s, "0x%08x (%u)", d->n, d->n);

  if (type == VLIB_USB_DT_DEVICE)
    {
      vlib_usb_device_descriptor_t *d = (typeof (d)) h;
      s = format (s, "descriptor type: %U", format_usb_desc_type, type);
      _ (bcdUSB, format_usb_bcd)
      _ (bDeviceClass)
      _ (bDeviceSubClass)
      _ (bDeviceProtocol)
      _ (bMaxPacketSize0)
      _ (idVendor)
      _ (idProduct)
      _ (bcdDevice, format_usb_bcd)
      _ (iManufacturer)
      _ (iProduct)
      _ (iSerialNumber)
      _ (bNumConfigurations)
    }
  else if (type == VLIB_USB_DT_CONFIG)
    {
      vlib_usb_config_descriptor_t *d = (typeof (d)) h;
      s = format (s, "descriptor type: %U", format_usb_desc_type, type);
      _ (bLength)
      _ (wTotalLength)
      _ (bNumInterfaces)
      _ (bConfigurationValue)
      _ (iConfiguration)
      _ (bmAttributes)
      _ (bMaxPower)
    }
  else if (type == VLIB_USB_DT_INTERFACE)
    {
      vlib_usb_interface_descriptor_t *d = (typeof (d)) h;
      s = format (s, "descriptor type: %U", format_usb_desc_type, type);
      _ (bInterfaceNumber)
      _ (bAlternateSetting)
      _ (bNumEndpoints)
      _ (bInterfaceClass)
      _ (bInterfaceSubClass)
      _ (bInterfaceProtocol)
      _ (iInterface)
    }
  else if (type == VLIB_USB_DT_ENDPOINT)
    {
      vlib_usb_endpoint_descriptor_t *d = (typeof (d)) h;
      s = format (s, "descriptor type: %U", format_usb_desc_type, type);
      _ (bEndpointAddress)
      _ (bmAttributes)
      _ (wMaxPacketSize)
      _ (bInterval)
    }
  else if (type == VLIB_USB_DT_INTERFACE_ASSOCIATION)
    {
      vlib_usb_interface_assoc_descriptor_t *d = (typeof (d)) h;
      s = format (s, "descriptor type: %U", format_usb_desc_type, type);
      _ (bFirstInterface)
      _ (bInterfaceCount)
      _ (bFunctionClass)
      _ (bFunctionSubClass)
      _ (bFunctionProtocol)
      _ (iFunction)
    }
  else if (type == USB_CDC_DESC_TYPE_CS_INTERFACE)
    {
      usb_cdc_desc_hdr_t *sh = (typeof (sh)) h;
      s = format (s, "descriptor type: CDC_CS_INTERFACE");

      if (sh->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_HEADER)
	{
	  usb_cdc_header_desc_t *d = (typeof (d)) h;
	  s = format (s, ", subtype HEADER");
	  _ (bcdCDC, format_usb_bcd)
	}
      else if (sh->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_UNION)
	{
	  usb_cdc_union_desc_t *d = (typeof (d)) h;
	  s = format (s, ", subtype UNION");
	  _ (bControlInterface)
	  _ (bSubordinateInterface[0])
	}
      else if (sh->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_ETHERNET)
	{
	  usb_cdc_ethernet_desc_t *d = (typeof (d)) h;
	  s = format (s, ", subtype ETHERNET");
	  _ (iMACAddress)
	  _ (bmEthernetStatistics)
	  _ (wMaxSegmentSize)
	  _ (bNumberPowerFilters)
	  _ (wNumberMCFilters)
	}
      else if (sh->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_MBIM_FUNC)
	{
	  usb_cdc_mbim_func_desc_t *d = (typeof (d)) h;
	  s = format (s, ", subtype MBIM_FUNC");
	  _ (bcmMBIMVersion, format_usb_bcd)
	  _ (wMaxControlMessage)
	  _ (bNumberFilters)
	  _ (bMaxFilterSize)
	  _ (wMaxSegmentSize)
	  _ (bmNetworkCapabilities)
	}
      else if (sh->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_MBIM_EXT_FUNC)
	{
	  usb_cdc_mbim_ext_func_desc_t *d = (typeof (d)) h;
	  s = format (s, ", subtype MBIM_EXT_FUNC");
	  _ (bcdMBIMExtendedVersion, format_usb_bcd)
	  _ (bMaxOutstandingCommandMessages)
	  _ (wMTU)
	}
      else
	s = format (s, "unknown descriptor: subtype 0x%02x len %u data %U",
		    sh->bDescriptorSubtype, h->bLength,
		    format_hex_bytes_no_wrap, h, h->bLength);
    }
  else
    s = format (s, "unknown descriptor: btype 0x%02x len %u data %U",
		h->bDescriptorType, h->bLength, format_hex_bytes_no_wrap, h,
		h->bLength);
#undef _
  return s;
}
u8 *
format_usb_cdc_ethernet_desc (u8 *s, va_list *args)
{
  usb_cdc_ethernet_desc_t *d = va_arg (*args, usb_cdc_ethernet_desc_t *);
  u32 indent = format_get_indent (s);
  int not_first = 0;

#define _(t, n)                                                               \
  s = format (s, "%s%U%-32s: %u", not_first ? "\n" : "", format_white_space,  \
	      not_first ? indent : 0, #n, d->n);                              \
  not_first = 1;
  foreach_usb_cdc_ethernet_desc_t
#undef _

    return s;
}

u8 *
format_usb_cdc_mbim_func_desc (u8 *s, va_list *args)
{
  usb_cdc_mbim_func_desc_t *d = va_arg (*args, usb_cdc_mbim_func_desc_t *);
  u32 indent = format_get_indent (s);
  int not_first = 0;

#define _(t, n)                                                               \
  s = format (s, "%s%U%-32s: %u", not_first ? "\n" : "", format_white_space,  \
	      not_first ? indent : 0, #n, d->n);                              \
  not_first = 1;
  foreach_usb_cdc_mbim_func_desc_t
#undef _

    return s;
}

u8 *
format_usb_cdc_mbim_ext_func_desc (u8 *s, va_list *args)
{
  usb_cdc_mbim_ext_func_desc_t *d =
    va_arg (*args, usb_cdc_mbim_ext_func_desc_t *);
  u32 indent = format_get_indent (s);
  int not_first = 0;

#define _(t, n)                                                               \
  s = format (s, "%s%U%-32s: %u", not_first ? "\n" : "", format_white_space,  \
	      not_first ? indent : 0, #n, d->n);                              \
  not_first = 1;
  foreach_usb_cdc_mbim_ext_func_desc_t
#undef _

    return s;
}

u8 *
format_vlib_usb_cdc_ncm_ntb_parameters (u8 *s, va_list *args)
{
  cdc_ncm_ntb_parameters_t *d = va_arg (*args, cdc_ncm_ntb_parameters_t *);
  u32 indent = format_get_indent (s);
  int not_first = 0;

#define _(t, n)                                                               \
  s = format (s, "%s%U%-32s: %u", not_first ? "\n" : "", format_white_space,  \
	      not_first ? indent : 0, #n, d->n);                              \
  not_first = 1;
  foreach_cdc_ncm_ntb_parameters
#undef _

    return s;
}

u8 *
format_vlib_usb_req_type (u8 *s, va_list *args)
{
  vlib_usb_req_type_t rt = va_arg (*args, int);
  char *recp[4] = { "DEVICE", "INTERFACE", "ENDPOINT", "UNKNOWN" };
  char *type[4] = { "STANDARD", "CLASS", "VENDOR", "UNKNOWN" };
  char *dir[2] = { "OUT", "IN" };

  s = format (s, "%s_%s_%s", type[(rt >> 5) & 3], recp[rt & 3],
	      dir[(rt >> 7) & 1]);
  return s;
}

u8 *
format_vlib_usb_req (u8 *s, va_list *args)
{
  vlib_usb_req_t *req = va_arg (*args, vlib_usb_req_t *);
  u32 in = format_get_indent (s);

  s = format (s, "bmRequestType %U (0x%02x)", format_vlib_usb_req_type,
	      req->bmRequestType, req->bmRequestType);
  s = format (s, "\n%UbRequest 0x%02x", format_white_space, in, req->bRequest);
  s = format (s, "\n%UwValue 0x%04x", format_white_space, in, req->wValue);
  s = format (s, "\n%UwIndex 0x%04x", format_white_space, in, req->wIndex);
  s = format (s, "\n%UwLength 0x%04x", format_white_space, in, req->wLength);

  return s;
}
