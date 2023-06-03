/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

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
format_usb_device_config (u8 *s, va_list *args)
{
  vlib_usb_desc_tree_t *dc = va_arg (*args, vlib_usb_desc_tree_t *);
  vlib_usb_desc_t *d = dc->all[0];
  u32 last_is_child = 0, indent = format_get_indent (s);

  while (d)
    {
      if (!last_is_child)
	fformat (stderr, "\n%U%U", format_white_space, indent + 2,
		 format_usb_desc, &d->desc);
      if (d->child && !last_is_child)
	{
	  d = d->child;
	  indent += 8;
	  last_is_child = 0;
	}
      else if (d->next)
	{
	  d = d->next;
	  last_is_child = 0;
	}
      else
	{
	  d = d->parent;
	  indent -= 8;
	  last_is_child = 1;
	}
    }
  return s;
}

u8 *
format_usb_bcd (u8 *s, va_list *args)
{
  u16 *p = va_arg (*args, u16 *);
  u32 v = *p, d = 0, m = 1;

  while (v)
    {
      d += m * (v & 0xf);
      m *= 10;
      v >>= 4;
    }

  return format (s, "0x%04x (%u%.2f)", *p, d / 100, (f64) (d % 100) / 100);
}

u8 *
format_usb_desc (u8 *s, va_list *args)
{
  struct usb_descriptor_header *h =
    va_arg (*args, struct usb_descriptor_header *);
  u32 indent = format_get_indent (s);

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

  if (h->bDescriptorType == USB_DT_DEVICE)
    {
      struct usb_device_descriptor *d = (typeof (d)) h;
      s = format (s, "device descriptor:");
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
  else if (h->bDescriptorType == USB_DT_CONFIG)
    {
      struct usb_config_descriptor *d = (typeof (d)) h;
      s = format (s, "config descriptor:");
      _ (bLength)
      _ (wTotalLength)
      _ (bNumInterfaces)
      _ (bConfigurationValue)
      _ (iConfiguration)
      _ (bmAttributes)
      _ (bMaxPower)
    }
  else if (h->bDescriptorType == USB_DT_INTERFACE)
    {
      struct usb_interface_descriptor *d = (typeof (d)) h;
      s = format (s, "interface descriptor:");
      _ (bInterfaceNumber)
      _ (bAlternateSetting)
      _ (bNumEndpoints)
      _ (bInterfaceClass)
      _ (bInterfaceSubClass)
      _ (bInterfaceProtocol)
      _ (iInterface)
    }
  else if (h->bDescriptorType == USB_DT_ENDPOINT)
    {
      struct usb_endpoint_descriptor *d = (typeof (d)) h;
      s = format (s, "endpoint descriptor:");
      _ (bEndpointAddress)
      _ (bmAttributes)
      _ (wMaxPacketSize)
      _ (bInterval)
    }
  else if (h->bDescriptorType == USB_DT_INTERFACE_ASSOCIATION)
    {
      struct usb_interface_assoc_descriptor *d = (typeof (d)) h;
      s = format (s, "interface association descriptor:");
      _ (bFirstInterface)
      _ (bInterfaceCount)
      _ (bFunctionClass)
      _ (bFunctionSubClass)
      _ (bFunctionProtocol)
      _ (iFunction)
    }
  else if (h->bDescriptorType == USB_CDC_DESC_TYPE_CS_INTERFACE)
    {
      usb_cdc_desc_hdr_t *sh = (typeof (sh)) h;
      s = format (s, "cs interface - ");

      if (sh->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_HEADER)
	{
	  usb_cdc_header_desc_t *d = (typeof (d)) h;
	  s = format (s, "header descriptor:");
	  _ (bcdCDC, format_usb_bcd)
	}
      else if (sh->bDescriptorSubtype == USB_CDC_DESC_SUBTYPE_UNION)
	{
	  usb_cdc_union_desc_t *d = (typeof (d)) h;
	  s = format (s, "union descriptor:");
	  _ (bControlInterface)
	  _ (bSubordinateInterface[0])
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
