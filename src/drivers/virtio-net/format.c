/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <driver.h>

u8 *
format_virtio_config_status (u8 *s, va_list *args)
{
  u32 status = va_arg (*args, u32);
  u8 *t = 0;

  if (status == 0)
    return format (s, "RESET");

#define _(a, b)                                                                                    \
  if (status & b)                                                                                  \
    t = format (t, "%s%s", t ? "|" : "", #a);
  foreach_virtio_config_status_flags
#undef _

    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_virtio_net_config_status (u8 *s, va_list *args)
{
  u32 status = va_arg (*args, u32);
  u8 *t = 0;

  if (status == 0)
    return format (s, "DOWN");

#define _(a, b)                                                                                    \
  if (status & b)                                                                                  \
    t = format (t, "%s%s", t ? "|" : "", #a);
  foreach_virtio_net_config_status_flags
#undef _

    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_virtio_features (u8 *s, va_list *args)
{
  clib_bitmap_t *feats = va_arg (*args, clib_bitmap_t *);
  u32 i, first = 1;
  u32 indent = format_get_indent (s);
  const char *names[64] = {
#define _(n, bit) [bit] = "VIRTIO_NET_F_" #n,
    foreach_virtio_net_features
#undef _
#define _(n, bit) [bit] = "VIRTIO_F_" #n,
      foreach_virtio_config_features
#undef _
#define _(n, bit) [bit] = "VIRTIO_RING_F_" #n,
	foreach_virtio_ring_features
#undef _
#define _(n, bit) [bit] = "VHOST_F_" #n,
	  foreach_vhost_features
#undef _
  };

  clib_bitmap_foreach (i, feats)
    {
      if (first)
	first = 0;
      else
	s = format_newline (s, indent);

      if (i >= ARRAY_LEN (names) || names[i] == 0)
	s = format (s, "unknown(%u)", i);
      else
	s = format (s, "%s(%u)", names[i], i);
    }

  return s;
}

u8 *
format_virtio_pci_cap_common_cfg (u8 *s, va_list *args)
{
  virtio_pci_common_cfg_t *cfg = va_arg (*args, virtio_pci_common_cfg_t *);
  u32 indent = format_get_indent (s);
  u32 device_feature_select = cfg->device_feature_select;
  u32 driver_feature_select = cfg->driver_feature_select;
  clib_bitmap_t *device_features = 0;
  clib_bitmap_t *driver_features = 0;
  u32 val;

  for (u32 i = 0; i < 2; i++)
    {
      cfg->device_feature_select = i;
      val = cfg->device_feature;
      if (val)
	device_features = clib_bitmap_set_multiple (device_features, i * 32, (uword) val, 32);

      cfg->driver_feature_select = i;
      val = cfg->driver_feature;
      if (val)
	driver_features = clib_bitmap_set_multiple (driver_features, i * 32, (uword) val, 32);
    }

  cfg->device_feature_select = device_feature_select;
  cfg->driver_feature_select = driver_feature_select;

  s = format (s,
	      "dev_status %U (0x%x) config_gen %u num_queues %u msix_config "
	      "0x%x",
	      format_virtio_config_status, cfg->device_status, cfg->device_status,
	      cfg->config_generation, cfg->num_queues, cfg->msix_config);

  s = format_newline (s, indent);
  s = format (s, "device_features: %U", format_virtio_features, device_features);

  s = format_newline (s, indent);
  s = format (s, "driver_features: %U", format_virtio_features, driver_features);

  clib_bitmap_free (device_features);
  clib_bitmap_free (driver_features);

  s = format_newline (s, indent);
  s = format (s, "queue_select %u size %u msix_vec 0x%x enable %u notify_off %u", cfg->queue_select,
	      cfg->queue_size, cfg->queue_msix_vector, cfg->queue_enable, cfg->queue_notify_off);

  s = format_newline (s, indent);
  s = format (s, "queue_desc 0x%lx driver 0x%lx device 0x%lx", cfg->queue_desc, cfg->queue_driver,
	      cfg->queue_device);

  return s;
}

u8 *
format_virtio_net_config (u8 *s, va_list *args)
{
  virtio_net_config_t *cfg = va_arg (*args, virtio_net_config_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "mac %U status %U (0x%x)", format_ethernet_address, cfg->mac,
	      format_virtio_net_config_status, cfg->status, cfg->status);

  s = format_newline (s, indent);
  s = format (s, "max_virtqueue_pairs %u mtu %u speed %u duplex %u", cfg->max_virtqueue_pairs,
	      cfg->mtu, cfg->speed, cfg->duplex);

  s = format_newline (s, indent);
  s = format (s,
	      "rss_max_key_size %u rss_max_indirection_table_length %u "
	      "supported_hash_types 0x%x",
	      cfg->rss_max_key_size, cfg->rss_max_indirection_table_length,
	      cfg->supported_hash_types);

  return s;
}

u8 *
format_virtio_pci_isr (u8 *s, va_list *args)
{
  u8 isr = *(u8 *) va_arg (*args, u8 *);

  s = format (s, "isr 0x%x", isr);

  return s;
}

u8 *
format_virtio_pci_notify_cfg (u8 *s, va_list *args)
{
  vn_dev_t *vd = va_arg (*args, vn_dev_t *);

  s = format (s, "multiplier %u", vd->notify_off_multiplier);

  return s;
}

u8 *
format_virtio_net_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  vn_dev_t *vnd = vnet_dev_get_data (port->dev);

  if (vnd->device_cfg)
    s = format (s, "status %U (0x%x)", format_virtio_net_config_status, vnd->device_cfg->status,
		vnd->device_cfg->status);

  return s;
}

u8 *
format_virtio_net_device_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  vn_dev_t *vnd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);

  s = format (s, "Common Config:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_virtio_pci_cap_common_cfg, vnd->common_cfg);

  s = format_newline (s, indent);
  s = format (s, "Device Config:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_virtio_net_config, vnd->device_cfg);

  s = format_newline (s, indent);
  s = format (s, "Notify Config:");
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_virtio_pci_notify_cfg, vnd);

  return s;
}
