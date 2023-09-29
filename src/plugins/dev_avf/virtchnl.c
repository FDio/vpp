/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_avf/avf.h>
#include <dev_avf/virtchnl.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (avf_log, static) = {
  .class_name = "dev_avf",
  .subclass_name = "virtchnl",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, avf_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, avf_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, avf_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, avf_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, avf_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)

static u8 *
format_virtchnl_version_info_t (u8 *s, va_list *args)
{
  virtchnl_version_info_t *p = va_arg (*args, virtchnl_version_info_t *);
  return format (s, "version %u.%u", p->major, p->minor);
}

static u8 *
format_virtchnl_vf_resource_t (u8 *s, va_list *args)
{
  virtchnl_vf_resource_t *p = va_arg (*args, virtchnl_vf_resource_t *);
  u32 indent = format_get_indent (s);
  s = format (s,
	      "get_vf_resources: num_vsis %u num_queue_pairs %u "
	      "max_vectors %u max_mtu %u vf_cap_flags 0x%x (%U) "
	      "rss_key_size %u rss_lut_size %u",
	      p->num_vsis, p->num_queue_pairs, p->max_vectors, p->max_mtu,
	      p->vf_cap_flags, format_avf_vf_cap_flags, p->vf_cap_flags,
	      p->rss_key_size, p->rss_lut_size);
  for (int i = 0; i < p->num_vsis; i++)
    s = format (
      s,
      "\n%Uget_vf_pources_vsi[%u]: vsi_id %u num_queue_pairs %u vsi_type %u "
      "qset_handle %u default_mac_addr %U",
      format_white_space, indent, i, p->vsi_res[i].vsi_id,
      p->vsi_res[i].num_queue_pairs, p->vsi_res[i].vsi_type,
      p->vsi_res[i].qset_handle, format_ethernet_address,
      p->vsi_res[i].default_mac_addr);
  return s;
}

vnet_dev_rv_t
avf_vc_op_version (vlib_main_t *vm, vnet_dev_t *dev,
		   virtchnl_version_info_t *ver)
{
  vnet_dev_rv_t rv;
  virtchnl_version_info_t myver = {
    .major = VIRTCHNL_VERSION_MAJOR,
    .minor = VIRTCHNL_VERSION_MINOR,
  };

  rv = avf_aq_pf_send_and_recv (vm, dev, VIRTCHNL_OP_VERSION, &myver,
				sizeof (virtchnl_version_info_t), ver,
				sizeof (virtchnl_version_info_t));

  if (rv == VNET_DEV_OK)
    log_debug (dev, "%U", format_virtchnl_version_info_t, ver);

  return rv;
}

vnet_dev_rv_t
avf_vc_op_get_vf_resources (vlib_main_t *vm, vnet_dev_t *dev,
			    virtchnl_vf_resource_t *res)
{
  vnet_dev_rv_t rv;
  u32 bitmap = (VIRTCHNL_VF_OFFLOAD_L2 | VIRTCHNL_VF_OFFLOAD_RSS_PF |
		VIRTCHNL_VF_OFFLOAD_WB_ON_ITR | VIRTCHNL_VF_OFFLOAD_VLAN |
		VIRTCHNL_VF_OFFLOAD_RX_POLLING |
		VIRTCHNL_VF_CAP_ADV_LINK_SPEED | VIRTCHNL_VF_OFFLOAD_FDIR_PF |
		VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF | VIRTCHNL_VF_OFFLOAD_VLAN_V2);

  log_debug (dev, "get_vf_resources: bitmap 0x%x (%U)", bitmap,
	     format_avf_vf_cap_flags, bitmap);

  rv = avf_aq_pf_send_and_recv (vm, dev, VIRTCHNL_OP_GET_VF_RESOURCES, &bitmap,
				sizeof (u32), res,
				sizeof (virtchnl_vf_resource_t));

  if (rv == VNET_DEV_OK)
    log_debug (dev, "%U", format_virtchnl_vf_resource_t, res);

  return rv;
}
