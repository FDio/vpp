/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _AVF_VIRTCHNL_FUNCS_H_
#define _AVF_VIRTCHNL_FUNCS_H_

#include <vppinfra/clib.h>
#include <vnet/dev/dev.h>
#include <dev_avf/avf.h>

#define VIRTCHNL_MSG_SZ(s, e, n) STRUCT_OFFSET_OF (s, e[(n) + 1])

vnet_dev_rv_t avf_virtchnl_req (vlib_main_t *, vnet_dev_t *, virtchnl_op_t,
				void *, u16, void *, u16);

static_always_inline vnet_dev_rv_t
avf_vc_op_version (vlib_main_t *vm, vnet_dev_t *dev,
		   virtchnl_version_info_t *req, virtchnl_version_info_t *resp)
{
  return avf_virtchnl_req (vm, dev, VIRTCHNL_OP_VERSION, req,
			   sizeof (virtchnl_version_info_t), resp,
			   sizeof (virtchnl_version_info_t));
}

static_always_inline vnet_dev_rv_t
avf_vc_op_get_vf_resources (vlib_main_t *vm, vnet_dev_t *dev, u32 *req,
			    virtchnl_vf_resource_t *resp)
{
  return avf_virtchnl_req (vm, dev, VIRTCHNL_OP_GET_VF_RESOURCES, req,
			   sizeof (*req), resp, sizeof (*resp));
}

static_always_inline vnet_dev_rv_t
avf_vc_op_config_vsi_queues (vlib_main_t *vm, vnet_dev_t *dev,
			     virtchnl_vsi_queue_config_info_t *req)
{
  return avf_virtchnl_req (vm, dev, VIRTCHNL_OP_CONFIG_VSI_QUEUES, req,
			   VIRTCHNL_MSG_SZ (virtchnl_vsi_queue_config_info_t,
					    qpair, req->num_queue_pairs),
			   0, 0);
}

static_always_inline vnet_dev_rv_t
avf_vc_op_config_rss_lut (vlib_main_t *vm, vnet_dev_t *dev,
			  virtchnl_rss_lut_t *req)
{
  return avf_virtchnl_req (
    vm, dev, VIRTCHNL_OP_CONFIG_RSS_LUT, req,
    VIRTCHNL_MSG_SZ (virtchnl_rss_lut_t, lut, req->lut_entries), 0, 0);
}

static_always_inline vnet_dev_rv_t
avf_vc_op_config_rss_key (vlib_main_t *vm, vnet_dev_t *dev,
			  virtchnl_rss_key_t *req)
{
  return avf_virtchnl_req (
    vm, dev, VIRTCHNL_OP_CONFIG_RSS_KEY, req,
    VIRTCHNL_MSG_SZ (virtchnl_rss_key_t, key, req->key_len), 0, 0);
}

static_always_inline vnet_dev_rv_t
avf_vc_op_config_promisc_mode (vlib_main_t *vm, vnet_dev_t *dev, u32 *req)
{
  return avf_virtchnl_req (vm, dev, VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE, req,
			   sizeof (*req), 0, 0);
}

static_always_inline vnet_dev_rv_t
avf_vc_op_disable_vlan_stripping (vlib_main_t *vm, vnet_dev_t *dev)
{
  return avf_virtchnl_req (vm, dev, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING, 0, 0,
			   0, 0);
}

static_always_inline vnet_dev_rv_t
avf_vc_op_add_eth_addr (vlib_main_t *vm, vnet_dev_t *dev,
			virtchnl_ether_addr_list_t *req)
{
  return avf_virtchnl_req (
    vm, dev, VIRTCHNL_OP_ADD_ETH_ADDR, req,
    VIRTCHNL_MSG_SZ (virtchnl_ether_addr_list_t, list, req->num_elements), 0,
    0);
}

static_always_inline vnet_dev_rv_t
avf_vc_op_get_offload_vlan_v2_caps (vlib_main_t *vm, vnet_dev_t *dev,
				    virtchnl_vlan_caps_t *resp)
{
  return avf_virtchnl_req (vm, dev, VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS, 0, 0,
			   resp, sizeof (*resp));
}
#endif /* _AVF_VIRTCHNL_FUNCS_H_ */
