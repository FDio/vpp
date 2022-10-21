/*
 *------------------------------------------------------------------
 * Copyright (c) 2022 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vppinfra/mem.h>
#include "avf_advanced_flow.h"

int
avf_rss_cfg_create (struct virtchnl_rss_cfg **rss_cfg, int tunnel_level)
{
  *rss_cfg = clib_mem_alloc (sizeof (**rss_cfg));
  if ((*rss_cfg) == NULL)
    return -1;

  clib_memset (*rss_cfg, 0, sizeof (**rss_cfg));

  (*rss_cfg)->proto_hdrs.tunnel_level = tunnel_level;

  return 0;
}

int
avf_rss_rcfg_destroy (struct virtchnl_rss_cfg *rss_cfg)
{
  clib_mem_free (rss_cfg);

  return 0;
}

int
avf_rss_parse_action (const struct avf_flow_action actions[],
		      struct virtchnl_rss_cfg *rss_cfg,
		      struct avf_flow_error *error)
{
  const struct avf_flow_action_rss *rss;
  enum virtchnl_action action_type;
  int ret;

  /* Supported action is RSS. */
  for (; actions->type != VIRTCHNL_ACTION_NONE; actions++)
    {
      action_type = actions->type;
      switch (action_type)
	{
	case VIRTCHNL_ACTION_RSS:
	  rss = actions->conf;

	  if (rss->func == AVF_ETH_HASH_FUNCTION_SIMPLE_XOR)
	    {
	      rss_cfg->rss_algorithm = VIRTCHNL_RSS_ALG_XOR_ASYMMETRIC;
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ACTION, actions,
					"simple xor is not supported.");
	      return ret;
	    }
	  else if (rss->func == AVF_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ)
	    {
	      rss_cfg->rss_algorithm = VIRTCHNL_RSS_ALG_TOEPLITZ_SYMMETRIC;
	    }
	  else
	    {
	      rss_cfg->rss_algorithm = VIRTCHNL_RSS_ALG_TOEPLITZ_ASYMMETRIC;
	    }
	  break;
	default:
	  ret =
	    avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION,
				actions, "Invalid action.");
	  return ret;
	}
    }

  return 0;
}

int
avf_rss_parse_generic_pattern (struct virtchnl_rss_cfg *rss_cfg,
			       struct avf_flow_item avf_items[],
			       struct avf_flow_error *error)
{
  struct avf_flow_item *item = avf_items;
  u8 *pkt_buf, *msk_buf;
  u16 spec_len, pkt_len;

  spec_len = clib_strnlen (item->spec, VIRTCHNL_MAX_SIZE_GEN_PACKET);
  pkt_len = spec_len / 2;

  pkt_buf = clib_mem_alloc (pkt_len);
  msk_buf = clib_mem_alloc (pkt_len);

  avf_parse_generic_pattern (item, pkt_buf, msk_buf, spec_len);

  clib_memcpy (rss_cfg->proto_hdrs.raw.spec, pkt_buf, pkt_len);
  clib_memcpy (rss_cfg->proto_hdrs.raw.mask, msk_buf, pkt_len);

  rss_cfg->proto_hdrs.count = 0;
  rss_cfg->proto_hdrs.tunnel_level = 0;
  rss_cfg->proto_hdrs.raw.pkt_len = pkt_len;

  clib_mem_free (pkt_buf);
  clib_mem_free (msk_buf);

  return 0;
}

/* Used for common flow creation */
int
avf_rss_parse_pattern (struct virtchnl_rss_cfg *rss_cfg,
		       struct avf_flow_item avf_items[],
		       struct avf_flow_error *error)
{
  return -1;
}

int
avf_rss_rule_create (struct avf_flow_vc_ctx *ctx,
		     struct virtchnl_rss_cfg *rss_cfg)
{
  int ret;

  ret = ctx->vc_op (ctx->vc_hdl, VIRTCHNL_ADV_OP_ADD_RSS_CFG, rss_cfg,
		    sizeof (*rss_cfg), 0, 0);

  return ret;
}

int
avf_rss_rule_destroy (struct avf_flow_vc_ctx *ctx,
		      struct virtchnl_rss_cfg *rss_cfg)
{
  int ret;

  ret = ctx->vc_op (ctx->vc_hdl, VIRTCHNL_ADV_OP_DEL_RSS_CFG, rss_cfg,
		    sizeof (*rss_cfg), 0, 0);

  return ret;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
