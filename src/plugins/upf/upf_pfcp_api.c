/*
 * Copyright(c) 2018 Travelping GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>

#include "pfcp.h"
#include "upf_pfcp.h"
#include "upf_pfcp_server.h"
#include "upf_pfcp_api.h"
#include "upf_adf.h"

#if CLIB_DEBUG > 0
#define gtp_debug clib_warning
#else
#define gtp_debug(...)				\
  do { } while (0)
#endif

#define API_VERSION      1

typedef struct {
  time_t start_time;
} upf_pfcp_session_t;

static int node_msg(sx_msg_t * msg);
static int session_msg(sx_msg_t * msg);

size_t upf_pfcp_api_session_data_size()
{
	return sizeof(upf_pfcp_session_t);
}

void upf_pfcp_api_session_data_init(void *sxp, time_t start_time)
{
	upf_pfcp_session_t *sx = (upf_pfcp_session_t *)sxp;

	memset(sx, 0, sizeof(*sx));
	sx->start_time = start_time;
}

static void init_response_node_id(struct pfcp_response *r)
{
  //TODO: need CLI/API to set local Node-Id.....
}

/*************************************************************************/

int upf_pfcp_handle_msg(sx_msg_t * msg)
{
  switch (msg->hdr->type)
    {
    case PFCP_HEARTBEAT_REQUEST:
    case PFCP_HEARTBEAT_RESPONSE:
    case PFCP_PFD_MANAGEMENT_REQUEST:
    case PFCP_PFD_MANAGEMENT_RESPONSE:
    case PFCP_ASSOCIATION_SETUP_REQUEST:
    case PFCP_ASSOCIATION_SETUP_RESPONSE:
    case PFCP_ASSOCIATION_UPDATE_REQUEST:
    case PFCP_ASSOCIATION_UPDATE_RESPONSE:
    case PFCP_ASSOCIATION_RELEASE_REQUEST:
    case PFCP_ASSOCIATION_RELEASE_RESPONSE:
    case PFCP_VERSION_NOT_SUPPORTED_RESPONSE:
    case PFCP_NODE_REPORT_REQUEST:
    case PFCP_NODE_REPORT_RESPONSE:
      return node_msg(msg);

    case PFCP_SESSION_SET_DELETION_REQUEST:
    case PFCP_SESSION_SET_DELETION_RESPONSE:
    case PFCP_SESSION_ESTABLISHMENT_REQUEST:
    case PFCP_SESSION_ESTABLISHMENT_RESPONSE:
    case PFCP_SESSION_MODIFICATION_REQUEST:
    case PFCP_SESSION_MODIFICATION_RESPONSE:
    case PFCP_SESSION_DELETION_REQUEST:
    case PFCP_SESSION_DELETION_RESPONSE:
    case PFCP_SESSION_REPORT_REQUEST:
    case PFCP_SESSION_REPORT_RESPONSE:
      return session_msg(msg);

    default:
      gtp_debug ("PFCP: msg type invalid: %d.", msg->hdr->type);
      break;
    }

  return -1;
}

/*************************************************************************/

static uword
unformat_ipfilter_address_port (unformat_input_t * i, va_list * args)
{
  ipfilter_address_t *ip = va_arg (*args, ipfilter_address_t *);
  ipfilter_port_t *port  = va_arg (*args, ipfilter_port_t *);

  ip->mask = ~0;
  port->min = 0;
  port->max = ~0;

  if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
    return 0;

  if (!unformat(i, "%U", unformat_ip46_address, &ip->address, IP46_TYPE_ANY))
    return 0;

  ip->mask = ip46_address_is_ip4(&ip->address) ? 32 : 128;
  if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
    return 1;
  if (unformat(i, "/%d", &ip->mask))
    ;

  if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
    return 1;
  if (unformat(i, "%d-%d", &port->min, &port->max))
    ;
  else if (unformat(i, "%d", &port->min))
    port->max = port->min;

  return 1;
}

static uword
unformat_ipfilter(unformat_input_t * i, acl_rule_t * acl)
{
  int step = 0;

  /* action dir proto from src to dst [options] */
  while (step < 5 && unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      switch (step)
	{
	case 0:			/* action */
	  if (unformat (i, "permit"))
	    {
	      acl->action = ACL_PERMIT;
	    }
	  else if (unformat (i, "deny"))
	    {
	      acl->action = ACL_DENY;
	    }
	  else
	    return 0;

	break;

      case 1:			/* dir */
	if (unformat (i, "in"))
	  {
	    acl->direction = ACL_IN;
	  }
	else if (unformat (i, "out"))
	  {
	    acl->direction = ACL_OUT;
	  }
	else
	  return 0;

	break;

      case 2:			/* proto */
	if (unformat (i, "ip"))
	  {
	    acl->proto = ~0;
	  }
	else if (unformat (i, "%u", &acl->proto))
	  ;
	else
	  return 0;

	break;

      case 3:			/* from src */
	if (unformat (i, "from any"))
	  {
	    acl->src_address = ACL_FROM_ANY;
	    acl->src_port.min = 0;
	    acl->src_port.max = ~0;
	  }
	else if (unformat (i, "from %U", unformat_ipfilter_address_port,
			   &acl->src_address, &acl->src_port))
	  ;
	else
	  return 0;

	break;

      case 4:
	if (unformat (i, "to assigned"))
	  {
	    acl->dst_address = ACL_TO_ASSIGNED;
	    acl->dst_port.min = 0;
	    acl->dst_port.max = ~0;
	  }
	else if (unformat (i, "to %U", unformat_ipfilter_address_port,
			   &acl->dst_address, &acl->dst_port))
	  ;
	else
	  return 0;

	break;

      default:
	return 0;
      }

      step++;
    }

  return 1;
}

static u8 *
format_ipfilter_address_port(u8 * s,va_list * args)
{
  ipfilter_address_t *ip = va_arg (*args, ipfilter_address_t *);
  ipfilter_port_t *port  = va_arg (*args, ipfilter_port_t *);
  int direction          = va_arg (*args, int);

  if (direction == 0 &&
      ipfilter_address_cmp_const(ip, ACL_FROM_ANY) == 0)
    {
      s = format(s, "any");
    }
  else if (direction == 1 &&
	   ipfilter_address_cmp_const(ip, ACL_TO_ASSIGNED) == 0)
    {
      s = format(s, "assigned");
    }
  else
    {
      s = format(s, "%U", format_ip46_address, &ip->address, IP46_TYPE_ANY);
      if (ip->mask != (ip46_address_is_ip4(&ip->address) ? 32 : 128))
	s = format(s, "/%u", ip->mask);
    }

  if (port->min != 0 || port->max != (u16)~0)
    {
      s = format(s, " %d", port->min);
      if (port->min != port->max)
	s = format(s, "-%d", port->max);
    }

  return s;
}

u8 *
format_ipfilter(u8 * s, va_list * args)
{
  acl_rule_t * acl = va_arg (*args, acl_rule_t *);

  switch (acl->action)
    {
    case ACL_PERMIT:
      s = format(s, "permit ");
      break;

    case ACL_DENY:
      s = format(s, "deny ");
      break;

    default:
      s = format(s, "action_%d ", acl->action);
      break;
    }

  switch (acl->direction)
    {
    case ACL_IN:
      s = format(s, "in ");
      break;

    case ACL_OUT:
      s = format(s, "out ");
      break;

    default:
      s = format(s, "direction_%d ", acl->direction);
      break;
    }

  if (acl->proto == (u8)~0)
    s = format(s, "ip ");
  else
    s = format(s, "%d ", acl->proto);

  s = format(s, "from %U ", format_ipfilter_address_port,
	     &acl->src_address, &acl->src_port, 0);
  s = format(s, "to %U ", format_ipfilter_address_port,
	     &acl->dst_address, &acl->dst_port, 1);

  return s;
}

/*************************************************************************/

/* message helpers */

static void
build_user_plane_ip_resource_information(pfcp_user_plane_ip_resource_information_t **upip)
{
  upf_main_t * gtm = &upf_main;
  upf_nwi_t * nwi;

  pool_foreach (nwi, gtm->nwis,
    ({
      upf_nwi_ip_res_t * ip_res;

      pool_foreach (ip_res, nwi->ip_res,
	({
	  pfcp_user_plane_ip_resource_information_t *r;

	  vec_alloc(*upip, 1);
	  r = vec_end(*upip);

	  r->network_instance = vec_dup(nwi->name);
	  if (ip_res->mask != 0)
	    {
	      r->teid_range_indication = __builtin_popcount(ip_res->mask);
	      r->teid_range = (ip_res->teid >> 24);
	    }

	  if (ip46_address_is_ip4 (&ip_res->ip))
	    {
	      r->flags |= USER_PLANE_IP_RESOURCE_INFORMATION_V4;
	      r->ip4 = ip_res->ip.ip4;
	    }
	  else
	    {
	      r->flags |= USER_PLANE_IP_RESOURCE_INFORMATION_V6;
	      r->ip6 = ip_res->ip.ip6;
	    }

	  _vec_len(*upip)++;
	}));
    }));
}

/* message handlers */

static int
handle_heartbeat_request(sx_msg_t * req, pfcp_heartbeat_request_t *msg)
{
  sx_server_main_t *sx = &sx_server_main;
  pfcp_heartbeat_response_t resp;

  memset(&resp, 0, sizeof(resp));
  SET_BIT(resp.grp.fields, HEARTBEAT_RESPONSE_RECOVERY_TIME_STAMP);
  resp.recovery_time_stamp = sx->start_time;

  gtp_debug ("PFCP: start_time: %p, %d, %x.",
		&sx, sx->start_time, sx->start_time);

  upf_pfcp_send_response(req, 0, PFCP_HEARTBEAT_RESPONSE, &resp.grp);

  return 0;
}

static int
handle_heartbeat_response(sx_msg_t * req, pfcp_heartbeat_response_t *msg)
{
  upf_main_t *gtm = &upf_main;
  upf_node_assoc_t *n;

  if (req->node == ~0 || pool_is_free_index (gtm->nodes, req->node))
    return -1;

  n = pool_elt_at_index (gtm->nodes, req->node);

  if (msg->recovery_time_stamp > n->recovery_time_stamp)
    sx_release_association(n);
  else if (msg->recovery_time_stamp < n->recovery_time_stamp)
    {
      /* 3GPP TS 23.007, Sect. 19A:
       *
       * If the value of a Recovery Time Stamp previously stored for a peer is larger
       * than the Recovery Time Stamp value received in the Heartbeat Response message
       * or the PFCP message, this indicates a possible race condition (newer message
       * arriving before the older one). The received Sx node related message and the
       * received new Recovery Time Stamp value shall be discarded and an error may
       * be logged.
       */
      return -1;
    }
  else
    {
      clib_warning("restarting HB timer\n");
      n->heartbeat_handle = upf_pfcp_server_start_timer
	(PFCP_SERVER_HB_TIMER, n - gtm->nodes, PFCP_HB_INTERVAL);
    }

  return 0;
}

static int
handle_pfd_management_request(sx_msg_t * req, pfcp_pfd_management_request_t *msg)
{
  return -1;
}

static int
handle_pfd_management_response(sx_msg_t * req, pfcp_pfd_management_response_t *msg)
{
  return -1;
}

static int
handle_association_setup_request(sx_msg_t * req, pfcp_association_setup_request_t *msg)
{
  sx_server_main_t *sx = &sx_server_main;
  pfcp_association_setup_response_t resp;
  upf_main_t *gtm = &upf_main;
  upf_node_assoc_t *n;
  int r = 0;

  memset(&resp, 0, sizeof(resp));
  SET_BIT(resp.grp.fields, ASSOCIATION_SETUP_RESPONSE_CAUSE);
  resp.response.cause = PFCP_CAUSE_REQUEST_REJECTED;

  init_response_node_id(&resp.response);

  SET_BIT(resp.grp.fields, ASSOCIATION_SETUP_RESPONSE_RECOVERY_TIME_STAMP);
  resp.recovery_time_stamp = sx->start_time;

  n = sx_get_association(&msg->request.node_id);
  if (n)
    {
      if (msg->recovery_time_stamp > n->recovery_time_stamp)
	sx_release_association(n);
      else if (msg->recovery_time_stamp == n->recovery_time_stamp)
	{
	  r = -1;
	  /* TODO: handle late resend ???? */
	  goto out_send_resp;
	}
      else if (msg->recovery_time_stamp < n->recovery_time_stamp)
	{
	  /* 3GPP TS 23.007, Sect. 19A:
	   *
	   * If the value of a Recovery Time Stamp previously stored for a peer is larger
	   * than the Recovery Time Stamp value received in the Heartbeat Response message
	   * or the PFCP message, this indicates a possible race condition (newer message
	   * arriving before the older one). The received Sx node related message and the
	   * received new Recovery Time Stamp value shall be discarded and an error may
	   * be logged.
	   */
	  return -1;
	}
    }

  n = sx_new_association(req->fib_index, &req->lcl.address, &req->rmt.address,
			 &msg->request.node_id);
  n->recovery_time_stamp = msg->recovery_time_stamp;

  SET_BIT(resp.grp.fields, ASSOCIATION_SETUP_RESPONSE_UP_FUNCTION_FEATURES);
  resp.up_function_features |= F_UPFF_EMPU;
  /* currently no optional features are supported */

  build_user_plane_ip_resource_information(&resp.user_plane_ip_resource_information);
  if (vec_len(resp.user_plane_ip_resource_information) != 0)
    SET_BIT(resp.grp.fields, ASSOCIATION_SETUP_RESPONSE_USER_PLANE_IP_RESOURCE_INFORMATION);

 out_send_resp:
  if (r == 0)
    {
      n->heartbeat_handle = upf_pfcp_server_start_timer
	(PFCP_SERVER_HB_TIMER, n - gtm->nodes, PFCP_HB_INTERVAL);

      resp.response.cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    }

  upf_pfcp_send_response(req, 0, PFCP_ASSOCIATION_SETUP_RESPONSE, &resp.grp);

  return r;
}

static int
handle_association_setup_response(sx_msg_t * req, pfcp_association_setup_response_t *msg)
{
  return -1;
}

static int
handle_association_update_request(sx_msg_t * req, pfcp_association_update_request_t *msg)
{
  return -1;
}

static int
handle_association_update_response(sx_msg_t * req, pfcp_association_update_response_t *msg)
{
  return -1;
}

static int
handle_association_release_request(sx_msg_t * req, pfcp_association_release_request_t *msg)
{
  return -1;
}

static int
handle_association_release_response(sx_msg_t * req, pfcp_association_release_response_t *msg)
{
  return -1;
}

#if 0
static int
handle_version_not_supported_response(sx_msg_t * req, pfcp_version_not_supported_response_t *msg)
{
  return -1;
}
#endif

static int
handle_node_report_request(sx_msg_t * req, pfcp_node_report_request_t *msg)
{
  return -1;
}

static int
handle_node_report_response(sx_msg_t * req, pfcp_node_report_response_t *msg)
{
  return -1;
}

static int node_msg(sx_msg_t * msg)
{
  union {
    struct pfcp_group grp;
    pfcp_heartbeat_request_t heartbeat_request;
    pfcp_heartbeat_response_t heartbeat_response;
    pfcp_pfd_management_request_t pfd_management_request;
    pfcp_pfd_management_response_t pfd_management_response;
    pfcp_association_setup_request_t association_setup_request;
    pfcp_association_setup_response_t association_setup_response;
    pfcp_association_update_request_t association_update_request;
    pfcp_association_update_response_t association_update_response;
    pfcp_association_release_request_t association_release_request;
    pfcp_association_release_response_t association_release_response;
    /* pfcp_version_not_supported_response_t version_not_supported_response; */
    pfcp_node_report_request_t node_report_request;
    pfcp_node_report_response_t node_report_response;
  } m;
  int r = 0;

  if (msg->hdr->s_flag)
    {
      gtp_debug ("PFCP: node msg with SEID.");
      return -1;
    }

  memset(&m, 0, sizeof(m));
  r = pfcp_decode_msg(msg->hdr->type, &msg->hdr->msg_hdr.ies[0],
		      clib_net_to_host_u16(msg->hdr->length) - sizeof(msg->hdr->msg_hdr), &m.grp);
  if (r != 0)
    {
      //TODO: error reply
      pfcp_free_msg(msg->hdr->type, &m.grp);
      return r;
    }

  switch (msg->hdr->type)
    {
    case PFCP_HEARTBEAT_REQUEST:
      r = handle_heartbeat_request(msg, &m.heartbeat_request);
      break;

    case PFCP_HEARTBEAT_RESPONSE:
      r = handle_heartbeat_response(msg, &m.heartbeat_response);
      break;

    case PFCP_PFD_MANAGEMENT_REQUEST:
      r = handle_pfd_management_request(msg, &m.pfd_management_request);
      break;

    case PFCP_PFD_MANAGEMENT_RESPONSE:
      r = handle_pfd_management_response(msg, &m.pfd_management_response);
      break;

    case PFCP_ASSOCIATION_SETUP_REQUEST:
      r = handle_association_setup_request(msg, &m.association_setup_request);
      break;

    case PFCP_ASSOCIATION_SETUP_RESPONSE:
      r = handle_association_setup_response(msg, &m.association_setup_response);
      break;

    case PFCP_ASSOCIATION_UPDATE_REQUEST:
      r = handle_association_update_request(msg, &m.association_update_request);
      break;

    case PFCP_ASSOCIATION_UPDATE_RESPONSE:
      r = handle_association_update_response(msg, &m.association_update_response);
      break;

    case PFCP_ASSOCIATION_RELEASE_REQUEST:
      r = handle_association_release_request(msg, &m.association_release_request);
      break;

    case PFCP_ASSOCIATION_RELEASE_RESPONSE:
      r = handle_association_release_response(msg, &m.association_release_response);
      break;

    /* case PFCP_VERSION_NOT_SUPPORTED_RESPONSE: */
    /*   r = handle_version_not_supported_response(msg, &m.version_not_supported_response); */
    /*   break; */

    case PFCP_NODE_REPORT_REQUEST:
      r = handle_node_report_request(msg, &m.node_report_request);
      break;

    case PFCP_NODE_REPORT_RESPONSE:
      r = handle_node_report_response(msg, &m.node_report_response);
      break;

    default:
      break;
    }

  pfcp_free_msg(msg->hdr->type, &m.grp);
  return 0;
}

#define OPT(MSG,FIELD,VALUE,DEFAULT)					\
  ((ISSET_BIT((MSG)->grp.fields, (FIELD))) ? MSG->VALUE : (DEFAULT))

static upf_nwi_t *lookup_nwi(u8 * name)
{
  upf_main_t * gtm = &upf_main;
  upf_nwi_t * nwi;
  uword *p;

  if (pool_elts(gtm->nwis) == 0)
    return NULL;

  if (!name)
    {
      pool_foreach (nwi, gtm->nwis,
      ({
	/* return first network instance */
	return nwi;
      }));
      return NULL;
    }

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (!p)
    return NULL;

  return pool_elt_at_index (gtm->nwis, p[0]);
}

static u8 src_to_intf(u8 src)
{
  switch (src)
    {
    case SRC_INTF_ACCESS:
      return INTF_ACCESS;
    case SRC_INTF_CORE:
      return INTF_CORE;
    case SRC_INTF_SGI_LAN:
      return INTF_SGI_LAN;
    case SRC_INTF_CP:
      return INTF_CP;
    }
  return 0;
}

static u8 dst_to_intf(u8 dst)
{
  switch (dst)
    {
    case DST_INTF_ACCESS:
      return INTF_ACCESS;
    case DST_INTF_CORE:
      return INTF_CORE;
    case DST_INTF_SGI_LAN:
      return INTF_SGI_LAN;
    case DST_INTF_CP:
      return INTF_CP;
    case DST_INTF_LI:
      return INTF_LI;
    }
  return 0;
}

static int handle_create_pdr(upf_session_t *sess, pfcp_create_pdr_t *create_pdr,
			     struct pfcp_group *grp,
			     int failed_rule_id_field,
			     pfcp_failed_rule_id_t *failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *)(grp + 1);
  upf_main_t *gtm = &upf_main;
  pfcp_create_pdr_t *pdr;
  int r = 0;

  vec_foreach(pdr, create_pdr)
    {
      upf_pdr_t *create;
      upf_nwi_t *nwi;

      create = clib_mem_alloc_no_fail(sizeof(*create));
      memset(create, 0, sizeof(*create));

      nwi = lookup_nwi(
	      ISSET_BIT(pdr->pdi.grp.fields, PDI_NETWORK_INSTANCE) ?
	      pdr->pdi.network_instance : NULL);
      if (!nwi)
	{
	  gtp_debug("PDR: %d, PDI for unknown network instance\n", pdr->pdr_id);
	  if (ISSET_BIT(pdr->pdi.grp.fields, PDI_NETWORK_INSTANCE))
		  gtp_debug("NWI: %v (%d)", pdr->pdi.network_instance,
			    vec_len(pdr->pdi.network_instance));
	  failed_rule_id->id = pdr->pdr_id;
	  break;
	}

      create->id = pdr->pdr_id;
      create->precedence = pdr->precedence;

      create->pdi.nwi = nwi - gtm->nwis;
      create->pdi.src_sw_if_index =
	      nwi->intf_sw_if_index[src_to_intf(pdr->pdi.source_interface)];
      if (create->pdi.src_sw_if_index == (u32)~0)
	{
	  gtp_debug("PDR: %d, PDI Source Interface %d has not been configured\n",
		    pdr->pdr_id, pdr->pdi.source_interface);
	  failed_rule_id->id = pdr->pdr_id;
	  break;
	}
      create->pdi.src_intf = pdr->pdi.source_interface;

      if (ISSET_BIT(pdr->pdi.grp.fields, PDI_F_TEID))
	{
	  create->pdi.fields |= F_PDI_LOCAL_F_TEID;
	  /* TODO validate TEID and mask
	  if (nwi->teid != (pdr->pdi.f_teid.teid & nwi->mask))
	    {
	      gtp_debug("PDR: %d, TEID not within configure partition\n", pdr->pdr_id);
	      failed_rule_id->id = pdr->pdr_id;
	      break;
	    }
	  */
	  create->pdi.teid = pdr->pdi.f_teid;
	}
      if (ISSET_BIT(pdr->pdi.grp.fields, PDI_UE_IP_ADDRESS))
	{
	  create->pdi.fields |= F_PDI_UE_IP_ADDR;
	  create->pdi.ue_addr = pdr->pdi.ue_ip_address;
	}
      if (ISSET_BIT(pdr->pdi.grp.fields, PDI_SDF_FILTER))
	{
	  unformat_input_t sdf;

	  create->pdi.fields |= F_PDI_SDF_FILTER;

	  unformat_init_vector(&sdf, pdr->pdi.sdf_filter.flow);
	  if (!unformat_ipfilter(&sdf, &create->pdi.acl))
	    {
	      gtp_debug("failed to parse SDF '%s'", pdr->pdi.sdf_filter.flow);
	      r = -1;
	      break;
	    }
	}

	if (ISSET_BIT(pdr->pdi.grp.fields, PDI_APPLICATION_ID))
	  {
	    uword *p = NULL;
	    create->pdi.fields |= F_PDI_APPLICATION_ID;

	    p = hash_get_mem (gtm->upf_app_by_name, pdr->pdi.application_id);
	    if (!p)
	      {
		failed_rule_id->id = pdr->pdr_id;
		r = -1;
		fformat(stderr, "PDR: %d, application id %v has not been configured\n",
			pdr->pdr_id, pdr->pdi.application_id);
		break;
	      }

	    ASSERT(!pool_is_free_index (gtm->upf_apps, p[0]));
	    create->pdi.adr.application_id = p[0];
	    create->pdi.adr.db_id = upf_adf_get_adr_db(p[0]);

#if CLIB_DEBUG > 0
	      {
		upf_adf_app_t *app = pool_elt_at_index (gtm->upf_apps, p[0]);
		gtp_debug("app: %v, ADR DB id %u", app->name, create->pdi.adr.db_id);
	      }
#endif
	  }

      create->outer_header_removal = OPT(pdr, CREATE_PDR_OUTER_HEADER_REMOVAL,
					 outer_header_removal, ~0);
      create->far_id = OPT(pdr, CREATE_PDR_FAR_ID, far_id, ~0);
      if (ISSET_BIT(pdr->grp.fields, CREATE_PDR_URR_ID))
	{
	  pfcp_urr_id_t *urr_id;

	  vec_foreach(urr_id, pdr->urr_id)
	    {
	      vec_add1(create->urr_ids, *urr_id);
	    }
	}

      // CREATE_PDR_QER_ID
      // CREATE_PDR_ACTIVATE_PREDEFINED_RULES

      if ((r = sx_create_pdr(sess, create)) != 0)
	{
	  gtp_debug("Failed to add PDR %d\n", pdr->pdr_id);
	  failed_rule_id->id = pdr->pdr_id;
	  break;
	}
    }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT(grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_PDR;
    }

  return r;
}

static int handle_update_pdr(upf_session_t *sess, pfcp_update_pdr_t *update_pdr,
			     struct pfcp_group *grp,
			     int failed_rule_id_field,
			     pfcp_failed_rule_id_t *failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *)(grp + 1);
  upf_main_t *gtm = &upf_main;
  pfcp_update_pdr_t *pdr;
  int r = 0;

  vec_foreach(pdr, update_pdr)
    {
      upf_pdr_t *update;
      upf_nwi_t *nwi;

      update = sx_get_pdr(sess, SX_PENDING, pdr->pdr_id);
      if (!update)
	{
	  gtp_debug("Sx Session %"PRIu64", update PDR Id %d not found.\n",
		    sess->cp_seid, pdr->pdr_id);
	  failed_rule_id->id = pdr->pdr_id;
	  r = -1;
	  break;
	}

      if (ISSET_BIT(pdr->pdi.grp.fields, PDI_NETWORK_INSTANCE))
	{
	  nwi = lookup_nwi(pdr->pdi.network_instance);
	  if (!nwi)
	    {
	      gtp_debug("PDR: %d, PDI for unknown network instance\n", pdr->pdr_id);
	      failed_rule_id->id = pdr->pdr_id;
	      break;
	    }
	  update->pdi.nwi = nwi - gtm->nwis;
	}
      else
	nwi = pool_elt_at_index (gtm->nwis, update->pdi.nwi);

      update->precedence = pdr->precedence;
      update->pdi.src_sw_if_index =
	      nwi->intf_sw_if_index[src_to_intf(pdr->pdi.source_interface)];
      if (update->pdi.src_sw_if_index == (u32)~0)
	{
	  gtp_debug("PDR: %d, PDI Source Interface %d has not been configured\n",
		    pdr->pdr_id, pdr->pdi.source_interface);
	  failed_rule_id->id = pdr->pdr_id;
	  break;
	}
      update->pdi.src_intf = pdr->pdi.source_interface;

      if (ISSET_BIT(pdr->pdi.grp.fields, PDI_F_TEID))
	{
	  update->pdi.fields |= F_PDI_LOCAL_F_TEID;
	  /* TODO validate TEID and mask */
	  update->pdi.teid = pdr->pdi.f_teid;
	}
      if (ISSET_BIT(pdr->pdi.grp.fields, PDI_UE_IP_ADDRESS))
	{
	  update->pdi.fields |= F_PDI_UE_IP_ADDR;
	  update->pdi.ue_addr = pdr->pdi.ue_ip_address;
	}
      if (ISSET_BIT(pdr->pdi.grp.fields, PDI_SDF_FILTER))
	{
	  unformat_input_t sdf;

	  update->pdi.fields |= F_PDI_SDF_FILTER;

	  unformat_init_vector(&sdf, pdr->pdi.sdf_filter.flow);
	  if (!unformat_ipfilter(&sdf, &update->pdi.acl))
	    {
	      gtp_debug("failed to parse SDF '%s'", pdr->pdi.sdf_filter.flow);
	      r = -1;
	      break;
	    }
	}

      if (ISSET_BIT(pdr->pdi.grp.fields, PDI_APPLICATION_ID))
	{
	  uword *p = NULL;

	  update->pdi.fields |= F_PDI_APPLICATION_ID;

	  p = hash_get_mem (gtm->upf_app_by_name, pdr->pdi.application_id);
	  if (!p)
	    {
	      failed_rule_id->id = pdr->pdr_id;
	      r = -1;
	      fformat(stderr, "PDR: %d, application id %v has not been configured\n",
		      pdr->pdr_id, pdr->pdi.application_id);
	      break;
	    }

	  ASSERT(!pool_is_free_index (gtm->upf_apps, p[0]));
	  update->pdi.adr.application_id = p[0];
	  update->pdi.adr.db_id =  upf_adf_get_adr_db(p[0]);

#if CLIB_DEBUG > 0
	  {
	    upf_adf_app_t *app = pool_elt_at_index (gtm->upf_apps, p[0]);
	    gtp_debug("app: %v, ADR DB id %u", app->name, update->pdi.adr.db_id);
	  }
#endif
	}

      update->outer_header_removal = OPT(pdr, UPDATE_PDR_OUTER_HEADER_REMOVAL,
					 outer_header_removal, ~0);
      update->far_id = OPT(pdr, UPDATE_PDR_FAR_ID, far_id, ~0);
      if (ISSET_BIT(pdr->grp.fields, UPDATE_PDR_URR_ID))
	{
	  pfcp_urr_id_t *urr_id;

	  vec_foreach(urr_id, pdr->urr_id)
	    {
	      vec_add1(update->urr_ids, *urr_id);
	    }
	}

      // UPDATE_PDR_QER_ID
      // UPDATE_PDR_ACTIVATE_PREDEFINED_RULES
    }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT(grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_PDR;
    }

  return r;
}

static int handle_remove_pdr(upf_session_t *sess, pfcp_remove_pdr_t *remove_pdr,
			     struct pfcp_group *grp,
			     int failed_rule_id_field,
			     pfcp_failed_rule_id_t *failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *)(grp + 1);
  pfcp_remove_pdr_t *pdr;
  int r = 0;

  vec_foreach(pdr, remove_pdr)
    {
      if ((r = sx_delete_pdr(sess, pdr->pdr_id)) != 0)
	{
	  gtp_debug("Failed to add PDR %d\n", pdr->pdr_id);
	  failed_rule_id->id = pdr->pdr_id;
	  break;
	}
    }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT(grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_PDR;
    }

  return r;
}

static void
ip_udp_gtpu_rewrite (upf_far_forward_t * ff)
{
  union
  {
    ip4_gtpu_header_t *h4;
    ip6_gtpu_header_t *h6;
    u8 *rw;
  } r =
  {
  .rw = 0};
  u8 is_ip4 = !!(ff->outer_header_creation.description & OUTER_HEADER_CREATION_IP4);
  int len = is_ip4 ? sizeof *r.h4 : sizeof *r.h6;
  u32 sw_if_index = ff->dst_sw_if_index;

  vec_validate_aligned (r.rw, len - 1, CLIB_CACHE_LINE_BYTES);

  udp_header_t *udp;
  gtpu_header_t *gtpu;
  /* Fixed portion of the (outer) ip header */
  if (is_ip4)
    {
      ip4_header_t *ip = &r.h4->ip4;
      udp = &r.h4->udp;
      gtpu = &r.h4->gtpu;
      ip->ip_version_and_header_length = 0x45;
      ip->ttl = 254;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address = *(ip4_address_t *)ip_interface_get_first_ip (sw_if_index, 1);
      ip->dst_address = ff->outer_header_creation.ip4;

      /* we fix up the ip4 header length and checksum after-the-fact */
      ip->checksum = ip4_header_checksum (ip);
    }
  else
    {
      ip6_header_t *ip = &r.h6->ip6;
      udp = &r.h6->udp;
      gtpu = &r.h6->gtpu;
      ip->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      ip->hop_limit = 255;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address = *(ip6_address_t *)ip_interface_get_first_ip (sw_if_index, 0);
      ip->dst_address = ff->outer_header_creation.ip6;
    }

  /* UDP header, randomize src port on something, maybe? */
  udp->src_port = clib_host_to_net_u16 (2152);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_GTPU);

  /* GTPU header */
  gtpu->ver_flags = GTPU_V1_VER | GTPU_PT_GTP;
  gtpu->type = GTPU_TYPE_GTPU;
  gtpu->teid = clib_host_to_net_u32 (ff->outer_header_creation.teid);

  ff->rewrite = r.rw;

  /* For now only support 8-byte gtpu header. TBD */
  _vec_len (ff->rewrite) = len - 4;

  return;
}

static int handle_create_far(upf_session_t *sess, pfcp_create_far_t *create_far,
			     struct pfcp_group *grp,
			     int failed_rule_id_field,
			     pfcp_failed_rule_id_t *failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *)(grp + 1);
  upf_main_t *gtm = &upf_main;
  pfcp_create_far_t *far;
  int r = 0;

  vec_foreach(far, create_far)
    {
      upf_far_t *create;

      create = clib_mem_alloc_no_fail(sizeof(*create));
      memset(create, 0, sizeof(*create));

      create->id = far->far_id;
      create->apply_action = far->apply_action;

      if ((create->apply_action & FAR_FORWARD) &&
	  far->grp.fields & CREATE_FAR_FORWARDING_PARAMETERS)
	{
	  upf_nwi_t *nwi;

	  nwi = lookup_nwi(
			   ISSET_BIT(far->forwarding_parameters.grp.fields,
				     FORWARDING_PARAMETERS_NETWORK_INSTANCE) ?
			   far->forwarding_parameters.network_instance : NULL);
	  if (!nwi)
	    {
	      gtp_debug("FAR: %d, Parameter with unknown network instance\n",
			far->far_id);
	      failed_rule_id->id = far->far_id;
	      break;
	    }

	  create->forward.nwi = nwi - gtm->nwis;
	  create->forward.dst_sw_if_index =
	    nwi->intf_sw_if_index[dst_to_intf(far->forwarding_parameters.destination_interface)];
	  if (create->forward.dst_sw_if_index == (u32)~0)
	    {
	      gtp_debug("FAR: %d, Destination Interface %d has not been configured\n",
			far->far_id, far->forwarding_parameters.destination_interface);
	      failed_rule_id->id = far->far_id;
	      break;
	    }
	  create->forward.dst_intf = far->forwarding_parameters.destination_interface;

	  //TODO: redirect_information
	  if (ISSET_BIT(far->forwarding_parameters.grp.fields,
			FORWARDING_PARAMETERS_OUTER_HEADER_CREATION))
	    {
	      create->forward.flags |= FAR_F_OUTER_HEADER_CREATION;
	      create->forward.outer_header_creation =
		far->forwarding_parameters.outer_header_creation;

	      ip_udp_gtpu_rewrite(&create->forward);
	    }
	  //TODO: transport_level_marking
	  //TODO: forwarding_policy
	  //TODO: header_enrichment
	}

      if ((r = sx_create_far(sess, create)) != 0)
	{
	  gtp_debug("Failed to add FAR %d\n", far->far_id);
	  failed_rule_id->id = far->far_id;
	  break;
	}
    }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT(grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_FAR;
    }

  return r;
}

static int handle_update_far(upf_session_t *sess, pfcp_update_far_t *update_far,
			     struct pfcp_group *grp,
			     int failed_rule_id_field,
			     pfcp_failed_rule_id_t *failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *)(grp + 1);
  upf_main_t *gtm = &upf_main;
  pfcp_update_far_t *far;
  int r = 0;

  vec_foreach(far, update_far)
    {
      upf_far_t *update;

      update = sx_get_far(sess, SX_PENDING, far->far_id);
      if (!update)
	{
	  gtp_debug("Sx Session %"PRIu64", update FAR Id %d not found.\n",
		    sess->cp_seid, far->far_id);
	  failed_rule_id->id = far->far_id;
	  r = -1;
	  break;
	}

      update->apply_action = far->apply_action;

      if ((update->apply_action & FAR_FORWARD) &&
	  far->grp.fields & UPDATE_FAR_UPDATE_FORWARDING_PARAMETERS)
	{
	  upf_nwi_t *nwi;

	  if (ISSET_BIT(far->update_forwarding_parameters.grp.fields,
			UPDATE_FORWARDING_PARAMETERS_NETWORK_INSTANCE))
	    {
	      nwi = lookup_nwi(far->update_forwarding_parameters.network_instance);
	      if (!nwi)
		{
		  gtp_debug("FAR: %d, Update Parameter with unknown network instance\n",
			    far->far_id);
		  failed_rule_id->id = far->far_id;
		  break;
		}
	      update->forward.nwi = nwi - gtm->nwis;
	    }
	  else
	    nwi = pool_elt_at_index (gtm->nwis, update->forward.nwi);

	  update->forward.dst_sw_if_index =
	    nwi->intf_sw_if_index
	    [dst_to_intf(far->update_forwarding_parameters.destination_interface)];
	  if (update->forward.dst_sw_if_index == (u32)~0)
	    {
	      gtp_debug("FAR: %d, Destination Interface %d has not been configured\n",
			far->far_id, far->update_forwarding_parameters.destination_interface);
	      failed_rule_id->id = far->far_id;
	      break;
	    }
	  update->forward.dst_intf = far->update_forwarding_parameters.destination_interface;

	  //TODO: redirect_information
	  if (ISSET_BIT(far->update_forwarding_parameters.grp.fields,
			UPDATE_FORWARDING_PARAMETERS_OUTER_HEADER_CREATION))
	    {
	      if (ISSET_BIT(far->update_forwarding_parameters.grp.fields,
			    UPDATE_FORWARDING_PARAMETERS_SXSMREQ_FLAGS) &&
		  far->update_forwarding_parameters.sxsmreq_flags & SXSMREQ_SNDEM)
		sx_send_end_marker(sess, far->far_id);

	      update->forward.flags |= FAR_F_OUTER_HEADER_CREATION;
	      update->forward.outer_header_creation =
		far->update_forwarding_parameters.outer_header_creation;

	      ip_udp_gtpu_rewrite(&update->forward);
	    }
	  //TODO: transport_level_marking
	  //TODO: forwarding_policy
	  //TODO: header_enrichment
	}
    }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT(grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_FAR;
    }

  return r;
}

static int handle_remove_far(upf_session_t *sess, pfcp_remove_far_t *remove_far,
			     struct pfcp_group *grp,
			     int failed_rule_id_field,
			     pfcp_failed_rule_id_t *failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *)(grp + 1);
  pfcp_remove_far_t *far;
  int r = 0;

  vec_foreach(far, remove_far)
    {
      if ((r = sx_delete_far(sess, far->far_id)) != 0)
	{
	  gtp_debug("Failed to add FAR %d\n", far->far_id);
	  failed_rule_id->id = far->far_id;
	  break;
	}
    }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT(grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_FAR;
    }

  return r;
}

static int handle_create_urr(upf_session_t *sess, pfcp_create_urr_t *create_urr, f64 now,
			     struct pfcp_group *grp,
			     int failed_rule_id_field,
			     pfcp_failed_rule_id_t *failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *)(grp + 1);
  pfcp_create_urr_t *urr;
  int r = 0;

  vec_foreach(urr, create_urr)
    {
      upf_urr_t *create;

      create = clib_mem_alloc_no_fail(sizeof(*create));
      memset(create, 0, sizeof(*create));

      create->measurement_period.handle =
	      create->monitoring_time.handle =
	      create->time_threshold.handle =
	      create->time_quota.handle = ~0;

      create->id = urr->urr_id;
      create->methods = urr->measurement_method;
      create->triggers = OPT(urr, CREATE_URR_REPORTING_TRIGGERS, reporting_triggers, 0);
      create->start_time = now;

      if (ISSET_BIT(urr->grp.fields, CREATE_URR_MEASUREMENT_PERIOD))
	{
	  create->update_flags |= SX_URR_UPDATE_MEASUREMENT_PERIOD;
	  create->measurement_period.period = urr->measurement_period;
	  create->measurement_period.base = now;
	}

      if (ISSET_BIT(urr->grp.fields, CREATE_URR_VOLUME_THRESHOLD))
	{
	  create->volume.threshold.ul = urr->volume_threshold.ul;
	  create->volume.threshold.dl = urr->volume_threshold.dl;
	  create->volume.threshold.total = urr->volume_threshold.total;
	}

      if (ISSET_BIT(urr->grp.fields, CREATE_URR_VOLUME_QUOTA))
	{
	  create->volume.quota.ul = urr->volume_quota.ul;
	  create->volume.quota.dl = urr->volume_quota.dl;
	  create->volume.quota.total = urr->volume_quota.total;
	}

      if (ISSET_BIT(urr->grp.fields, CREATE_URR_TIME_THRESHOLD))
	{
	  create->update_flags |= SX_URR_UPDATE_TIME_THRESHOLD;
	  create->time_threshold.period = urr->time_threshold;
	  create->time_threshold.base = now;
	}
      if (ISSET_BIT(urr->grp.fields, CREATE_URR_TIME_QUOTA))
	{
	  create->update_flags |= SX_URR_UPDATE_TIME_QUOTA;
	  create->time_quota.period = urr->time_quota;
	  create->time_quota.base = now;
	}

      //TODO: quota_holding_time;
      //TODO: dropped_dl_traffic_threshold;

      if (ISSET_BIT(urr->grp.fields, CREATE_URR_MONITORING_TIME))
	{
	  create->update_flags |= SX_URR_UPDATE_MONITORING_TIME;
	  create->monitoring_time.base = urr->monitoring_time;
	}

      //TODO: subsequent_volume_threshold;
      //TODO: subsequent_time_threshold;
      //TODO: inactivity_detection_time;
      //TODO: linked_urr_id;
      //TODO: measurement_information;
      //TODO: time_quota_mechanism;

      if ((r = sx_create_urr(sess, create)) != 0)
	{
	  gtp_debug("Failed to add URR %d\n", urr->urr_id);
	  failed_rule_id->id = urr->urr_id;
	  break;
	}
    }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT(grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_URR;
    }

  return r;
}

static int handle_update_urr(upf_session_t *sess, pfcp_update_urr_t *update_urr, f64 now,
			     struct pfcp_group *grp,
			     int failed_rule_id_field,
			     pfcp_failed_rule_id_t *failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *)(grp + 1);
  pfcp_update_urr_t *urr;
  int r = 0;

  vec_foreach(urr, update_urr)
    {
      upf_urr_t *update;

      update = sx_get_urr(sess, SX_PENDING, urr->urr_id);
      if (!update)
	{
	  gtp_debug("Sx Session %"PRIu64", update URR Id %d not found.\n",
		    sess->cp_seid, urr->urr_id);
	  failed_rule_id->id = urr->urr_id;
	  r = -1;
	  break;
	}

      update->methods = urr->measurement_method;
      update->triggers = OPT(urr, UPDATE_URR_REPORTING_TRIGGERS,
			     reporting_triggers, update->triggers);
      update->status &= ~URR_OVER_QUOTA;

      if (ISSET_BIT(urr->grp.fields, UPDATE_URR_MEASUREMENT_PERIOD))
	{
	  update->update_flags |= SX_URR_UPDATE_MEASUREMENT_PERIOD;
	  update->measurement_period.period = urr->measurement_period;
	  update->measurement_period.base = now;
	}

      if (ISSET_BIT(urr->grp.fields, UPDATE_URR_VOLUME_THRESHOLD))
	{
	  update->volume.threshold.ul = urr->volume_threshold.ul;
	  update->volume.threshold.dl = urr->volume_threshold.dl;
	  update->volume.threshold.total = urr->volume_threshold.total;
	}
      if (ISSET_BIT(urr->grp.fields, UPDATE_URR_VOLUME_QUOTA))
	{
	  update->update_flags |= SX_URR_UPDATE_VOLUME_QUOTA;
	  memset(&update->volume.measure.consumed, 0,
		 sizeof(update->volume.measure.consumed));
	  update->volume.quota.ul = urr->volume_quota.ul;
	  update->volume.quota.dl = urr->volume_quota.dl;
	  update->volume.quota.total = urr->volume_quota.total;
	}

      if (ISSET_BIT(urr->grp.fields, UPDATE_URR_TIME_THRESHOLD))
	{
	  update->update_flags |= SX_URR_UPDATE_TIME_THRESHOLD;
	  update->time_threshold.period = urr->time_threshold;
	}
      if (ISSET_BIT(urr->grp.fields, UPDATE_URR_TIME_QUOTA))
	{
	  update->update_flags |= SX_URR_UPDATE_TIME_QUOTA;
	  update->time_quota.period = urr->time_quota;
	  update->time_quota.base = update->start_time;
	}

      //TODO: quota_holding_time;
      //TODO: dropped_dl_traffic_threshold;

      if (ISSET_BIT(urr->grp.fields, UPDATE_URR_MONITORING_TIME))
	{
	  update->update_flags |= SX_URR_UPDATE_MONITORING_TIME;
	  update->monitoring_time.base = urr->monitoring_time;
	}

      //TODO: subsequent_volume_threshold;
      //TODO: subsequent_time_threshold;
      //TODO: inactivity_detection_time;
      //TODO: linked_urr_id;
      //TODO: measurement_information;
      //TODO: time_quota_mechanism;
    }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT(grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_URR;
    }

  return r;
}

static int handle_remove_urr(upf_session_t *sess, pfcp_remove_urr_t *remove_urr, f64 now,
			     struct pfcp_group *grp,
			     int failed_rule_id_field,
			     pfcp_failed_rule_id_t *failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *)(grp + 1);
  pfcp_remove_urr_t *urr;
  int r = 0;

  vec_foreach(urr, remove_urr)
    {
      if ((r = sx_delete_urr(sess, urr->urr_id)) != 0)
	{
	  gtp_debug("Failed to add URR %d\n", urr->urr_id);
	  failed_rule_id->id = urr->urr_id;
	  break;
	}
    }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT(grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_URR;
    }

  return r;
}

static pfcp_usage_report_t *
init_usage_report(upf_urr_t *urr, u32 trigger, pfcp_usage_report_t **report)
{
  pfcp_usage_report_t *r;

  vec_alloc(*report, 1);
  r = vec_end(*report);

  SET_BIT(r->grp.fields, USAGE_REPORT_URR_ID);
  r->urr_id = urr->id;

  SET_BIT(r->grp.fields, USAGE_REPORT_UR_SEQN);
  r->ur_seqn = urr->seq_no;
  urr->seq_no++;

  SET_BIT(r->grp.fields, USAGE_REPORT_USAGE_REPORT_TRIGGER);
  r->usage_report_trigger = trigger;

  return r;
}

pfcp_usage_report_t *
build_usage_report(upf_session_t *sess, upf_urr_t *urr,
		   u32 trigger, f64 now, pfcp_usage_report_t **report)
{
  pfcp_usage_report_t *r;
  urr_volume_t volume;
  u32 start, end;

  clib_spinlock_lock (&sess->lock);

  volume = urr->volume;
  memset(&urr->volume.measure.packets, 0, sizeof(urr->volume.measure.packets));
  memset(&urr->volume.measure.bytes, 0, sizeof(urr->volume.measure.bytes));

  clib_spinlock_unlock (&sess->lock);

  if (urr->status & URR_AFTER_MONITORING_TIME)
    {
      r = init_usage_report(urr, USAGE_REPORT_TRIGGER_MONITORING_TIME, report);

      SET_BIT(r->grp.fields, USAGE_REPORT_USAGE_INFORMATION);
      r->usage_information = USAGE_INFORMATION_BEFORE;

      /* TODO: apply proper rounding, the f64 to u32 conversion works a trunc */
      start = urr->usage_before_monitoring_time.start_time;
      end = urr->start_time;

      if ((trigger & (USAGE_REPORT_TRIGGER_START_OF_TRAFFIC |
		      USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC)) == 0)
	{
	  SET_BIT(r->grp.fields, USAGE_REPORT_START_TIME);
	  SET_BIT(r->grp.fields, USAGE_REPORT_END_TIME);

	  r->start_time = start;
	  r->end_time = end;
	}

      SET_BIT(r->grp.fields, USAGE_REPORT_VOLUME_MEASUREMENT);
      r->volume_measurement.fields = 7;

      r->volume_measurement.ul = urr->usage_before_monitoring_time.volume.bytes.ul;
      r->volume_measurement.dl = urr->usage_before_monitoring_time.volume.bytes.dl;
      r->volume_measurement.total = urr->usage_before_monitoring_time.volume.bytes.total;

      SET_BIT(r->grp.fields, USAGE_REPORT_DURATION_MEASUREMENT);
      r->duration_measurement = end - start;

      urr->monitoring_time.base = 0;

      _vec_len(*report)++;
    }

  r = init_usage_report(urr, trigger, report);

  if (urr->status & URR_AFTER_MONITORING_TIME)
    {
      SET_BIT(r->grp.fields, USAGE_REPORT_USAGE_INFORMATION);
      r->usage_information = USAGE_INFORMATION_AFTER;
    }

  /* TODO: apply proper rounding, the f64 to u32 conversion works a trunc */
  start = urr->start_time;
  end = now;

  if ((trigger & (USAGE_REPORT_TRIGGER_START_OF_TRAFFIC |
		  USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC)) == 0)
    {
      SET_BIT(r->grp.fields, USAGE_REPORT_START_TIME);
      SET_BIT(r->grp.fields, USAGE_REPORT_END_TIME);

      r->start_time = start;
      r->end_time = end;
    }

  SET_BIT(r->grp.fields, USAGE_REPORT_VOLUME_MEASUREMENT);
  r->volume_measurement.fields = 7;

  r->volume_measurement.ul = volume.measure.bytes.ul;
  r->volume_measurement.dl = volume.measure.bytes.dl;
  r->volume_measurement.total = volume.measure.bytes.total;

  SET_BIT(r->grp.fields, USAGE_REPORT_DURATION_MEASUREMENT);
  r->duration_measurement = end - start;

  /* SET_BIT(r->grp.fields, USAGE_REPORT_APPLICATION_DETECTION_INFORMATION); */
  /* SET_BIT(r->grp.fields, USAGE_REPORT_UE_IP_ADDRESS); */
  /* SET_BIT(r->grp.fields, USAGE_REPORT_NETWORK_INSTANCE); */
  /* SET_BIT(r->grp.fields, USAGE_REPORT_TIME_OF_FIRST_PACKET); */
  /* SET_BIT(r->grp.fields, USAGE_REPORT_TIME_OF_LAST_PACKET); */
  /* SET_BIT(r->grp.fields, USAGE_REPORT_USAGE_INFORMATION); */

  _vec_len(*report)++;

  urr->status &= ~URR_AFTER_MONITORING_TIME;
  urr->start_time = now;
  if (urr->time_threshold.base) urr->time_threshold.base = now;

  return r;
}

static int
handle_session_set_deletion_request(sx_msg_t * req, pfcp_session_set_deletion_request_t *msg)
{
  return -1;
}

static int
handle_session_set_deletion_response(sx_msg_t * req, pfcp_session_set_deletion_response_t *msg)
{
  return -1;
}

static int
handle_session_establishment_request(sx_msg_t * req, pfcp_session_establishment_request_t *msg)
{
  pfcp_session_establishment_response_t resp;
  ip46_address_t up_address = ip46_address_initializer;
  ip46_address_t cp_address = ip46_address_initializer;
  sx_server_main_t *sxsm = &sx_server_main;
  upf_session_t *sess = NULL;
  upf_node_assoc_t *assoc;
  f64 now = sxsm->now;
  int r = 0;
  int is_ip4;

  memset(&resp, 0, sizeof(resp));
  SET_BIT(resp.grp.fields, SESSION_ESTABLISHMENT_RESPONSE_CAUSE);
  resp.response.cause = PFCP_CAUSE_REQUEST_REJECTED;

  assoc = sx_get_association(&msg->request.node_id);
  if (!assoc)
    {
      resp.response.cause = PFCP_CAUSE_NO_ESTABLISHED_SX_ASSOCIATION;
      upf_pfcp_send_response(req, msg->f_seid.seid, PFCP_SESSION_ESTABLISHMENT_RESPONSE, &resp.grp);

      return -1;
    }

  SET_BIT(resp.grp.fields, SESSION_ESTABLISHMENT_RESPONSE_UP_F_SEID);
  resp.up_f_seid.seid = msg->f_seid.seid;

  is_ip4 = ip46_address_is_ip4(&req->lcl.address);
  if (is_ip4)
    {
      resp.up_f_seid.flags |= IE_F_SEID_IP_ADDRESS_V4;
      resp.up_f_seid.ip4 = req->lcl.address.ip4;

      ip_set(&up_address, &req->lcl.address.ip4, 1);
      ip_set(&cp_address, &msg->f_seid.ip4, 1);
    }
  else
    {
      resp.up_f_seid.flags |= IE_F_SEID_IP_ADDRESS_V6;
      resp.up_f_seid.ip6 = req->lcl.address.ip6;

      ip_set(&up_address, &req->lcl.address.ip6, 0);
      ip_set(&cp_address, &msg->f_seid.ip6, 0);
    }

  sess = sx_create_session(assoc, req->fib_index, &up_address,
			   msg->f_seid.seid, &cp_address);

  if ((r = handle_create_pdr(sess, msg->create_pdr, &resp.grp,
			     SESSION_ESTABLISHMENT_RESPONSE_FAILED_RULE_ID,
			     &resp.failed_rule_id)) != 0)
    goto out_send_resp;

  if ((r = handle_create_far(sess, msg->create_far, &resp.grp,
			     SESSION_ESTABLISHMENT_RESPONSE_FAILED_RULE_ID,
			     &resp.failed_rule_id)) != 0)
    goto out_send_resp;

  if ((r = handle_create_urr(sess, msg->create_urr, now, &resp.grp,
			     SESSION_ESTABLISHMENT_RESPONSE_FAILED_RULE_ID,
			     &resp.failed_rule_id)) != 0)
    goto out_send_resp;

  gtp_debug("%U", format_sx_session, sess, SX_PENDING);

  r = sx_update_apply(sess);
  gtp_debug("Appy: %d\n", r);

  sx_update_finish(sess);

  gtp_debug("-------------------------------------\n");
  sx_session_dump_tbls();

  gtp_debug("-------------------------------------\n");

 out_send_resp:
  if (r == 0)
    resp.response.cause = PFCP_CAUSE_REQUEST_ACCEPTED;

  upf_pfcp_send_response(req, sess->cp_seid, PFCP_SESSION_ESTABLISHMENT_RESPONSE, &resp.grp);

  if (r != 0)
    {
      if (sx_disable_session(sess) != 0)
	clib_error("failed to remove UPF session 0x%016" PRIx64, sess->cp_seid);
      sx_free_session(sess);
    }

  return r;
}

static int
handle_session_establishment_response(sx_msg_t * req, pfcp_session_establishment_response_t *msg)
{
  return -1;
}

static int
handle_session_modification_request(sx_msg_t * req, pfcp_session_modification_request_t *msg)
{
  pfcp_session_modification_response_t resp;
  sx_server_main_t *sxsm = &sx_server_main;
  pfcp_query_urr_t *qry;
  upf_session_t *sess;
  f64 now = sxsm->now;
  u64 cp_seid = 0;
  int r = 0;

  memset(&resp, 0, sizeof(resp));
  SET_BIT(resp.grp.fields, SESSION_ESTABLISHMENT_RESPONSE_CAUSE);
  resp.response.cause = PFCP_CAUSE_REQUEST_REJECTED;

  if (!(sess = sx_lookup(be64toh(req->hdr->session_hdr.seid))))
    {
      gtp_debug("Sx Session %"PRIu64" not found.\n", be64toh(req->hdr->session_hdr.seid));
      resp.response.cause = PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;

      r = -1;
      goto out_send_resp;
    }

  cp_seid = sess->cp_seid;

  if (msg->grp.fields & (BIT(SESSION_MODIFICATION_REQUEST_REMOVE_PDR) |
			 BIT(SESSION_MODIFICATION_REQUEST_REMOVE_FAR) |
			 BIT(SESSION_MODIFICATION_REQUEST_REMOVE_URR) |
			 BIT(SESSION_MODIFICATION_REQUEST_REMOVE_QER) |
			 BIT(SESSION_MODIFICATION_REQUEST_REMOVE_BAR) |
			 BIT(SESSION_MODIFICATION_REQUEST_CREATE_PDR) |
			 BIT(SESSION_MODIFICATION_REQUEST_CREATE_FAR) |
			 BIT(SESSION_MODIFICATION_REQUEST_CREATE_URR) |
			 BIT(SESSION_MODIFICATION_REQUEST_CREATE_QER) |
			 BIT(SESSION_MODIFICATION_REQUEST_CREATE_BAR) |
			 BIT(SESSION_MODIFICATION_REQUEST_UPDATE_PDR) |
			 BIT(SESSION_MODIFICATION_REQUEST_UPDATE_FAR) |
			 BIT(SESSION_MODIFICATION_REQUEST_UPDATE_URR) |
			 BIT(SESSION_MODIFICATION_REQUEST_UPDATE_QER) |
			 BIT(SESSION_MODIFICATION_REQUEST_UPDATE_BAR)))
    {
      /* invoke the update process only if a update is include */
      sx_update_session(sess);

      if ((r = handle_create_pdr(sess, msg->create_pdr, &resp.grp,
				 SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				 &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_update_pdr(sess, msg->update_pdr, &resp.grp,
				 SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				 &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_remove_pdr(sess, msg->remove_pdr, &resp.grp,
				 SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				 &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_create_far(sess, msg->create_far, &resp.grp,
				 SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				 &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_update_far(sess, msg->update_far, &resp.grp,
				 SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				 &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_remove_far(sess, msg->remove_far, &resp.grp,
				 SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				 &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_create_urr(sess, msg->create_urr, now, &resp.grp,
				 SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				 &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_update_urr(sess, msg->update_urr, now, &resp.grp,
				 SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				 &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_remove_urr(sess, msg->remove_urr, now, &resp.grp,
				 SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				 &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = sx_update_apply(sess)) != 0)
	goto out_update_finish;
    }

  if (ISSET_BIT(msg->grp.fields, SESSION_MODIFICATION_REQUEST_QUERY_URR) &&
      vec_len(msg->query_urr) != 0)
    {
      SET_BIT(resp.grp.fields, SESSION_MODIFICATION_RESPONSE_USAGE_REPORT);

      vec_foreach(qry, msg->query_urr)
	{
	  upf_urr_t *urr;

	  if (!(urr = sx_get_urr(sess, SX_ACTIVE, qry->urr_id)))
	    continue;

	  build_usage_report(sess, urr, USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT,
			     now, &resp.usage_report);
	}
    }
  else if (ISSET_BIT(msg->grp.fields, SESSION_MODIFICATION_REQUEST_SXSMREQ_FLAGS) &&
	   msg->sxsmreq_flags & SXSMREQ_QAURR)
    {
      struct rules *active;

      active = sx_get_rules(sess, SX_ACTIVE);
      if (vec_len(active->urr) != 0)
	{
	  upf_urr_t *urr;

	  SET_BIT(resp.grp.fields, SESSION_MODIFICATION_RESPONSE_USAGE_REPORT);

	  vec_foreach(urr, active->urr)
	    {
	      build_usage_report(sess, urr, USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT,
				 now, &resp.usage_report);
	    }
	}
    }

 out_update_finish:
  sx_update_finish(sess);

  gtp_debug("%U", format_sx_session, sess, SX_ACTIVE);

 out_send_resp:
  if (r == 0)
    resp.response.cause = PFCP_CAUSE_REQUEST_ACCEPTED;

  upf_pfcp_send_response(req, cp_seid, PFCP_SESSION_MODIFICATION_RESPONSE, &resp.grp);

 return r;
}

static int
handle_session_modification_response(sx_msg_t * req, pfcp_session_modification_response_t *msg)
{
  return -1;
}

static int
handle_session_deletion_request(sx_msg_t * req, pfcp_session_deletion_request_t *msg)
{
  sx_server_main_t *sxsm = &sx_server_main;
  pfcp_session_deletion_response_t resp;
  f64 now = sxsm->now;
  upf_session_t *sess;
  struct rules *active;
  u64 cp_seid = 0;
  int r = 0;

  memset(&resp, 0, sizeof(resp));
  SET_BIT(resp.grp.fields, SESSION_DELETION_RESPONSE_CAUSE);
  resp.response.cause = PFCP_CAUSE_REQUEST_REJECTED;

  if (!(sess = sx_lookup(be64toh(req->hdr->session_hdr.seid))))
    {
      gtp_debug("Sx Session %"PRIu64" not found.\n", be64toh(req->hdr->session_hdr.seid));
      resp.response.cause = PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;

      r = -1;
      goto out_send_resp;
    }

  cp_seid = sess->cp_seid;

  if ((r = sx_disable_session(sess)) != 0)
    {
      gtp_debug("Sx Session %"PRIu64" could no be disabled.\n",
	      be64toh(req->hdr->session_hdr.seid));
      goto out_send_resp;
    }

  active = sx_get_rules(sess, SX_ACTIVE);
  if (vec_len(active->urr) != 0)
    {
      upf_urr_t *urr;

      SET_BIT(resp.grp.fields, SESSION_DELETION_RESPONSE_USAGE_REPORT);

      vec_foreach(urr, active->urr)
	{
	  build_usage_report(sess, urr, USAGE_REPORT_TRIGGER_TERMINATION_REPORT,
			     now, &resp.usage_report);
	}
    }

 out_send_resp:
  if (r == 0)
    {
      sx_free_session(sess);
      resp.response.cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    }

  upf_pfcp_send_response(req, cp_seid, PFCP_SESSION_DELETION_RESPONSE, &resp.grp);

  return r;
}

static int
handle_session_deletion_response(sx_msg_t * req, pfcp_session_deletion_response_t *msg)
{
  return -1;
}

static int
handle_session_report_request(sx_msg_t * req, pfcp_session_report_request_t *msg)
{
  return -1;
}

static int
handle_session_report_response(sx_msg_t * req, pfcp_session_report_response_t *msg)
{
  return -1;
}


static int session_msg(sx_msg_t * msg)
{
  union {
    struct pfcp_group grp;
    pfcp_session_set_deletion_request_t session_set_deletion_request;
    pfcp_session_set_deletion_response_t session_set_deletion_response;
    pfcp_session_establishment_request_t session_establishment_request;
    pfcp_session_establishment_response_t session_establishment_response;
    pfcp_session_modification_request_t session_modification_request;
    pfcp_session_modification_response_t session_modification_response;
    pfcp_session_deletion_request_t session_deletion_request;
    pfcp_session_deletion_response_t session_deletion_response;
    pfcp_session_report_request_t session_report_request;
    pfcp_session_report_response_t session_report_response;
  } m;
  int r = 0;

  if (!msg->hdr->s_flag)
    {
      gtp_debug ("PFCP: session msg without SEID.");
      return -1;
    }

  memset(&m, 0, sizeof(m));
  r = pfcp_decode_msg(msg->hdr->type, &msg->hdr->session_hdr.ies[0],
		      clib_net_to_host_u16(msg->hdr->length) - sizeof(msg->hdr->session_hdr), &m.grp);
  if (r != 0)
    {
      //TODO: error reply
      pfcp_free_msg(msg->hdr->type, &m.grp);
      return r;
    }

  switch (msg->hdr->type)
    {
    case PFCP_SESSION_SET_DELETION_REQUEST:
      r = handle_session_set_deletion_request(msg, &m.session_set_deletion_request);
      break;

    case PFCP_SESSION_SET_DELETION_RESPONSE:
      r = handle_session_set_deletion_response(msg, &m.session_set_deletion_response);
      break;

    case PFCP_SESSION_ESTABLISHMENT_REQUEST:
      r = handle_session_establishment_request(msg, &m.session_establishment_request);
      break;

    case PFCP_SESSION_ESTABLISHMENT_RESPONSE:
      r = handle_session_establishment_response(msg, &m.session_establishment_response);
      break;

    case PFCP_SESSION_MODIFICATION_REQUEST:
      r = handle_session_modification_request(msg, &m.session_modification_request);
      break;

    case PFCP_SESSION_MODIFICATION_RESPONSE:
      r = handle_session_modification_response(msg, &m.session_modification_response);
      break;

    case PFCP_SESSION_DELETION_REQUEST:
      r = handle_session_deletion_request(msg, &m.session_deletion_request);
      break;

    case PFCP_SESSION_DELETION_RESPONSE:
      r = handle_session_deletion_response(msg, &m.session_deletion_response);
      break;

    case PFCP_SESSION_REPORT_REQUEST:
      r = handle_session_report_request(msg, &m.session_report_request);
      break;

    case PFCP_SESSION_REPORT_RESPONSE:
      r = handle_session_report_response(msg, &m.session_report_response);
      break;

    default:
      break;
    }

  pfcp_free_msg(msg->hdr->type, &m.grp);
  return 0;
}

void upf_pfcp_error_report(upf_session_t * sx, gtp_error_ind_t * error)
{
  pfcp_session_report_request_t req;
  pfcp_f_teid_t f_teid;

  memset(&req, 0, sizeof(req));
  SET_BIT(req.grp.fields, SESSION_REPORT_REQUEST_REPORT_TYPE);
  req.report_type = REPORT_TYPE_ERIR;

  SET_BIT(req.grp.fields, SESSION_REPORT_REQUEST_ERROR_INDICATION_REPORT);
  SET_BIT(req.error_indication_report.grp.fields, ERROR_INDICATION_REPORT_F_TEID);

  f_teid.teid = error->teid;
  if (ip46_address_is_ip4(&error->addr))
    {
      f_teid.flags = F_TEID_V4;
      f_teid.ip4 = error->addr.ip4;
    }
  else
    {
      f_teid.flags = F_TEID_V6;
      f_teid.ip6 = error->addr.ip6;
    }

  vec_add1(req.error_indication_report.f_teid, f_teid);

  upf_pfcp_send_request(sx, PFCP_SESSION_REPORT_REQUEST, &req.grp);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
