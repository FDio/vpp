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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <math.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_hop_by_hop.h>

#include "pfcp.h"
#include "upf_pfcp.h"
#include "upf_pfcp_server.h"
#include "upf_pfcp_api.h"
#include "upf_app_db.h"

#if CLIB_DEBUG > 1
#define upf_debug clib_warning
#else
#define upf_debug(...)				\
  do { } while (0)
#endif

#define API_VERSION      1

extern char *vpe_version_string;

typedef struct
{
  time_t start_time;
} upf_pfcp_session_t;

static int node_msg (pfcp_msg_t * msg);
static int session_msg (pfcp_msg_t * msg);

size_t
upf_pfcp_api_session_data_size ()
{
  return sizeof (upf_pfcp_session_t);
}

void
upf_pfcp_api_session_data_init (void *sxp, time_t start_time)
{
  upf_pfcp_session_t *sx = (upf_pfcp_session_t *) sxp;

  memset (sx, 0, sizeof (*sx));
  sx->start_time = start_time;
}

static void
init_response_node_id (struct pfcp_response *r)
{
  //TODO: need CLI/API to set local Node-Id.....
}

/*************************************************************************/

int
upf_pfcp_handle_msg (pfcp_msg_t * msg)
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
      return node_msg (msg);

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
      return session_msg (msg);

    default:
      upf_debug ("PFCP: msg type invalid: %d.", msg->hdr->type);
      break;
    }

  return -1;
}

/*************************************************************************/

static uword
unformat_ipfilter_address_port (unformat_input_t * i, va_list * args)
{
  acl_rule_t *acl = va_arg (*args, acl_rule_t *);
  int field = va_arg (*args, int);
  ipfilter_address_t *ip = &acl->address[field];
  ipfilter_port_t *port = &acl->port[field];
  int is_ip4;

  ip->mask = ~0;
  port->min = 0;
  port->max = ~0;

  if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
    return 0;

  if (unformat (i, "any"))
    {
      *ip = ACL_ADDR_ANY;
    }
  else if (unformat (i, "assigned"))
    {
      *ip = ACL_ADDR_ASSIGNED;
    }
  else
    if (unformat
	(i, "%U", unformat_ip46_address, &ip->address, IP46_TYPE_ANY))
    {
      is_ip4 = ip46_address_is_ip4 (&ip->address);
      acl->type = is_ip4 ? IPFILTER_IPV4 : IPFILTER_IPV6;
      ip->mask = is_ip4 ? 32 : 128;

      if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
	return 1;
      if (unformat (i, "/%d", &ip->mask))
	;
    }
  else
    return 0;

  if (unformat_check_input (i) == UNFORMAT_END_OF_INPUT)
    return 1;
  if (unformat (i, "%d-%d", &port->min, &port->max))
    ;
  else if (unformat (i, "%d", &port->min))
    port->max = port->min;

  return 1;
}

static uword
unformat_ipfilter (unformat_input_t * i, acl_rule_t * acl)
{
  int step = 0;

  acl->type = IPFILTER_WILDCARD;

  /* action dir proto from src to dst [options] */
  while (step < 5 && unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      switch (step)
	{
	case 0:		/* action */
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

	case 1:		/* dir */
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

	case 2:		/* proto */
	  if (unformat (i, "ip"))
	    {
	      acl->proto = ~0;
	    }
	  else if (unformat (i, "%u", &acl->proto))
	    ;
	  else
	    return 0;

	  break;

	case 3:		/* from src */
	  if (unformat (i, "from %U", unformat_ipfilter_address_port,
			acl, UPF_ACL_FIELD_SRC))
	    ;
	  else
	    return 0;

	  break;

	case 4:
	  if (unformat (i, "to %U", unformat_ipfilter_address_port,
			acl, UPF_ACL_FIELD_DST))
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
format_ipfilter_address_port (u8 * s, va_list * args)
{
  acl_rule_t *acl = va_arg (*args, acl_rule_t *);
  int field = va_arg (*args, int);
  ipfilter_address_t *ip = &acl->address[field];
  ipfilter_port_t *port = &acl->port[field];

  if (acl_addr_is_any (ip))
    {
      s = format (s, "any");
    }
  else if (acl_addr_is_assigned (ip))
    {
      s = format (s, "assigned");
    }
  else
    {
      s = format (s, "%U", format_ip46_address, &ip->address, IP46_TYPE_ANY);
      if (ip->mask != (ip46_address_is_ip4 (&ip->address) ? 32 : 128))
	s = format (s, "/%u", ip->mask);
    }

  if (port->min != 0 || port->max != (u16) ~ 0)
    {
      s = format (s, " %d", port->min);
      if (port->min != port->max)
	s = format (s, "-%d", port->max);
    }

  return s;
}

u8 *
format_ipfilter (u8 * s, va_list * args)
{
  acl_rule_t *acl = va_arg (*args, acl_rule_t *);

  switch (acl->action)
    {
    case ACL_PERMIT:
      s = format (s, "permit ");
      break;

    case ACL_DENY:
      s = format (s, "deny ");
      break;

    default:
      s = format (s, "action_%d ", acl->action);
      break;
    }

  switch (acl->direction)
    {
    case ACL_IN:
      s = format (s, "in ");
      break;

    case ACL_OUT:
      s = format (s, "out ");
      break;

    default:
      s = format (s, "direction_%d ", acl->direction);
      break;
    }

  if (acl->proto == (u8) ~ 0)
    s = format (s, "ip ");
  else
    s = format (s, "%d ", acl->proto);

  s = format (s, "from %U ", format_ipfilter_address_port,
	      acl, UPF_ACL_FIELD_SRC);
  s =
    format (s, "to %U ", format_ipfilter_address_port,
	    acl, UPF_ACL_FIELD_DST);

  return s;
}

/*************************************************************************/

/* message helpers */

static void
  build_user_plane_ip_resource_information
  (pfcp_user_plane_ip_resource_information_t ** upip)
{
  upf_main_t *gtm = &upf_main;
  upf_upip_res_t *res;

  vec_alloc (*upip, pool_elts (gtm->upip_res));

  /* *INDENT-OFF* */
  pool_foreach (res, gtm->upip_res,
  ({
    pfcp_user_plane_ip_resource_information_t *r;

    vec_add2 (*upip, r, 1);

    if (res->nwi_index != ~0)
      {
	upf_nwi_t *nwi = pool_elt_at_index(gtm->nwis, res->nwi_index);

	r->flags |= USER_PLANE_IP_RESOURCE_INFORMATION_ASSONI;
	r->network_instance = vec_dup(nwi->name);
      }

    if (INTF_INVALID != res->intf)
      {

	r->flags |= USER_PLANE_IP_RESOURCE_INFORMATION_ASSOSI;
	r->source_intf = res->intf;
      }

    if (res->mask != 0)
      {
	r->teid_range_indication = __builtin_popcount(res->mask);
	r->teid_range = (res->teid >> 24);
      }

    if (!is_zero_ip4_address (&res->ip4))
      {
	r->flags |= USER_PLANE_IP_RESOURCE_INFORMATION_V4;
	r->ip4 = res->ip4;
      }

    if (!is_zero_ip6_address (&res->ip6))
      {
	r->flags |= USER_PLANE_IP_RESOURCE_INFORMATION_V6;
	r->ip6 = res->ip6;
      }
  }));
  /* *INDENT-ON* */
}

/* message handlers */

static int
handle_heartbeat_request (pfcp_msg_t * req, pfcp_heartbeat_request_t * msg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_simple_response_t resp;

  memset (&resp, 0, sizeof (resp));
  SET_BIT (resp.grp.fields, PFCP_RESPONSE_RECOVERY_TIME_STAMP);
  resp.response.recovery_time_stamp = psm->start_time;

  upf_debug ("PFCP: start_time: %p, %d, %x.",
	     &psm, psm->start_time, psm->start_time);

  upf_pfcp_send_response (req, 0, PFCP_HEARTBEAT_RESPONSE, &resp.grp);

  return 0;
}

static int
handle_heartbeat_response (pfcp_msg_t * req, pfcp_simple_response_t * msg)
{
  upf_main_t *gtm = &upf_main;
  upf_node_assoc_t *n;

  if (req->node == ~0 || pool_is_free_index (gtm->nodes, req->node))
    return -1;

  n = pool_elt_at_index (gtm->nodes, req->node);

  if (msg->response.recovery_time_stamp > n->recovery_time_stamp)
    pfcp_release_association (n);
  else if (msg->response.recovery_time_stamp < n->recovery_time_stamp)
    {
      /* 3GPP TS 23.007, Sect. 19A:
       *
       * If the value of a Recovery Time Stamp previously stored for a peer is larger
       * than the Recovery Time Stamp value received in the Heartbeat Response message
       * or the PFCP message, this indicates a possible race condition (newer message
       * arriving before the older one). The received PFCP node related message and the
       * received new Recovery Time Stamp value shall be discarded and an error may
       * be logged.
       */
      return -1;
    }
  else
    {
      upf_debug ("restarting HB timer\n");
      n->heartbeat_handle = upf_pfcp_server_start_timer
	(PFCP_SERVER_HB_TIMER, n - gtm->nodes, PFCP_HB_INTERVAL);
    }

  return 0;
}

static int
handle_pfd_management_request (pfcp_msg_t * req,
			       pfcp_pfd_management_request_t * msg)
{
  return -1;
}

static int
handle_pfd_management_response (pfcp_msg_t * req,
				pfcp_simple_response_t * msg)
{
  return -1;
}

static int
handle_association_setup_request (pfcp_msg_t * req,
				  pfcp_association_setup_request_t * msg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_association_setup_response_t resp;
  upf_main_t *gtm = &upf_main;
  upf_node_assoc_t *n;
  int r = 0;

  memset (&resp, 0, sizeof (resp));
  SET_BIT (resp.grp.fields, ASSOCIATION_SETUP_RESPONSE_CAUSE);
  resp.response.cause = PFCP_CAUSE_REQUEST_REJECTED;

  init_response_node_id (&resp.response);

  SET_BIT (resp.grp.fields, ASSOCIATION_SETUP_RESPONSE_RECOVERY_TIME_STAMP);
  resp.recovery_time_stamp = psm->start_time;

  SET_BIT (resp.grp.fields, ASSOCIATION_SETUP_RESPONSE_TP_BUILD_ID);
  vec_add (resp.tp_build_id, vpe_version_string, strlen (vpe_version_string));

  n = pfcp_get_association (&msg->request.node_id);
  if (n)
    {
      /* 3GPP TS 23.007, Sect. 19A:
       *
       * A PFCP function that receives a PFCP Association Setup Request
       * shall proceed with:
       *
       * - establishing the PFCP association and
       * - deleting the existing PFCP association and associated PFCP sessions,
       *   if a PFCP association was already established for the Node ID received
       *   in the request, regardless of the Recovery Timestamp received in the
       *   request.
       *
       * A PFCP function shall ignore the Recovery Timestamp received in
       * PFCP Association Setup Response message.
       *
       */
      pfcp_release_association (n);
    }

  n =
    pfcp_new_association (req->session_handle,
			  &req->lcl.address, &req->rmt.address,
			  &msg->request.node_id);
  n->recovery_time_stamp = msg->recovery_time_stamp;

  SET_BIT (resp.grp.fields, ASSOCIATION_SETUP_RESPONSE_UP_FUNCTION_FEATURES);
  resp.up_function_features |= F_UPFF_EMPU;
  /* currently no optional features are supported */

  build_user_plane_ip_resource_information
    (&resp.user_plane_ip_resource_information);
  if (vec_len (resp.user_plane_ip_resource_information) != 0)
    SET_BIT (resp.grp.fields,
	     ASSOCIATION_SETUP_RESPONSE_USER_PLANE_IP_RESOURCE_INFORMATION);

  if (r == 0)
    {
      n->heartbeat_handle = upf_pfcp_server_start_timer
	(PFCP_SERVER_HB_TIMER, n - gtm->nodes, PFCP_HB_INTERVAL);

      resp.response.cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    }

  upf_pfcp_send_response (req, 0, PFCP_ASSOCIATION_SETUP_RESPONSE, &resp.grp);

  return r;
}

static int
handle_association_setup_response (pfcp_msg_t * req,
				   pfcp_association_setup_response_t * msg)
{
  return -1;
}

static int
handle_association_update_request (pfcp_msg_t * req,
				   pfcp_association_update_request_t * msg)
{
  return -1;
}

static int
handle_association_update_response (pfcp_msg_t * req,
				    pfcp_association_update_response_t * msg)
{
  return -1;
}

static int
handle_association_release_request (pfcp_msg_t * req,
				    pfcp_association_release_request_t * msg)
{
  return -1;
}

static int
handle_association_release_response (pfcp_msg_t * req,
				     pfcp_simple_response_t * msg)
{
  return -1;
}

#if 0
static int
handle_version_not_supported_response (pfcp_msg_t * req,
				       pfcp_version_not_supported_response_t *
				       msg)
{
  return -1;
}
#endif

static int
handle_node_report_request (pfcp_msg_t * req,
			    pfcp_node_report_request_t * msg)
{
  return -1;
}

static int
handle_node_report_response (pfcp_msg_t * req, pfcp_simple_response_t * msg)
{
  return -1;
}

static void
send_simple_repsonse (pfcp_msg_t * req, u64 seid, u8 type,
		      pfcp_cause_t cause, pfcp_offending_ie_t * err)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_simple_response_t resp;

  memset (&resp, 0, sizeof (resp));
  SET_BIT (resp.grp.fields, PFCP_RESPONSE_CAUSE);
  resp.response.cause = cause;

  switch (type)
    {
    case PFCP_HEARTBEAT_RESPONSE:
    case PFCP_PFD_MANAGEMENT_RESPONSE:
    case PFCP_SESSION_MODIFICATION_RESPONSE:
    case PFCP_SESSION_DELETION_RESPONSE:
    case PFCP_SESSION_REPORT_RESPONSE:
      break;

    default:
      init_response_node_id (&resp.response);
      break;
    }

  switch (type)
    {
    case PFCP_HEARTBEAT_RESPONSE:
    case PFCP_ASSOCIATION_SETUP_RESPONSE:
      SET_BIT (resp.grp.fields, PFCP_RESPONSE_RECOVERY_TIME_STAMP);
      resp.response.recovery_time_stamp = psm->start_time;
      break;

    default:
      break;
    }

  if (vec_len (err) != 0)
    {
      SET_BIT (resp.grp.fields, PFCP_RESPONSE_OFFENDING_IE);
      resp.response.offending_ie = err[0];
    }

  upf_pfcp_send_response (req, seid, type, &resp.grp);
}

static int
node_msg (pfcp_msg_t * msg)
{
  union
  {
    struct pfcp_group grp;
    pfcp_simple_response_t simple_response;
    pfcp_heartbeat_request_t heartbeat_request;
    pfcp_pfd_management_request_t pfd_management_request;
    pfcp_association_setup_request_t association_setup_request;
    pfcp_association_setup_response_t association_setup_response;
    pfcp_association_update_request_t association_update_request;
    pfcp_association_update_response_t association_update_response;
    pfcp_association_release_request_t association_release_request;
    /* pfcp_version_not_supported_response_t version_not_supported_response; */
    pfcp_node_report_request_t node_report_request;
  } m;
  pfcp_offending_ie_t *err = NULL;
  int r = 0;

  if (msg->hdr->s_flag)
    {
      upf_debug ("PFCP: node msg with SEID.");
      return -1;
    }

  memset (&m, 0, sizeof (m));
  r = pfcp_decode_msg (msg->hdr->type, &msg->hdr->msg_hdr.ies[0],
		       clib_net_to_host_u16 (msg->hdr->length) -
		       sizeof (msg->hdr->msg_hdr), &m.grp, &err);
  if (r != 0)
    {
      switch (msg->hdr->type)
	{
	case PFCP_HEARTBEAT_REQUEST:
	case PFCP_PFD_MANAGEMENT_REQUEST:
	case PFCP_ASSOCIATION_SETUP_REQUEST:
	case PFCP_ASSOCIATION_UPDATE_REQUEST:
	case PFCP_ASSOCIATION_RELEASE_REQUEST:
	  send_simple_repsonse (msg, 0, msg->hdr->type + 1, r, err);
	  break;

	default:
	  break;
	}

      pfcp_free_msg (msg->hdr->type, &m.grp);
      vec_free (err);
      return r;
    }

  switch (msg->hdr->type)
    {
    case PFCP_HEARTBEAT_REQUEST:
      r = handle_heartbeat_request (msg, &m.heartbeat_request);
      break;

    case PFCP_HEARTBEAT_RESPONSE:
      r = handle_heartbeat_response (msg, &m.simple_response);
      break;

    case PFCP_PFD_MANAGEMENT_REQUEST:
      r = handle_pfd_management_request (msg, &m.pfd_management_request);
      break;

    case PFCP_PFD_MANAGEMENT_RESPONSE:
      r = handle_pfd_management_response (msg, &m.simple_response);
      break;

    case PFCP_ASSOCIATION_SETUP_REQUEST:
      r =
	handle_association_setup_request (msg, &m.association_setup_request);
      break;

    case PFCP_ASSOCIATION_SETUP_RESPONSE:
      r =
	handle_association_setup_response (msg,
					   &m.association_setup_response);
      break;

    case PFCP_ASSOCIATION_UPDATE_REQUEST:
      r =
	handle_association_update_request (msg,
					   &m.association_update_request);
      break;

    case PFCP_ASSOCIATION_UPDATE_RESPONSE:
      r =
	handle_association_update_response (msg,
					    &m.association_update_response);
      break;

    case PFCP_ASSOCIATION_RELEASE_REQUEST:
      r =
	handle_association_release_request (msg,
					    &m.association_release_request);
      break;

    case PFCP_ASSOCIATION_RELEASE_RESPONSE:
      r = handle_association_release_response (msg, &m.simple_response);
      break;

      /* case PFCP_VERSION_NOT_SUPPORTED_RESPONSE: */
      /*   r = handle_version_not_supported_response(msg, &m.version_not_supported_response); */
      /*   break; */

    case PFCP_NODE_REPORT_REQUEST:
      r = handle_node_report_request (msg, &m.node_report_request);
      break;

    case PFCP_NODE_REPORT_RESPONSE:
      r = handle_node_report_response (msg, &m.simple_response);
      break;

    default:
      break;
    }

  pfcp_free_msg (msg->hdr->type, &m.grp);
  return 0;
}

#define OPT(MSG,FIELD,VALUE,DEFAULT)					\
  ((ISSET_BIT((MSG)->grp.fields, (FIELD))) ? MSG->VALUE : (DEFAULT))

static upf_nwi_t *
lookup_nwi (u8 * name)
{
  upf_main_t *gtm = &upf_main;
  uword *p;

  assert (name);

  if (pool_elts (gtm->nwis) == 0)
    return NULL;

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (!p)
    return NULL;

  return pool_elt_at_index (gtm->nwis, p[0]);
}

static int
handle_create_pdr (upf_session_t * sx, pfcp_create_pdr_t * create_pdr,
		   struct pfcp_group *grp,
		   int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  upf_main_t *gtm = &upf_main;
  pfcp_create_pdr_t *pdr;
  struct rules *rules;
  int r = 0;

  if ((r = pfcp_make_pending_pdr (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  rules = pfcp_get_rules (sx, PFCP_PENDING);
  vec_alloc (rules->pdr, vec_len (create_pdr));

  vec_foreach (pdr, create_pdr)
  {
    upf_pdr_t *create;

    vec_add2 (rules->pdr, create, 1);
    memset (create, 0, sizeof (*create));

    create->pdi.nwi_index = ~0;
    create->pdi.adr.application_id = ~0;
    create->pdi.adr.db_id = ~0;

    create->id = pdr->pdr_id;
    create->precedence = pdr->precedence;

    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_NETWORK_INSTANCE))
      {
	upf_nwi_t *nwi = lookup_nwi (pdr->pdi.network_instance);
	if (!nwi)
	  {
	    upf_debug ("PDR: %d, PDI for unknown network instance\n",
		       pdr->pdr_id);
	    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_NETWORK_INSTANCE))
	      upf_debug ("NWI: %v (%d)", pdr->pdi.network_instance,
			 vec_len (pdr->pdi.network_instance));
	    failed_rule_id->id = pdr->pdr_id;
	    r = -1;
	    vec_pop (rules->pdr);
	    break;
	  }

	create->pdi.nwi_index = nwi - gtm->nwis;
      }

    create->pdi.src_intf = pdr->pdi.source_interface;

    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_F_TEID))
      {
	create->pdi.fields |= F_PDI_LOCAL_F_TEID;
	/* TODO validate TEID and mask
	   if (nwi->teid != (pdr->pdi.f_teid.teid & nwi->mask))
	   {
	   upf_debug("PDR: %d, TEID not within configure partition\n", pdr->pdr_id);
	   failed_rule_id->id = pdr->pdr_id;
	   r = -1;
	   vec_pop (rules->pdr);
	   break;
	   }
	 */
	create->pdi.teid = pdr->pdi.f_teid;
      }
    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_UE_IP_ADDRESS))
      {
	create->pdi.fields |= F_PDI_UE_IP_ADDR;
	create->pdi.ue_addr = pdr->pdi.ue_ip_address;
      }
    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_SDF_FILTER))
      {
	pfcp_sdf_filter_t *sdf;

	create->pdi.fields |= F_PDI_SDF_FILTER;

	vec_alloc (create->pdi.acl, _vec_len (pdr->pdi.sdf_filter));

	vec_foreach (sdf, pdr->pdi.sdf_filter)
	{
	  unformat_input_t input;
	  acl_rule_t *acl;

	  unformat_init_vector (&input, sdf->flow);
	  vec_add2 (create->pdi.acl, acl, 1);

	  if (!unformat_ipfilter (&input, acl))
	    {
	      failed_rule_id->id = pdr->pdr_id;
	      vec_pop (rules->pdr);
	      upf_debug ("failed to parse SDF '%s'", sdf->flow);
	      r = -1;
	      break;
	    }
	}
      }

    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_APPLICATION_ID))
      {
	upf_adf_app_t *app;
	uword *p = NULL;
	create->pdi.fields |= F_PDI_APPLICATION_ID;

	p = hash_get_mem (gtm->upf_app_by_name, pdr->pdi.application_id);
	if (!p)
	  {
	    failed_rule_id->id = pdr->pdr_id;
	    vec_pop (rules->pdr);
	    r = -1;
	    fformat (stderr,
		     "PDR: %d, application id %v has not been configured\n",
		     pdr->pdr_id, pdr->pdi.application_id);
	    break;
	  }

	ASSERT (!pool_is_free_index (gtm->upf_apps, p[0]));
	app = pool_elt_at_index (gtm->upf_apps, p[0]);
	create->pdi.adr.application_id = p[0];
	create->pdi.adr.db_id = upf_adf_get_adr_db (p[0]);
	create->pdi.adr.flags = app->flags;

	upf_debug ("app: %v, ADR DB id %u", app->name, create->pdi.adr.db_id);
      }

    create->outer_header_removal = OPT (pdr, CREATE_PDR_OUTER_HEADER_REMOVAL,
					outer_header_removal, ~0);
    create->far_id = OPT (pdr, CREATE_PDR_FAR_ID, far_id, ~0);
    if (ISSET_BIT (pdr->grp.fields, CREATE_PDR_URR_ID))
      {
	pfcp_urr_id_t *urr_id;

	vec_alloc (create->urr_ids, _vec_len (pdr->urr_id));
	vec_foreach (urr_id, pdr->urr_id)
	{
	  vec_add1 (create->urr_ids, *urr_id);
	}
      }

    if (ISSET_BIT (pdr->grp.fields, CREATE_PDR_QER_ID))
      {
	pfcp_qer_id_t *qer_id;

	vec_alloc (create->qer_ids, _vec_len (pdr->qer_id));
	vec_foreach (qer_id, pdr->qer_id)
	{
	  vec_add1 (create->qer_ids, *qer_id);
	}
      }

    // CREATE_PDR_ACTIVATE_PREDEFINED_RULES
  }

  pfcp_sort_pdrs (rules);

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_PDR;
    }

  return r;
}

static int
handle_update_pdr (upf_session_t * sx, pfcp_update_pdr_t * update_pdr,
		   struct pfcp_group *grp,
		   int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  upf_main_t *gtm = &upf_main;
  pfcp_update_pdr_t *pdr;
  int r = 0;

  if ((r = pfcp_make_pending_pdr (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  vec_foreach (pdr, update_pdr)
  {
    upf_pdr_t *update;

    update = pfcp_get_pdr (sx, PFCP_PENDING, pdr->pdr_id);
    if (!update)
      {
	upf_debug ("PFCP Session %" PRIu64 ", update PDR Id %d not found.\n",
		   sx->cp_seid, pdr->pdr_id);
	failed_rule_id->id = pdr->pdr_id;
	r = -1;
	break;
      }

    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_NETWORK_INSTANCE))
      {
	if (vec_len (pdr->pdi.network_instance) != 0)
	  {
	    upf_nwi_t *nwi = lookup_nwi (pdr->pdi.network_instance);
	    if (!nwi)
	      {
		upf_debug ("PDR: %d, PDI for unknown network instance\n",
			   pdr->pdr_id);
		failed_rule_id->id = pdr->pdr_id;
		r = -1;
		break;
	      }
	    update->pdi.nwi_index = nwi - gtm->nwis;
	  }
	else
	  update->pdi.nwi_index = ~0;
      }

    update->precedence = pdr->precedence;
    update->pdi.src_intf = pdr->pdi.source_interface;

    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_F_TEID))
      {
	update->pdi.fields |= F_PDI_LOCAL_F_TEID;
	/* TODO validate TEID and mask */
	update->pdi.teid = pdr->pdi.f_teid;
      }
    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_UE_IP_ADDRESS))
      {
	update->pdi.fields |= F_PDI_UE_IP_ADDR;
	update->pdi.ue_addr = pdr->pdi.ue_ip_address;
      }
    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_SDF_FILTER))
      {
	pfcp_sdf_filter_t *sdf;

	update->pdi.fields |= F_PDI_SDF_FILTER;

	vec_reset_length (update->pdi.acl);
	vec_alloc (update->pdi.acl, _vec_len (pdr->pdi.sdf_filter));

	vec_foreach (sdf, pdr->pdi.sdf_filter)
	{
	  unformat_input_t input;
	  acl_rule_t *acl;

	  unformat_init_vector (&input, sdf->flow);
	  vec_add2 (update->pdi.acl, acl, 1);

	  if (!unformat_ipfilter (&input, acl))
	    {
	      failed_rule_id->id = pdr->pdr_id;
	      upf_debug ("failed to parse SDF '%s'", sdf->flow);
	      r = -1;
	      break;
	    }
	}
      }

    if (ISSET_BIT (pdr->pdi.grp.fields, PDI_APPLICATION_ID))
      {
	upf_adf_app_t *app;
	uword *p = NULL;

	update->pdi.fields |= F_PDI_APPLICATION_ID;

	p = hash_get_mem (gtm->upf_app_by_name, pdr->pdi.application_id);
	if (!p)
	  {
	    failed_rule_id->id = pdr->pdr_id;
	    r = -1;
	    fformat (stderr,
		     "PDR: %d, application id %v has not been configured\n",
		     pdr->pdr_id, pdr->pdi.application_id);
	    break;
	  }

	ASSERT (!pool_is_free_index (gtm->upf_apps, p[0]));
	app = pool_elt_at_index (gtm->upf_apps, p[0]);
	update->pdi.adr.application_id = p[0];
	update->pdi.adr.db_id = upf_adf_get_adr_db (p[0]);
	update->pdi.adr.flags = app->flags;

	upf_debug ("app: %v, ADR DB id %u", app->name, update->pdi.adr.db_id);
      }

    update->outer_header_removal = OPT (pdr, UPDATE_PDR_OUTER_HEADER_REMOVAL,
					outer_header_removal, ~0);
    update->far_id = OPT (pdr, UPDATE_PDR_FAR_ID, far_id, ~0);
    if (ISSET_BIT (pdr->grp.fields, UPDATE_PDR_URR_ID))
      {
	pfcp_urr_id_t *urr_id;

	vec_reset_length (update->urr_ids);
	vec_alloc (update->urr_ids, _vec_len (pdr->urr_id));
	vec_foreach (urr_id, pdr->urr_id)
	{
	  vec_add1 (update->urr_ids, *urr_id);
	}
      }

    if (ISSET_BIT (pdr->grp.fields, UPDATE_PDR_QER_ID))
      {
	pfcp_qer_id_t *qer_id;

	vec_reset_length (update->qer_ids);
	vec_alloc (update->qer_ids, _vec_len (pdr->qer_id));
	vec_foreach (qer_id, pdr->qer_id)
	{
	  vec_add1 (update->qer_ids, *qer_id);
	}
      }

    // UPDATE_PDR_ACTIVATE_PREDEFINED_RULES
  }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_PDR;
    }

  return r;
}

static int
handle_remove_pdr (upf_session_t * sx, pfcp_remove_pdr_t * remove_pdr,
		   struct pfcp_group *grp,
		   int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  pfcp_remove_pdr_t *pdr;
  int r = 0;

  if ((r = pfcp_make_pending_pdr (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  vec_foreach (pdr, remove_pdr)
  {
    if ((r = pfcp_delete_pdr (sx, pdr->pdr_id)) != 0)
      {
	upf_debug ("Failed to remove PDR %d\n", pdr->pdr_id);
	failed_rule_id->id = pdr->pdr_id;
	r = -1;
	break;
      }
  }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_PDR;
    }

  return r;
}

/* find source IP based on outgoing route and UpIP */
static void *
upip_ip_interface_ip (upf_far_forward_t * ff, u32 fib_index, int is_ip4)
{
  ip_lookup_main_t *lm =
    is_ip4 ? &ip4_main.lookup_main : &ip6_main.lookup_main;
  upf_main_t *gtm = &upf_main;
  ip_interface_address_t *a;
  upf_upip_res_t *res;

  /* *INDENT-OFF* */
  pool_foreach (res, gtm->upip_res,
  ({
    uword *p;

    if (is_ip4 && is_zero_ip4_address (&res->ip4))
      continue;
    if (!is_ip4 && is_zero_ip6_address (&res->ip6))
      continue;

    if (INTF_INVALID != res->intf && ff->dst_intf != res->intf)
      continue;

    if (~0 != res->nwi_index && ~0 != ff->nwi_index && ff->nwi_index != res->nwi_index)
      continue;

    if (is_ip4)
      {
	ip4_address_fib_t ip4_af;

	ip4_addr_fib_init (&ip4_af, &res->ip4, fib_index);
	p = mhash_get (&lm->address_to_if_address_index, &ip4_af);
      }
    else
      {
	ip6_address_fib_t ip6_af;

	ip6_addr_fib_init (&ip6_af, &res->ip6, fib_index);
	p = mhash_get (&lm->address_to_if_address_index, &ip6_af);
      }
    if (!p)
      continue;

    a = pool_elt_at_index (lm->if_address_pool, p[0]);
    if (a->sw_if_index == ff->dst_sw_if_index)
      return (is_ip4) ? (void *)&res->ip4 : (void *)&res->ip6;
  }));
  /* *INDENT-ON* */

  clib_warning ("No NWI IP found, using first interface IP");
  return ip_interface_get_first_ip (ff->dst_sw_if_index, is_ip4);
}

static void
ip_udp_gtpu_rewrite (upf_far_forward_t * ff, u32 fib_index, int is_ip4)
{
  union
  {
    ip4_gtpu_header_t *h4;
    ip6_gtpu_header_t *h6;
    u8 *rw;
  } r = {
    .rw = 0
  };
  int len = is_ip4 ? sizeof *r.h4 : sizeof *r.h6;

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

      ip->src_address =
	*(ip4_address_t *) upip_ip_interface_ip (ff, fib_index, 1);
      ip->dst_address = ff->outer_header_creation.ip.ip4;

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

      ip->src_address =
	*(ip6_address_t *) upip_ip_interface_ip (ff, fib_index, 0);
      ip->dst_address = ff->outer_header_creation.ip.ip6;
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

/* from src/vnet/ip/ping.c */
static fib_node_index_t
upf_ip46_fib_table_lookup_host (u32 fib_index, ip46_address_t * pa46,
				int is_ip4)
{
  fib_node_index_t fib_entry_index = is_ip4 ?
    ip4_fib_table_lookup (ip4_fib_get (fib_index), &pa46->ip4, 32) :
    ip6_fib_table_lookup (fib_index, &pa46->ip6, 128);
  return fib_entry_index;
}

/* from src/vnet/ip/ping.c */
static u32
upf_ip46_get_resolving_interface (u32 fib_index, ip46_address_t * pa46,
				  int is_ip4)
{
  fib_node_index_t fib_entry_index;

  ASSERT (~0 != fib_index);

  fib_entry_index = upf_ip46_fib_table_lookup_host (fib_index, pa46, is_ip4);
  return fib_entry_get_resolving_interface (fib_entry_index);
}

static int
handle_create_far (upf_session_t * sx, pfcp_create_far_t * create_far,
		   struct pfcp_group *grp,
		   int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  upf_main_t *gtm = &upf_main;
  pfcp_create_far_t *far;
  struct rules *rules;
  int r = 0;

  if ((r = pfcp_make_pending_far (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  rules = pfcp_get_rules (sx, PFCP_PENDING);
  vec_alloc (rules->far, vec_len (create_far));

  vec_foreach (far, create_far)
  {
    upf_far_t *create;

    vec_add2 (rules->far, create, 1);
    memset (create, 0, sizeof (*create));
    create->forward.nwi_index = ~0;
    create->forward.dst_sw_if_index = ~0;

    create->id = far->far_id;
    create->apply_action = far->apply_action;

    if ((create->apply_action & FAR_FORWARD) &&
	ISSET_BIT (far->grp.fields, CREATE_FAR_FORWARDING_PARAMETERS))
      {

	if (ISSET_BIT (far->forwarding_parameters.grp.fields,
		       FORWARDING_PARAMETERS_NETWORK_INSTANCE))
	  {
	    upf_nwi_t *nwi =
	      lookup_nwi (far->forwarding_parameters.network_instance);
	    if (!nwi)
	      {
		upf_debug
		  ("FAR: %d, Parameter with unknown network instance\n",
		   far->far_id);
		failed_rule_id->id = far->far_id;
		r = -1;
		vec_pop (rules->far);
		break;
	      }

	    create->forward.nwi_index = nwi - gtm->nwis;
	  }

	create->forward.dst_intf =
	  far->forwarding_parameters.destination_interface;

	if (ISSET_BIT (far->forwarding_parameters.grp.fields,
		       FORWARDING_PARAMETERS_REDIRECT_INFORMATION))
	  {
	    create->forward.flags |= FAR_F_REDIRECT_INFORMATION;
	    cpy_redirect_information
	      (&create->forward.redirect_information,
	       &far->forwarding_parameters.redirect_information);

	  }

	if (ISSET_BIT (far->forwarding_parameters.grp.fields,
		       FORWARDING_PARAMETERS_OUTER_HEADER_CREATION))
	  {
	    pfcp_outer_header_creation_t *ohc =
	      &far->forwarding_parameters.outer_header_creation;
	    u32 fib_index;
	    int is_ip4 = !!(ohc->description & OUTER_HEADER_CREATION_ANY_IP4);

	    create->forward.flags |= FAR_F_OUTER_HEADER_CREATION;
	    create->forward.outer_header_creation =
	      far->forwarding_parameters.outer_header_creation;

	    fib_index =
	      upf_nwi_fib_index (is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6,
				 create->forward.nwi_index);
	    if (~0 == fib_index)
	      {
		upf_debug
		  ("FAR: %d, Network instance with invalid VRF for IPv%d\n",
		   far->far_id, is_ip4 ? 4 : 6);
		failed_rule_id->id = far->far_id;
		r = -1;
		vec_pop (rules->far);
		break;
	      }
	    create->forward.dst_sw_if_index =
	      upf_ip46_get_resolving_interface (fib_index, &ohc->ip, is_ip4);
	    if (~0 == create->forward.dst_sw_if_index)
	      {
		clib_warning
		  ("FAR: %d, No route to %U in fib index %d\n",
		   far->far_id, format_ip46_address, &ohc->ip, IP46_TYPE_ANY,
		   is_ip4 ? ip4_fib_get (fib_index)->table_id :
		   ip6_fib_get (fib_index)->table_id);

		failed_rule_id->id = far->far_id;
		r = -1;
		vec_pop (rules->far);
		break;
	      }

	    ip_udp_gtpu_rewrite (&create->forward, fib_index, is_ip4);
	  }
	//TODO: transport_level_marking
	//TODO: forwarding_policy
	//TODO: header_enrichment
      }
  }

  pfcp_sort_fars (rules);

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_FAR;
    }

  return r;
}

static int
handle_update_far (upf_session_t * sx, pfcp_update_far_t * update_far,
		   struct pfcp_group *grp,
		   int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  upf_main_t *gtm = &upf_main;
  pfcp_update_far_t *far;
  int r = 0;

  if ((r = pfcp_make_pending_far (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  vec_foreach (far, update_far)
  {
    upf_far_t *update;

    update = pfcp_get_far (sx, PFCP_PENDING, far->far_id);
    if (!update)
      {
	upf_debug ("PFCP Session %" PRIu64 ", update FAR Id %d not found.\n",
		   sx->cp_seid, far->far_id);
	failed_rule_id->id = far->far_id;
	r = -1;
	break;
      }

    update->apply_action =
      OPT (far, UPDATE_FAR_APPLY_ACTION, apply_action, update->apply_action);

    if ((update->apply_action & FAR_FORWARD) &&
	ISSET_BIT (far->grp.fields, UPDATE_FAR_UPDATE_FORWARDING_PARAMETERS))
      {
	if (ISSET_BIT (far->update_forwarding_parameters.grp.fields,
		       UPDATE_FORWARDING_PARAMETERS_NETWORK_INSTANCE))
	  {
	    if (vec_len (far->update_forwarding_parameters.network_instance)
		!= 0)
	      {
		upf_nwi_t *nwi =
		  lookup_nwi (far->
			      update_forwarding_parameters.network_instance);
		if (!nwi)
		  {
		    upf_debug
		      ("FAR: %d, Update Parameter with unknown network instance\n",
		       far->far_id);
		    failed_rule_id->id = far->far_id;
		    r = -1;
		    break;
		  }
		update->forward.nwi_index = nwi - gtm->nwis;
	      }
	    else
	      {
		update->forward.nwi_index = ~0;
	      }
	  }

	update->forward.dst_intf =
	  far->update_forwarding_parameters.destination_interface;

	if (ISSET_BIT (far->update_forwarding_parameters.grp.fields,
		       UPDATE_FORWARDING_PARAMETERS_REDIRECT_INFORMATION))
	  {
	    update->forward.flags |= FAR_F_REDIRECT_INFORMATION;
	    free_redirect_information (&update->forward.redirect_information);
	    cpy_redirect_information
	      (&update->forward.redirect_information,
	       &far->update_forwarding_parameters.redirect_information);
	  }

	if (ISSET_BIT (far->update_forwarding_parameters.grp.fields,
		       UPDATE_FORWARDING_PARAMETERS_OUTER_HEADER_CREATION))
	  {
	    pfcp_outer_header_creation_t *ohc =
	      &far->update_forwarding_parameters.outer_header_creation;
	    u32 fib_index;
	    int is_ip4 = !!(ohc->description & OUTER_HEADER_CREATION_ANY_IP4);

	    if (ISSET_BIT (far->update_forwarding_parameters.grp.fields,
			   UPDATE_FORWARDING_PARAMETERS_PFCPSMREQ_FLAGS) &&
		far->update_forwarding_parameters.pfcpsmreq_flags &
		PFCPSMREQ_SNDEM)
	      pfcp_send_end_marker (sx, far->far_id);

	    update->forward.flags |= FAR_F_OUTER_HEADER_CREATION;
	    update->forward.outer_header_creation = *ohc;

	    fib_index =
	      upf_nwi_fib_index (is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6,
				 update->forward.nwi_index);
	    if (~0 == fib_index)
	      {
		upf_debug
		  ("FAR: %d, Network instance with invalid VRF for IPv%d\n",
		   far->far_id, is_ip4 ? 4 : 6);
		failed_rule_id->id = far->far_id;
		r = -1;
		break;
	      }

	    update->forward.dst_sw_if_index =
	      upf_ip46_get_resolving_interface (fib_index, &ohc->ip, is_ip4);
	    if (~0 == update->forward.dst_sw_if_index)
	      {
		upf_debug
		  ("FAR: %d, No route to %U in table %d\n",
		   far->far_id, format_ip46_address, &ohc->ip, IP46_TYPE_ANY,
		   is_ip4 ? ip4_fib_get (fib_index)->table_id :
		   ip6_fib_get (fib_index)->table_id);

		failed_rule_id->id = far->far_id;
		r = -1;
		break;
	      }

	    ip_udp_gtpu_rewrite (&update->forward, fib_index, is_ip4);
	  }
	//TODO: transport_level_marking
	//TODO: forwarding_policy
	//TODO: header_enrichment
      }
  }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_FAR;
    }

  return r;
}

static int
handle_remove_far (upf_session_t * sx, pfcp_remove_far_t * remove_far,
		   struct pfcp_group *grp,
		   int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  pfcp_remove_far_t *far;
  int r = 0;

  if ((r = pfcp_make_pending_far (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  vec_foreach (far, remove_far)
  {
    if ((r = pfcp_delete_far (sx, far->far_id)) != 0)
      {
	upf_debug ("Failed to add FAR %d\n", far->far_id);
	failed_rule_id->id = far->far_id;
	r = -1;
	break;
      }
  }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_FAR;
    }

  return r;
}

static int
handle_create_urr (upf_session_t * sx, pfcp_create_urr_t * create_urr,
		   f64 now, struct pfcp_group *grp, int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  pfcp_create_urr_t *urr;
  struct rules *rules;
  int r = 0;

  if ((r = pfcp_make_pending_urr (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  rules = pfcp_get_rules (sx, PFCP_PENDING);
  vec_alloc (rules->urr, vec_len (create_urr));

  vec_foreach (urr, create_urr)
  {
    upf_urr_t *create;

    vec_add2 (rules->urr, create, 1);
    memset (create, 0, sizeof (*create));

    create->measurement_period.handle =
      create->time_threshold.handle =
      create->time_quota.handle = create->traffic_timer.handle = ~0;
    create->monitoring_time.vlib_time = INFINITY;
    create->time_of_first_packet = INFINITY;
    create->time_of_last_packet = INFINITY;

    create->id = urr->urr_id;
    create->methods = urr->measurement_method;
    create->triggers =
      OPT (urr, CREATE_URR_REPORTING_TRIGGERS, reporting_triggers, 0);
    create->start_time = now;

    if (ISSET_BIT (urr->grp.fields, CREATE_URR_MEASUREMENT_PERIOD))
      {
	create->update_flags |= PFCP_URR_UPDATE_MEASUREMENT_PERIOD;
	create->measurement_period.period = urr->measurement_period;
	create->measurement_period.base = now;
      }

    if (ISSET_BIT (urr->grp.fields, CREATE_URR_VOLUME_THRESHOLD))
      {
	create->volume.threshold.ul = urr->volume_threshold.ul;
	create->volume.threshold.dl = urr->volume_threshold.dl;
	create->volume.threshold.total = urr->volume_threshold.total;
      }

    if (ISSET_BIT (urr->grp.fields, CREATE_URR_VOLUME_QUOTA))
      {
	create->volume.quota.ul = urr->volume_quota.ul;
	create->volume.quota.dl = urr->volume_quota.dl;
	create->volume.quota.total = urr->volume_quota.total;
      }

    if (ISSET_BIT (urr->grp.fields, CREATE_URR_TIME_THRESHOLD))
      {
	create->update_flags |= PFCP_URR_UPDATE_TIME_THRESHOLD;
	create->time_threshold.period = urr->time_threshold;
	create->time_threshold.base = now;
      }
    if (ISSET_BIT (urr->grp.fields, CREATE_URR_TIME_QUOTA))
      {
	create->update_flags |= PFCP_URR_UPDATE_TIME_QUOTA;
	create->time_quota.period = urr->time_quota;
	create->time_quota.base = now;
      }

    //TODO: quota_holding_time;
    //TODO: dropped_dl_traffic_threshold;

    if (ISSET_BIT (urr->grp.fields, CREATE_URR_MONITORING_TIME))
      {
	f64 secs;

	create->update_flags |= PFCP_URR_UPDATE_MONITORING_TIME;
	create->monitoring_time.unix_time =
	  urr->monitoring_time + modf (sx->unix_time_start, &secs);
	create->monitoring_time.vlib_time =
	  vlib_time_now (psm->vlib_main) +
	  (create->monitoring_time.unix_time - now);
      }

    //TODO: subsequent_volume_threshold;
    //TODO: subsequent_time_threshold;
    //TODO: inactivity_detection_time;

    if (ISSET_BIT (urr->grp.fields, CREATE_URR_LINKED_URR_ID) &&
	create->triggers & REPORTING_TRIGGER_LINKED_USAGE_REPORTING)
      create->linked_urr_ids = vec_dup (urr->linked_urr_id);

    //TODO: linked_urr_id;
    //TODO: measurement_information;
    //TODO: time_quota_mechanism;
  }

  pfcp_sort_urrs (rules);

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_URR;
    }

  return r;
}

static int
handle_update_urr (upf_session_t * sx, pfcp_update_urr_t * update_urr,
		   f64 now, struct pfcp_group *grp, int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  pfcp_update_urr_t *urr;
  int r = 0;

  if ((r = pfcp_make_pending_urr (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  vec_foreach (urr, update_urr)
  {
    upf_urr_t *update;

    update = pfcp_get_urr (sx, PFCP_PENDING, urr->urr_id);
    if (!update)
      {
	upf_debug ("PFCP Session %" PRIu64 ", update URR Id %d not found.\n",
		   sx->cp_seid, urr->urr_id);
	failed_rule_id->id = urr->urr_id;
	r = -1;
	break;
      }

    update->methods = urr->measurement_method;
    update->triggers = OPT (urr, UPDATE_URR_REPORTING_TRIGGERS,
			    reporting_triggers, update->triggers);
    update->status &= ~URR_OVER_QUOTA;

    if (ISSET_BIT (urr->grp.fields, UPDATE_URR_MEASUREMENT_PERIOD))
      {
	update->update_flags |= PFCP_URR_UPDATE_MEASUREMENT_PERIOD;
	update->measurement_period.period = urr->measurement_period;

	/* TODO:
	 *
	 * 3GPP TS 29.244 is not clear on whether the inclusion of
	 * Measurement-Period IE resets the start of the periodic
	 * reporting.
	 *
	 * The current implementation does reset the start time
	 * for periodic reporting
	 */
	update->measurement_period.base = now;
      }

    if (ISSET_BIT (urr->grp.fields, UPDATE_URR_VOLUME_THRESHOLD))
      {
	update->volume.threshold.ul = urr->volume_threshold.ul;
	update->volume.threshold.dl = urr->volume_threshold.dl;
	update->volume.threshold.total = urr->volume_threshold.total;
      }
    if (ISSET_BIT (urr->grp.fields, UPDATE_URR_VOLUME_QUOTA))
      {
	update->update_flags |= PFCP_URR_UPDATE_VOLUME_QUOTA;
	memset (&update->volume.measure.consumed, 0,
		sizeof (update->volume.measure.consumed));
	update->volume.quota.ul = urr->volume_quota.ul;
	update->volume.quota.dl = urr->volume_quota.dl;
	update->volume.quota.total = urr->volume_quota.total;
      }

    if (ISSET_BIT (urr->grp.fields, UPDATE_URR_TIME_THRESHOLD))
      {
	update->update_flags |= PFCP_URR_UPDATE_TIME_THRESHOLD;
	update->time_threshold.period = urr->time_threshold;
      }
    if (ISSET_BIT (urr->grp.fields, UPDATE_URR_TIME_QUOTA))
      {
	update->update_flags |= PFCP_URR_UPDATE_TIME_QUOTA;
	update->time_quota.period = urr->time_quota;
	update->time_quota.base = update->start_time;
      }

    //TODO: quota_holding_time;
    //TODO: dropped_dl_traffic_threshold;

    if (ISSET_BIT (urr->grp.fields, UPDATE_URR_MONITORING_TIME))
      {
	f64 secs;

	update->update_flags |= PFCP_URR_UPDATE_MONITORING_TIME;
	update->monitoring_time.unix_time =
	  urr->monitoring_time + modf (sx->unix_time_start, &secs);
	update->monitoring_time.vlib_time =
	  vlib_time_now (psm->vlib_main) +
	  (update->monitoring_time.unix_time - now);
      }

    //TODO: subsequent_volume_threshold;
    //TODO: subsequent_time_threshold;
    //TODO: inactivity_detection_time;

    if (ISSET_BIT (urr->grp.fields, UPDATE_URR_LINKED_URR_ID) &&
	update->triggers & REPORTING_TRIGGER_LINKED_USAGE_REPORTING)
      update->linked_urr_ids = vec_dup (urr->linked_urr_id);
    else
      vec_free (update->linked_urr_ids);

    //TODO: measurement_information;
    //TODO: time_quota_mechanism;
  }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_URR;
    }

  return r;
}

static int
handle_remove_urr (upf_session_t * sx, pfcp_remove_urr_t * remove_urr,
		   f64 now, struct pfcp_group *grp, int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  pfcp_remove_urr_t *urr;
  int r = 0;

  if ((r = pfcp_make_pending_urr (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  vec_foreach (urr, remove_urr)
  {
    if ((r = pfcp_delete_urr (sx, urr->urr_id)) != 0)
      {
	upf_debug ("Failed to add URR %d\n", urr->urr_id);
	failed_rule_id->id = urr->urr_id;
	r = -1;
	break;
      }
  }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_URR;
    }

  return r;
}

static int
handle_create_qer (upf_session_t * sx, pfcp_create_qer_t * create_qer,
		   f64 now, struct pfcp_group *grp, int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  upf_main_t *gtm = &upf_main;
  pfcp_create_qer_t *qer;
  struct rules *rules;
  int r = 0;

  if ((r = pfcp_make_pending_qer (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  rules = pfcp_get_rules (sx, PFCP_PENDING);
  vec_alloc (rules->qer, vec_len (create_qer));

  vec_foreach (qer, create_qer)
  {
    upf_qer_t *create;

    vec_add2 (rules->qer, create, 1);
    memset (create, 0, sizeof (*create));

    create->id = qer->qer_id;
    create->policer.key =
      OPT (qer, CREATE_QER_QER_CORRELATION_ID, qer_correlation_id,
	   (u64) (sx - gtm->sessions) << 32 | create->id);
    create->policer.value = ~0;

    create->gate_status[UPF_UL] = qer->gate_status.ul;
    create->gate_status[UPF_DL] = qer->gate_status.dl;

    if (ISSET_BIT (qer->grp.fields, CREATE_QER_MBR))
      {
	create->flags |= PFCP_QER_MBR;
	create->mbr = qer->mbr;
      }

    //TODO: gbr;
    //TODO: packet_rate;
    //TODO: dl_flow_level_marking;
    //TODO: qos_flow_identifier;
    //TODO: reflective_qos;
  }

  pfcp_sort_qers (rules);

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_QER;
    }

  return r;
}

static int
handle_update_qer (upf_session_t * sx, pfcp_update_qer_t * update_qer,
		   f64 now, struct pfcp_group *grp, int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  upf_main_t *gtm = &upf_main;
  pfcp_update_qer_t *qer;
  int r = 0;

  if ((r = pfcp_make_pending_qer (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  vec_foreach (qer, update_qer)
  {
    upf_qer_t *update;

    update = pfcp_get_qer (sx, PFCP_PENDING, qer->qer_id);
    if (!update)
      {
	upf_debug ("PFCP Session %" PRIu64 ", update QER Id %d not found.\n",
		   sx->cp_seid, qer->qer_id);
	failed_rule_id->id = qer->qer_id;
	r = -1;
	break;
      }

    update->policer.key =
      (ISSET_BIT (qer->grp.fields, UPDATE_QER_QER_CORRELATION_ID)) ?
      qer->qer_correlation_id : (u64) (sx - gtm->sessions) << 32 | update->id;
    update->policer.value = ~0;

    if (ISSET_BIT (qer->grp.fields, UPDATE_QER_GATE_STATUS))
      {
	update->gate_status[UPF_UL] = qer->gate_status.ul;
	update->gate_status[UPF_DL] = qer->gate_status.dl;
      }

    if (ISSET_BIT (qer->grp.fields, UPDATE_QER_MBR))
      {
	update->flags |= PFCP_QER_MBR;
	update->mbr = qer->mbr;
      }

    //TODO: gbr;
    //TODO: packet_rate;
    //TODO: dl_flow_level_marking;
    //TODO: qos_flow_identifier;
    //TODO: reflective_qos;
  }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_QER;
    }

  return r;
}

static int
handle_remove_qer (upf_session_t * sx, pfcp_remove_qer_t * remove_qer,
		   f64 now, struct pfcp_group *grp, int failed_rule_id_field,
		   pfcp_failed_rule_id_t * failed_rule_id)
{
  struct pfcp_response *response = (struct pfcp_response *) (grp + 1);
  pfcp_remove_qer_t *qer;
  int r = 0;

  if ((r = pfcp_make_pending_qer (sx)) != 0)
    {
      response->cause = PFCP_CAUSE_NO_RESOURCES_AVAILABLE;
      return r;
    }

  vec_foreach (qer, remove_qer)
  {
    if ((r = pfcp_delete_qer (sx, qer->qer_id)) != 0)
      {
	upf_debug ("Failed to add QER %d\n", qer->qer_id);
	failed_rule_id->id = qer->qer_id;
	r = -1;
	break;
      }
  }

  if (r != 0)
    {
      response->cause = PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE;

      SET_BIT (grp->fields, failed_rule_id_field);
      failed_rule_id->type = FAILED_RULE_TYPE_QER;
    }

  return r;
}

static pfcp_usage_report_t *
init_usage_report (upf_urr_t * urr, u32 trigger,
		   pfcp_usage_report_t ** report)
{
  pfcp_usage_report_t *r;

  vec_add2 (*report, r, 1);
  memset (r, 0, sizeof (*r));

  SET_BIT (r->grp.fields, USAGE_REPORT_URR_ID);
  r->urr_id = urr->id;

  SET_BIT (r->grp.fields, USAGE_REPORT_UR_SEQN);
  r->ur_seqn = urr->seq_no;
  urr->seq_no++;

  SET_BIT (r->grp.fields, USAGE_REPORT_USAGE_REPORT_TRIGGER);
  r->usage_report_trigger = trigger;

  return r;
}

static void
report_usage_ev (upf_session_t * sess, ip46_address_t * ue, upf_urr_t * urr,
		 u32 trigger, f64 now, pfcp_usage_report_t ** report)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_usage_report_t *r;
  urr_volume_t volume;
  u64 start_time, duration;
  f64 vnow = vlib_time_now (psm->vlib_main);

  ASSERT (report);

  clib_spinlock_lock (&sess->lock);

  volume = urr->volume;
  memset (&urr->volume.measure.packets, 0,
	  sizeof (urr->volume.measure.packets));
  memset (&urr->volume.measure.bytes, 0, sizeof (urr->volume.measure.bytes));

  if (!(urr->status & URR_AFTER_MONITORING_TIME) &&
      urr->monitoring_time.vlib_time != INFINITY &&
      urr->monitoring_time.unix_time < now)
    {
      urr->usage_before_monitoring_time.volume = urr->volume.measure;
      memset (&urr->volume.measure.packets, 0,
	      sizeof (urr->volume.measure.packets));
      memset (&urr->volume.measure.bytes, 0,
	      sizeof (urr->volume.measure.bytes));

      urr->usage_before_monitoring_time.start_time = urr->start_time;
      urr->usage_before_monitoring_time.time_of_first_packet =
	urr->time_of_first_packet;
      urr->usage_before_monitoring_time.time_of_last_packet =
	urr->time_of_last_packet;
      urr->start_time = urr->monitoring_time.unix_time;
      urr->time_of_first_packet = INFINITY;
      urr->time_of_last_packet = INFINITY;
      urr->monitoring_time.vlib_time = INFINITY;
      urr->status |= URR_AFTER_MONITORING_TIME;
    }

  clib_spinlock_unlock (&sess->lock);

  if (urr->status & URR_AFTER_MONITORING_TIME)
    {
      r =
	init_usage_report (urr, USAGE_REPORT_TRIGGER_MONITORING_TIME, report);

      SET_BIT (r->grp.fields, USAGE_REPORT_USAGE_INFORMATION);
      r->usage_information = USAGE_INFORMATION_BEFORE;

      start_time = trunc (urr->usage_before_monitoring_time.start_time);
      duration = trunc (urr->start_time) - start_time;

      if ((trigger & (USAGE_REPORT_TRIGGER_START_OF_TRAFFIC |
		      USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC)) == 0)
	{
	  SET_BIT (r->grp.fields, USAGE_REPORT_START_TIME);
	  SET_BIT (r->grp.fields, USAGE_REPORT_END_TIME);

	  r->start_time = start_time;
	  r->end_time = r->start_time + duration;

	  if (urr->usage_before_monitoring_time.time_of_first_packet !=
	      INFINITY)
	    {
	      SET_BIT (r->grp.fields, USAGE_REPORT_TIME_OF_FIRST_PACKET);
	      r->time_of_first_packet =
		trunc (now -
		       (vnow -
			urr->
			usage_before_monitoring_time.time_of_first_packet));

	      if (urr->usage_before_monitoring_time.time_of_last_packet !=
		  INFINITY)
		{
		  SET_BIT (r->grp.fields, USAGE_REPORT_TIME_OF_LAST_PACKET);
		  r->time_of_last_packet =
		    trunc (now -
			   (vnow -
			    urr->
			    usage_before_monitoring_time.time_of_last_packet));
		}
	    }

	  SET_BIT (r->grp.fields, USAGE_REPORT_TP_NOW);
	  SET_BIT (r->grp.fields, USAGE_REPORT_TP_START_TIME);
	  SET_BIT (r->grp.fields, USAGE_REPORT_TP_END_TIME);

	  r->tp_now = now;
	  r->tp_start_time = urr->usage_before_monitoring_time.start_time;
	  r->tp_end_time = urr->start_time;
	}

      SET_BIT (r->grp.fields, USAGE_REPORT_VOLUME_MEASUREMENT);
      r->volume_measurement.fields = PFCP_VOLUME_ALL;

      r->volume_measurement.volume.ul =
	urr->usage_before_monitoring_time.volume.bytes.ul;
      r->volume_measurement.volume.dl =
	urr->usage_before_monitoring_time.volume.bytes.dl;
      r->volume_measurement.volume.total =
	urr->usage_before_monitoring_time.volume.bytes.total;
      r->volume_measurement.packets.ul =
	urr->usage_before_monitoring_time.volume.packets.ul;
      r->volume_measurement.packets.dl =
	urr->usage_before_monitoring_time.volume.packets.dl;
      r->volume_measurement.packets.total =
	urr->usage_before_monitoring_time.volume.packets.total;

      SET_BIT (r->grp.fields, USAGE_REPORT_DURATION_MEASUREMENT);
      r->duration_measurement = duration;

      urr->monitoring_time.vlib_time = INFINITY;
    }

  r = init_usage_report (urr, trigger, report);

  if (urr->status & URR_AFTER_MONITORING_TIME)
    {
      SET_BIT (r->grp.fields, USAGE_REPORT_USAGE_INFORMATION);
      r->usage_information = USAGE_INFORMATION_AFTER;
    }

  start_time = trunc (urr->start_time);
  duration = trunc (now) - start_time;

  if ((trigger & (USAGE_REPORT_TRIGGER_START_OF_TRAFFIC |
		  USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC)) == 0)
    {
      SET_BIT (r->grp.fields, USAGE_REPORT_START_TIME);
      SET_BIT (r->grp.fields, USAGE_REPORT_END_TIME);

      r->start_time = start_time;
      r->end_time = r->start_time + duration;


      if (urr->time_of_first_packet != INFINITY)
	{
	  SET_BIT (r->grp.fields, USAGE_REPORT_TIME_OF_FIRST_PACKET);
	  r->time_of_first_packet =
	    trunc (now - (vnow - urr->time_of_first_packet));

	  if (urr->time_of_last_packet != INFINITY)
	    {
	      SET_BIT (r->grp.fields, USAGE_REPORT_TIME_OF_LAST_PACKET);
	      r->time_of_last_packet =
		trunc (now - (vnow - urr->time_of_last_packet));
	    }
	}

      SET_BIT (r->grp.fields, USAGE_REPORT_TP_NOW);
      SET_BIT (r->grp.fields, USAGE_REPORT_TP_START_TIME);
      SET_BIT (r->grp.fields, USAGE_REPORT_TP_END_TIME);

      r->tp_now = now;
      r->tp_start_time = urr->start_time;
      r->tp_end_time = urr->start_time + duration;
    }

  if (((trigger & (USAGE_REPORT_TRIGGER_START_OF_TRAFFIC |
		   USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC)) != 0)
      && (ue != NULL))
    {

      SET_BIT (r->grp.fields, USAGE_REPORT_UE_IP_ADDRESS);
      if (ip46_address_is_ip4 (ue))
	{
	  r->ue_ip_address.flags = IE_UE_IP_ADDRESS_V4;
	  r->ue_ip_address.ip4 = ue->ip4;
	}
      else
	{
	  r->ue_ip_address.flags = IE_UE_IP_ADDRESS_V6;
	  r->ue_ip_address.ip6 = ue->ip6;
	}
    }

  if ((trigger & USAGE_REPORT_TRIGGER_START_OF_TRAFFIC) == 0)
    {
      SET_BIT (r->grp.fields, USAGE_REPORT_VOLUME_MEASUREMENT);
      r->volume_measurement.fields = PFCP_VOLUME_ALL;

      r->volume_measurement.volume.ul = volume.measure.bytes.ul;
      r->volume_measurement.volume.dl = volume.measure.bytes.dl;
      r->volume_measurement.volume.total = volume.measure.bytes.total;
      r->volume_measurement.packets.ul = volume.measure.packets.ul;
      r->volume_measurement.packets.dl = volume.measure.packets.dl;
      r->volume_measurement.packets.total = volume.measure.packets.total;

      SET_BIT (r->grp.fields, USAGE_REPORT_DURATION_MEASUREMENT);
      r->duration_measurement = duration;
    }

  /* SET_BIT(r->grp.fields, USAGE_REPORT_APPLICATION_DETECTION_INFORMATION); */
  /* SET_BIT(r->grp.fields, USAGE_REPORT_NETWORK_INSTANCE); */
  /* SET_BIT(r->grp.fields, USAGE_REPORT_USAGE_INFORMATION); */

  urr->status &= ~URR_AFTER_MONITORING_TIME;
  urr->start_time += duration;
  if (urr->time_threshold.base)
    urr->time_threshold.base = urr->start_time;
  urr->time_of_first_packet = INFINITY;
  urr->time_of_last_packet = INFINITY;
}

void
upf_usage_report_build (upf_session_t * sx,
			ip46_address_t * ue,
			upf_urr_t * urr, f64 now,
			upf_usage_report_t * report,
			pfcp_usage_report_t ** usage_report)
{
  u32 idx;

  clib_warning ("Usage Report:\n  LIUSA %U\n",
		format_bitmap_hex, report->liusa_bitmap);

  vec_foreach_index (idx, report->events)
  {
    upf_usage_report_ev_t *r = vec_elt_at_index (report->events, idx);

    if (r->triggers)
      report_usage_ev (sx, ue, vec_elt_at_index (urr, idx),
		       r->triggers, r->now, usage_report);
    else
      {
	/* not triggered, check LIUSA reporting */

	if (clib_bitmap_get (report->liusa_bitmap, idx))
	  report_usage_ev (sx, ue, vec_elt_at_index (urr, idx),
			   USAGE_REPORT_TRIGGER_LINKED_USAGE_REPORTING,
			   now, usage_report);
      }
  }
}


static int
handle_session_set_deletion_request (pfcp_msg_t * req,
				     pfcp_session_set_deletion_request_t *
				     msg)
{
  return -1;
}

static int
handle_session_set_deletion_response (pfcp_msg_t * req,
				      pfcp_simple_response_t * msg)
{
  return -1;
}

static int
handle_session_establishment_request (pfcp_msg_t * req,
				      pfcp_session_establishment_request_t *
				      msg)
{
  pfcp_session_establishment_response_t resp;
  ip46_address_t up_address = ip46_address_initializer;
  ip46_address_t cp_address = ip46_address_initializer;
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_session_t *sess = NULL;
  upf_node_assoc_t *assoc;
  f64 now = psm->now;
  int r = 0;
  int is_ip4;

  memset (&resp, 0, sizeof (resp));
  SET_BIT (resp.grp.fields, SESSION_ESTABLISHMENT_RESPONSE_CAUSE);
  resp.response.cause = PFCP_CAUSE_REQUEST_REJECTED;

  assoc = pfcp_get_association (&msg->request.node_id);
  if (!assoc)
    {
      resp.response.cause = PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION;
      upf_pfcp_send_response (req, msg->f_seid.seid,
			      PFCP_SESSION_ESTABLISHMENT_RESPONSE, &resp.grp);

      return -1;
    }

  SET_BIT (resp.grp.fields, SESSION_ESTABLISHMENT_RESPONSE_UP_F_SEID);
  resp.up_f_seid.seid = msg->f_seid.seid;

  is_ip4 = ip46_address_is_ip4 (&req->rmt.address);
  if (is_ip4)
    {
      resp.up_f_seid.flags |= IE_F_SEID_IP_ADDRESS_V4;
      resp.up_f_seid.ip4 = req->lcl.address.ip4;

      ip_set (&up_address, &req->lcl.address.ip4, 1);
      ip_set (&cp_address, &msg->f_seid.ip4, 1);
    }
  else
    {
      resp.up_f_seid.flags |= IE_F_SEID_IP_ADDRESS_V6;
      resp.up_f_seid.ip6 = req->lcl.address.ip6;

      ip_set (&up_address, &req->lcl.address.ip6, 0);
      ip_set (&cp_address, &msg->f_seid.ip6, 0);
    }

  sess =
    pfcp_create_session (assoc, &up_address, msg->f_seid.seid, &cp_address);

  if (ISSET_BIT
      (msg->grp.fields,
       SESSION_ESTABLISHMENT_REQUEST_USER_PLANE_INACTIVITY_TIMER))
    {
      struct rules *pending = pfcp_get_rules (sess, PFCP_PENDING);

      pending->inactivity_timer.period = msg->user_plane_inactivity_timer;
      pending->inactivity_timer.handle = ~0;
    }

  if ((r = handle_create_pdr (sess, msg->create_pdr, &resp.grp,
			      SESSION_ESTABLISHMENT_RESPONSE_FAILED_RULE_ID,
			      &resp.failed_rule_id)) != 0)
    goto out_send_resp;

  if ((r = handle_create_far (sess, msg->create_far, &resp.grp,
			      SESSION_ESTABLISHMENT_RESPONSE_FAILED_RULE_ID,
			      &resp.failed_rule_id)) != 0)
    goto out_send_resp;

  if ((r = handle_create_urr (sess, msg->create_urr, now, &resp.grp,
			      SESSION_ESTABLISHMENT_RESPONSE_FAILED_RULE_ID,
			      &resp.failed_rule_id)) != 0)
    goto out_send_resp;

  r = pfcp_update_apply (sess);
  upf_debug ("Appy: %d\n", r);

  pfcp_update_finish (sess);

  upf_debug ("%U", format_pfcp_session, sess, PFCP_ACTIVE, /*debug */ 1);

out_send_resp:
  if (r == 0)
    resp.response.cause = PFCP_CAUSE_REQUEST_ACCEPTED;

  upf_pfcp_send_response (req, sess->cp_seid,
			  PFCP_SESSION_ESTABLISHMENT_RESPONSE, &resp.grp);

  if (r != 0)
    {
      if (pfcp_disable_session (sess, false) != 0)
	clib_error ("failed to remove UPF session 0x%016" PRIx64,
		    sess->cp_seid);
      pfcp_free_session (sess);
    }

  return r;
}

static int
handle_session_establishment_response (pfcp_msg_t * req,
				       pfcp_session_establishment_response_t *
				       msg)
{
  return -1;
}

static int
handle_session_modification_request (pfcp_msg_t * req,
				     pfcp_session_modification_request_t *
				     msg)
{
  pfcp_session_modification_response_t resp;
  pfcp_server_main_t *psm = &pfcp_server_main;
  upf_usage_report_t report;
  pfcp_query_urr_t *qry;
  struct rules *active;
  upf_session_t *sess;
  f64 now = psm->now;
  u64 cp_seid = 0;
  int r = 0;

  memset (&resp, 0, sizeof (resp));
  SET_BIT (resp.grp.fields, SESSION_ESTABLISHMENT_RESPONSE_CAUSE);
  resp.response.cause = PFCP_CAUSE_REQUEST_REJECTED;

  if (!(sess = pfcp_lookup (be64toh (req->hdr->session_hdr.seid))))
    {
      upf_debug ("PFCP Session %" PRIu64 " not found.\n",
		 be64toh (req->hdr->session_hdr.seid));
      resp.response.cause = PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;

      r = -1;
      goto out_send_resp;
    }

  cp_seid = sess->cp_seid;

  if (msg->grp.fields &
      (BIT (SESSION_MODIFICATION_REQUEST_USER_PLANE_INACTIVITY_TIMER) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_PDR) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_FAR) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_URR) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_QER) |
       BIT (SESSION_MODIFICATION_REQUEST_REMOVE_BAR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_PDR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_FAR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_URR) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_QER) |
       BIT (SESSION_MODIFICATION_REQUEST_CREATE_BAR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_PDR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_FAR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_URR) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_QER) |
       BIT (SESSION_MODIFICATION_REQUEST_UPDATE_BAR)))
    {
      /* invoke the update process only if a update is include */
      pfcp_update_session (sess);

      if (msg->grp.fields &
	  BIT (SESSION_MODIFICATION_REQUEST_USER_PLANE_INACTIVITY_TIMER))
	{
	  struct rules *pending = pfcp_get_rules (sess, PFCP_PENDING);

	  pending->inactivity_timer.period = msg->user_plane_inactivity_timer;
	  pending->inactivity_timer.handle = ~0;
	}

      if ((r = handle_create_pdr (sess, msg->create_pdr, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_update_pdr (sess, msg->update_pdr, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_remove_pdr (sess, msg->remove_pdr, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_create_far (sess, msg->create_far, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_update_far (sess, msg->update_far, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_remove_far (sess, msg->remove_far, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_create_urr (sess, msg->create_urr, now, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_update_urr (sess, msg->update_urr, now, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_remove_urr (sess, msg->remove_urr, now, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_create_qer (sess, msg->create_qer, now, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_update_qer (sess, msg->update_qer, now, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = handle_remove_qer (sess, msg->remove_qer, now, &resp.grp,
				  SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID,
				  &resp.failed_rule_id)) != 0)
	goto out_send_resp;

      if ((r = pfcp_update_apply (sess)) != 0)
	goto out_update_finish;
    }

  active = pfcp_get_rules (sess, PFCP_ACTIVE);
  upf_usage_report_init (&report, vec_len (active->urr));

  if (ISSET_BIT (msg->grp.fields, SESSION_MODIFICATION_REQUEST_QUERY_URR) &&
      vec_len (msg->query_urr) != 0)
    {
      SET_BIT (resp.grp.fields, SESSION_MODIFICATION_RESPONSE_USAGE_REPORT);

      vec_foreach (qry, msg->query_urr)
      {
	upf_urr_t *urr;

	if (!(urr = pfcp_get_urr_by_id (active, qry->urr_id)))
	  continue;

	upf_usage_report_trigger (&report, urr - active->urr,
				  USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT,
				  urr->liusa_bitmap, now);
      }
    }
  else
    if (ISSET_BIT
	(msg->grp.fields, SESSION_MODIFICATION_REQUEST_PFCPSMREQ_FLAGS)
	&& msg->pfcpsmreq_flags & PFCPSMREQ_QAURR)
    {
      if (vec_len (active->urr) != 0)
	{
	  SET_BIT (resp.grp.fields,
		   SESSION_MODIFICATION_RESPONSE_USAGE_REPORT);
	  upf_usage_report_set (&report,
				USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT, now);
	}
    }

  upf_usage_report_build (sess, NULL, active->urr, now, &report,
			  &resp.usage_report);
  upf_usage_report_free (&report);

out_update_finish:
  pfcp_update_finish (sess);

  upf_debug ("%U", format_pfcp_session, sess, PFCP_ACTIVE, /*debug */ 1);

out_send_resp:
  if (r == 0)
    resp.response.cause = PFCP_CAUSE_REQUEST_ACCEPTED;

  upf_pfcp_send_response (req, cp_seid, PFCP_SESSION_MODIFICATION_RESPONSE,
			  &resp.grp);

  return r;
}

static int
handle_session_modification_response (pfcp_msg_t * req,
				      pfcp_session_modification_response_t *
				      msg)
{
  return -1;
}

static int
handle_session_deletion_request (pfcp_msg_t * req,
				 pfcp_session_deletion_request_t * msg)
{
  pfcp_server_main_t *psm = &pfcp_server_main;
  pfcp_session_deletion_response_t resp;
  struct rules *active;
  f64 now = psm->now;
  upf_session_t *sess;
  u64 cp_seid = 0;
  int r = 0;

  memset (&resp, 0, sizeof (resp));
  SET_BIT (resp.grp.fields, SESSION_DELETION_RESPONSE_CAUSE);
  resp.response.cause = PFCP_CAUSE_REQUEST_REJECTED;

  if (!(sess = pfcp_lookup (be64toh (req->hdr->session_hdr.seid))))
    {
      upf_debug ("PFCP Session %" PRIu64 " not found.\n",
		 be64toh (req->hdr->session_hdr.seid));
      resp.response.cause = PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;

      r = -1;
      goto out_send_resp_no_session;
    }

  cp_seid = sess->cp_seid;

  if ((r = pfcp_disable_session (sess, true)) != 0)
    {
      upf_debug ("PFCP Session %" PRIu64 " could no be disabled.\n",
		 be64toh (req->hdr->session_hdr.seid));
      goto out_send_resp;
    }

  active = pfcp_get_rules (sess, PFCP_ACTIVE);
  if (vec_len (active->urr) != 0)
    {
      upf_usage_report_t report;

      SET_BIT (resp.grp.fields, SESSION_DELETION_RESPONSE_USAGE_REPORT);

      upf_usage_report_init (&report, vec_len (active->urr));
      upf_usage_report_set (&report, USAGE_REPORT_TRIGGER_TERMINATION_REPORT,
			    now);
      upf_usage_report_build (sess, NULL, active->urr, now, &report,
			      &resp.usage_report);
      upf_usage_report_free (&report);
    }

out_send_resp:
  if (r == 0)
    {
      pfcp_free_session (sess);
      resp.response.cause = PFCP_CAUSE_REQUEST_ACCEPTED;
    }

out_send_resp_no_session:
  upf_pfcp_send_response (req, cp_seid, PFCP_SESSION_DELETION_RESPONSE,
			  &resp.grp);

  return r;
}

static int
handle_session_deletion_response (pfcp_msg_t * req,
				  pfcp_session_deletion_response_t * msg)
{
  return -1;
}

static int
handle_session_report_request (pfcp_msg_t * req,
			       pfcp_session_report_request_t * msg)
{
  return -1;
}

static int
handle_session_report_response (pfcp_msg_t * req,
				pfcp_session_report_response_t * msg)
{
  return -1;
}


static int
session_msg (pfcp_msg_t * msg)
{
  union
  {
    struct pfcp_group grp;
    pfcp_simple_response_t simple_response;
    pfcp_session_set_deletion_request_t session_set_deletion_request;
    pfcp_session_establishment_request_t session_establishment_request;
    pfcp_session_establishment_response_t session_establishment_response;
    pfcp_session_modification_request_t session_modification_request;
    pfcp_session_modification_response_t session_modification_response;
    pfcp_session_deletion_request_t session_deletion_request;
    pfcp_session_deletion_response_t session_deletion_response;
    pfcp_session_report_request_t session_report_request;
    pfcp_session_report_response_t session_report_response;
  } m;
  pfcp_offending_ie_t *err = NULL;
  int r = 0;

  if (!msg->hdr->s_flag)
    {
      upf_debug ("PFCP: session msg without SEID.");
      return -1;
    }

  memset (&m, 0, sizeof (m));
  r = pfcp_decode_msg (msg->hdr->type, &msg->hdr->session_hdr.ies[0],
		       clib_net_to_host_u16 (msg->hdr->length) -
		       sizeof (msg->hdr->session_hdr), &m.grp, &err);
  if (r != 0)
    {
      switch (msg->hdr->type)
	{
	case PFCP_SESSION_SET_DELETION_REQUEST:
	case PFCP_SESSION_ESTABLISHMENT_REQUEST:
	case PFCP_SESSION_MODIFICATION_REQUEST:
	case PFCP_SESSION_DELETION_REQUEST:
	case PFCP_SESSION_REPORT_REQUEST:
	  send_simple_repsonse (msg, 0, msg->hdr->type + 1, r, err);
	  break;

	default:
	  break;
	}

      pfcp_free_msg (msg->hdr->type, &m.grp);
      vec_free (err);
      return r;
    }

  switch (msg->hdr->type)
    {
    case PFCP_SESSION_SET_DELETION_REQUEST:
      r =
	handle_session_set_deletion_request (msg,
					     &m.session_set_deletion_request);
      break;

    case PFCP_SESSION_SET_DELETION_RESPONSE:
      r = handle_session_set_deletion_response (msg, &m.simple_response);
      break;

    case PFCP_SESSION_ESTABLISHMENT_REQUEST:
      r =
	handle_session_establishment_request (msg,
					      &m.
					      session_establishment_request);
      break;

    case PFCP_SESSION_ESTABLISHMENT_RESPONSE:
      r =
	handle_session_establishment_response (msg,
					       &m.
					       session_establishment_response);
      break;

    case PFCP_SESSION_MODIFICATION_REQUEST:
      r =
	handle_session_modification_request (msg,
					     &m.session_modification_request);
      break;

    case PFCP_SESSION_MODIFICATION_RESPONSE:
      r =
	handle_session_modification_response (msg,
					      &m.
					      session_modification_response);
      break;

    case PFCP_SESSION_DELETION_REQUEST:
      r = handle_session_deletion_request (msg, &m.session_deletion_request);
      break;

    case PFCP_SESSION_DELETION_RESPONSE:
      r =
	handle_session_deletion_response (msg, &m.session_deletion_response);
      break;

    case PFCP_SESSION_REPORT_REQUEST:
      r = handle_session_report_request (msg, &m.session_report_request);
      break;

    case PFCP_SESSION_REPORT_RESPONSE:
      r = handle_session_report_response (msg, &m.session_report_response);
      break;

    default:
      break;
    }

  pfcp_free_msg (msg->hdr->type, &m.grp);
  return 0;
}

void
upf_pfcp_error_report (upf_session_t * sx, gtp_error_ind_t * error)
{
  pfcp_session_report_request_t req;
  pfcp_f_teid_t f_teid;

  memset (&req, 0, sizeof (req));
  SET_BIT (req.grp.fields, SESSION_REPORT_REQUEST_REPORT_TYPE);
  req.report_type = REPORT_TYPE_ERIR;

  SET_BIT (req.grp.fields, SESSION_REPORT_REQUEST_ERROR_INDICATION_REPORT);
  SET_BIT (req.error_indication_report.grp.fields,
	   ERROR_INDICATION_REPORT_F_TEID);

  f_teid.teid = error->teid;
  if (ip46_address_is_ip4 (&error->addr))
    {
      f_teid.flags = F_TEID_V4;
      f_teid.ip4 = error->addr.ip4;
    }
  else
    {
      f_teid.flags = F_TEID_V6;
      f_teid.ip6 = error->addr.ip6;
    }

  vec_add1 (req.error_indication_report.f_teid, f_teid);

  upf_pfcp_send_request (sx, PFCP_SESSION_REPORT_REQUEST, &req.grp);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
