/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */

#include <lb/lb.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/string.h>
#include <vpp/api/types.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>


#define vl_msg_id(n,h) n,
typedef enum {
#include <lb/lb.api.h>
    /* We'll want to know how many messages IDs we need... */
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id


/* define message structures */
#define vl_typedefs
#include <lb/lb.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <lb/lb.api.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <lb/lb.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <lb/lb.api.h>
#undef vl_msg_name_crc_list


#define REPLY_MSG_ID_BASE lbm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
setup_message_id_table (lb_main_t * lbm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + lbm->msg_id_base);
  foreach_vl_msg_name_crc_lb;
#undef _
}

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

static void
vl_api_lb_conf_t_handler
(vl_api_lb_conf_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_conf_reply_t * rmp;
  int rv = 0;

  if (mp->sticky_buckets_per_core == ~0) {
    mp->sticky_buckets_per_core = lbm->per_cpu_sticky_buckets;
  }
  if (mp->flow_timeout == ~0) {
    mp->flow_timeout = lbm->flow_timeout;
  }

  rv = lb_conf((ip4_address_t *)&mp->ip4_src_address,
               (ip6_address_t *)&mp->ip6_src_address,
               mp->sticky_buckets_per_core,
               mp->flow_timeout);

 REPLY_MACRO (VL_API_LB_CONF_REPLY);
}

static void *vl_api_lb_conf_t_print
(vl_api_lb_conf_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: lb_conf ");
  s = format (s, "%U ", format_ip4_address, (ip4_address_t *)&mp->ip4_src_address);
  s = format (s, "%U ", format_ip6_address, (ip6_address_t *)&mp->ip6_src_address);
  s = format (s, "%u ", mp->sticky_buckets_per_core);
  s = format (s, "%u ", mp->flow_timeout);
  FINISH;
}


static void
vl_api_lb_add_del_vip_t_handler
(vl_api_lb_add_del_vip_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_conf_reply_t * rmp;
  int rv = 0;
  lb_vip_add_args_t args;

  /* if port == 0, it means all-port VIP */
  if (mp->port == 0)
    {
      mp->protocol = ~0;
    }

  memcpy (&(args.prefix.ip6), mp->pfx.address.un.ip6, sizeof(args.prefix.ip6));

  if (mp->is_del) {
    u32 vip_index;
    if (!(rv = lb_vip_find_index(&(args.prefix), mp->pfx.address_length,
                                 mp->protocol, ntohs(mp->port), &vip_index)))
      rv = lb_vip_del(vip_index);
  } else {
    u32 vip_index;
    lb_vip_type_t type = 0;

    if (ip46_prefix_is_ip4(&(args.prefix), mp->pfx.address_length)) {
        if (mp->encap == LB_ENCAP_TYPE_GRE4)
            type = LB_VIP_TYPE_IP4_GRE4;
        else if (mp->encap == LB_ENCAP_TYPE_GRE6)
            type = LB_VIP_TYPE_IP4_GRE6;
        else if (mp->encap == LB_ENCAP_TYPE_L3DSR)
            type = LB_VIP_TYPE_IP4_L3DSR;
        else if (mp->encap == LB_ENCAP_TYPE_NAT4)
            type = LB_VIP_TYPE_IP4_NAT4;
    } else {
        if (mp->encap == LB_ENCAP_TYPE_GRE4)
            type = LB_VIP_TYPE_IP6_GRE4;
        else if (mp->encap == LB_ENCAP_TYPE_GRE6)
            type = LB_VIP_TYPE_IP6_GRE6;
        else if (mp->encap == LB_ENCAP_TYPE_NAT6)
            type = LB_VIP_TYPE_IP6_NAT6;
    }

    args.plen = mp->pfx.address_length;
    args.protocol = mp->protocol;
    args.port = ntohs(mp->port);
    args.type = type;
    args.new_length = ntohl(mp->new_flows_table_length);

    if (mp->encap == LB_ENCAP_TYPE_L3DSR) {
        args.encap_args.dscp = (u8)(mp->dscp & 0x3F);
      }
    else if ((mp->encap == LB_ENCAP_TYPE_NAT4)
            ||(mp->encap == LB_ENCAP_TYPE_NAT6)) {
        args.encap_args.srv_type = mp->type;
        args.encap_args.target_port = ntohs(mp->target_port);
      }

    rv = lb_vip_add(args, &vip_index);
  }
 REPLY_MACRO (VL_API_LB_ADD_DEL_VIP_REPLY);
}

static void *vl_api_lb_add_del_vip_t_print
(vl_api_lb_add_del_vip_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: lb_add_del_vip ");
  s = format (s, "%U/%d", format_vl_api_address,
       &mp->pfx.address, mp->pfx.address_length);

  s = format (s, "%s ", (mp->encap == LB_ENCAP_TYPE_GRE4)? "gre4"
              : (mp->encap == LB_ENCAP_TYPE_GRE6)? "gre6"
              : (mp->encap == LB_ENCAP_TYPE_NAT4)? "nat4"
              : (mp->encap == LB_ENCAP_TYPE_NAT6)? "nat6"
              : "l3dsr");

  if (mp->encap==LB_ENCAP_TYPE_L3DSR)
    {
      s = format (s, "dscp %u ", mp->dscp);
    }

  if ((mp->encap==LB_ENCAP_TYPE_NAT4)
      || (mp->encap==LB_ENCAP_TYPE_NAT6))
    {
      s = format (s, "type %u ", mp->type);
      s = format (s, "port %u ", mp->port);
      s = format (s, "target_port %u ", mp->target_port);
    }

  s = format (s, "%u ", mp->new_flows_table_length);
  s = format (s, "%s ", mp->is_del?"del":"add");
  FINISH;
}

static void
vl_api_lb_add_del_as_t_handler
(vl_api_lb_add_del_as_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_conf_reply_t * rmp;
  int rv = 0;
  u32 vip_index;
  ip46_address_t vip_ip_prefix;

  clib_memcpy(&vip_ip_prefix.ip6, mp->pfx.address.un.ip6,
              sizeof(vip_ip_prefix.ip6));


  ip46_address_t as_address;

  memcpy(&as_address.ip6, mp->as_address,
         sizeof(as_address.ip6));

  if ((rv = lb_vip_find_index(&vip_ip_prefix, mp->pfx.address_length,
                              mp->protocol, ntohs(mp->port), &vip_index)))
    goto done;

  if (mp->is_del)
    rv = lb_vip_del_ass(vip_index, &as_address, 1, mp->is_flush);
  else
    rv = lb_vip_add_ass(vip_index, &as_address, 1);

done:
 REPLY_MACRO (VL_API_LB_ADD_DEL_AS_REPLY);
}

static void *vl_api_lb_add_del_as_t_print
(vl_api_lb_add_del_as_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: lb_add_del_as ");
  s = format (s, "%U/%d", format_vl_api_address,
       &mp->pfx.address, mp->pfx.address_length);
  s = format (s, "%U ", format_ip46_address,
                (ip46_address_t *)mp->as_address, IP46_TYPE_ANY);
  s = format (s, "%s ", mp->is_del?"del":"add");
  FINISH;
}

static void
vl_api_lb_vip_dump_t_handler
(vl_api_lb_vip_dump_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_vip_details_t * rmp;
  int msg_size = 0;
  lb_vip_t *vip = 0;
  int rv = 0;
  u32 vip_count = 0;
  int vip_index = 0;

  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vip_count = pool_len(lbm->vips);
  msg_size = sizeof (*rmp) + sizeof (rmp->vips[0]) * vip_count;
  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
      htons (VL_API_LB_VIP_DETAILS + lbm->msg_id_base);
  rmp->context = mp->context;
  rmp->retval = htonl(rv);

  /* constrcut as stats under this vip */
  rmp->vip_count = htonl(vip_count);
  pool_foreach(vip, lbm->vips, {
      memcpy(rmp->vips[vip_index].pfx.address.un.ip6, vip->prefix.as_u8, sizeof(vip->prefix));
      rmp->vips[vip_index].pfx.address_length = vip->plen;
      rmp->vips[vip_index].protocol = vip->protocol;
      rmp->vips[vip_index].port = htons(vip->port);
      vip_index++;
  });

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void *vl_api_lb_vip_dump_t_print
(vl_api_lb_vip_dump_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: lb_vip_dump ");

  FINISH;
}

static void send_lb_as_details
  (lb_vip_t * vip, vl_api_registration_t * reg, u32 context)
{
  vl_api_lb_as_details_t *rmp;
  lb_main_t *lbm = &lb_main;
  int msg_size = 0;
  u32 as_count = 0;
  u32 *as_index;
  u32 asindex = 0;
  int rv = 0;

  as_count = pool_len(vip->as_indexes);

  msg_size = sizeof (*rmp) + sizeof (rmp->ass[0]) * as_count;
  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    htons (VL_API_LB_AS_DETAILS + lbm->msg_id_base);
  rmp->context = context;

  /* construct as list under this vip */
  lb_as_t *as;
  rmp->as_count = htonl(as_count);
  pool_foreach(as_index, vip->as_indexes, {
      as = &lbm->ass[*as_index];
      memcpy(rmp->ass[asindex].pfx.address.un.ip6, &(as->address.as_u8), sizeof(as->address));
      rmp->ass[asindex].pfx.address_length = 128;

      asindex++;
  });

  rmp->retval = htonl(rv);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_lb_as_dump_t_handler
(vl_api_lb_as_dump_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_as_details_t * rmp;
  u32 vip_index;
  lb_vip_t *vip = 0;
  int rv = 0;
  ip46_address_t prefix;

  clib_memcpy(&prefix.ip6, mp->pfx.address.un.ip6, sizeof(mp->pfx.address.un.ip6));

  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if ((prefix.ip6.as_u64[0] == ~0) && (prefix.ip6.as_u64[1] == ~0))
    {
      /* *INDENT-OFF* */
      pool_foreach(vip, lbm->vips,
      ({
        send_lb_as_details(vip, reg, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* dump all ASs for specific VIP */
      rv = lb_vip_find_index(&prefix, mp->pfx.address_length,
                             mp->protocol, ntohs(mp->port), &vip_index);
      if (rv)
        {
          /* *INDENT-OFF* */
          REPLY_MACRO2(VL_API_LB_AS_DETAILS,
          ({
            rmp->retval = htonl(rv);
          }));
          /* *INDENT-ON* */

          return;
        }

      vip = &lbm->vips[vip_index];
      send_lb_as_details (vip, reg, mp->context);
    }
}

static void *vl_api_lb_as_dump_t_print
(vl_api_lb_as_dump_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: lb_as_dump ");

  FINISH;
}

static void
vl_api_lb_flush_vip_t_handler
(vl_api_lb_flush_vip_t * mp)
{
  lb_main_t *lbm = &lb_main;
  int rv = 0;
  ip46_address_t vip_prefix;
  u8 vip_plen;
  u32 vip_index;
  vl_api_lb_flush_vip_reply_t * rmp;

  if (mp->port == 0)
    {
      mp->protocol = ~0;
    }

  memcpy (&(vip_prefix.ip6), mp->pfx.address.un.ip6, sizeof(vip_prefix.ip6));

  vip_plen = mp->pfx.address_length;

  rv = lb_vip_find_index(&vip_prefix, vip_plen, mp->protocol,
                         ntohs(mp->port), &vip_index);

  rv = lb_flush_vip_as(vip_index, ~0);

 REPLY_MACRO (VL_API_LB_FLUSH_VIP_REPLY);
}

static void *vl_api_lb_flush_vip_t_print
(vl_api_lb_flush_vip_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: lb_add_del_vip ");
  s = format (s, "%U/%d", format_vl_api_address,
       &mp->pfx.address, mp->pfx.address_length);
  s = format (s, "protocol %u ", mp->protocol);
  s = format (s, "port %u ", mp->port);

  FINISH;
}

/* List of message types that this plugin understands */
#define foreach_lb_plugin_api_msg            \
_(LB_CONF, lb_conf)                          \
_(LB_ADD_DEL_VIP, lb_add_del_vip)            \
_(LB_ADD_DEL_AS, lb_add_del_as)              \
_(LB_VIP_DUMP, lb_vip_dump)                  \
_(LB_AS_DUMP, lb_as_dump)                    \
_(LB_FLUSH_VIP, lb_flush_vip)

static clib_error_t * lb_api_init (vlib_main_t * vm)
{
  lb_main_t *lbm = &lb_main;
  u8 *name = format (0, "lb_%08x%c", api_version, 0);
  lbm->msg_id_base = vl_msg_api_get_msg_ids
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + lbm->msg_id_base),     \
                           #n,                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_lb_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (lbm, &api_main);

  vec_free (name);

  return 0;
}

VLIB_INIT_FUNCTION (lb_api_init);
