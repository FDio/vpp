/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 *------------------------------------------------------------------
 * srv6_gtp.c - SRv6 LocalSID doing SRv6->GTP translation
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <srv6-gtp/srv6_gtp.h>
#include <vpp/app/version.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

unsigned char srv6_localsid_name[32] = "SRv6 to GTP";
unsigned char keyword_str[32] = "end.gtp";
unsigned char def_str[64] = "This SRv6 localSID maps SRv6 traffic into a GTP tunnel";
unsigned char params_str[32] = "sa <ipv4 sa> da <ipv4 da>";
u8 prefix_length = 96;  //4B will be Arguments. Size used in FIB entry

/*****************************************/
/* SRv6 LocalSID instantiation and removal functions */
static int
srv6_localsid_creation_fn (ip6_sr_localsid_t *localsid)
{
  /* 
   * Do you want to do anything fancy upon localsid instantiation?
   * You can do it here
   * (If return != 0 the localsid creation will be cancelled.)
   */
  /* As an example Im going to do a +1 to the fib table inserted by the user */
  srv6_gtp_per_sid_memory_t *ls_mem = (void*)localsid->plugin_mem;
  //Prepare rewrite string

  vec_validate_aligned (ls_mem->rewrite, sizeof(ip4_gtpu_header_t)-1, CLIB_CACHE_LINE_BYTES);

  ip4_gtpu_header_t *hdr = (void *)ls_mem->rewrite;
  ip4_header_t *ip = &hdr->ip4;
  udp_header_t *udp = &hdr->udp;
  gtpu_header_t *gtpu = &hdr->gtpu;

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address = ls_mem->src_addr;
  ip->dst_address = ls_mem->dst_addr;
  ip->checksum = ip4_header_checksum (ip);

  udp->src_port = clib_host_to_net_u16 (2152);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_GTPU);

  gtpu->ver_flags = GTPU_V1_VER | GTPU_PT_GTP;
  gtpu->type = GTPU_TYPE_GTPU;
  return 0;
}

static int
srv6_localsid_removal_fn (ip6_sr_localsid_t *localsid)
{
  /* Do you want to do anything fancy upon localsid removal?
   * You can do it here
   * (If return != 0 the localsid removal will be cancelled.)
   */
  /* 
   * BTW if you stored something in localsid->plugin_mem you should clean it now
   */
  clib_mem_free(((srv6_gtp_per_sid_memory_t *)localsid->plugin_mem)->rewrite);
  //In this example we are only cleaning the memory allocated per localsid
  clib_mem_free(localsid->plugin_mem);
  return 0;
}

/**********************************/
/* SRv6 LocalSID format functions */
/*
 * Prints nicely the parameters of a localsid
 * Example: print "Table 5"
 */
u8 *
format_srv6_gtp (u8 * s, va_list * args)
{
  srv6_gtp_per_sid_memory_t *ls_mem = va_arg (*args, void *);
  s = format (s, "IPv4 SA: %U\n", format_ip4_address, &ls_mem->src_addr);
  s = format (s, "IPv4 DA: %U", format_ip4_address, &ls_mem->dst_addr);
  return s;
}

/*
 * Process the parameters of a localsid
 * Example: process from:
 * sr localsid address cafe::1 behavior new_srv6_localsid 5
 * everything from behavior on... so in this case 'new_srv6_localsid 5'
 * Notice that it MUST match the keyword_str and params_str defined above.
 */
//"sa <ipv4 sa> da <ipv4 da> teid <TEID>";
uword
unformat_srv6_gtp (unformat_input_t * input, va_list * args)
{
  void **plugin_mem = va_arg (*args, void **);
  srv6_gtp_per_sid_memory_t *ls_mem;
  ip4_address_t sa, da;
  char sa_set, da_set;
  sa_set = da_set = 0;

  if (!unformat (input, "end.gtp"))
    return 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
  { 
    if (!sa_set && unformat (input, "src %U", unformat_ip4_address, &sa))
      sa_set = 1;

    if (!da_set && unformat (input, "dst %U", unformat_ip4_address, &da))
      da_set = 1;
    else
      break;
  }

  if(sa_set && da_set)
  {
    /* Allocate a portion of memory */
    ls_mem = clib_mem_alloc_aligned_at_offset (sizeof(srv6_gtp_per_sid_memory_t), 0, 0, 1);

    /* Set to zero the memory */
    memset (ls_mem, 0, sizeof(srv6_gtp_per_sid_memory_t));

    /* Our brand-new car is ready */
    ls_mem->src_addr = sa;
    ls_mem->dst_addr = da;

    /* Dont forget to add it to the localsid */
    *plugin_mem = ls_mem;
    return 1;
  }
  return 0;
}

/*************************/
/* SRv6 LocalSID FIB DPO */
static u8 *
format_srv6_gtp_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: srv6-to-gtp:[%u]", index));
}

void
srv6_gtp_dpo_lock (dpo_id_t * dpo)
{
}

void
srv6_gtp_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t srv6_gtp_vft = {
  .dv_lock = srv6_gtp_dpo_lock,
  .dv_unlock = srv6_gtp_dpo_unlock,
  .dv_format = format_srv6_gtp_dpo,
};

const static char *const srv6_gtp_ip6_nodes[] = {
  "srv6-gtp",
  NULL,
};

const static char *const *const srv6_gtp_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_gtp_ip6_nodes,
};

/**********************/
static clib_error_t * srv6_gtp_init (vlib_main_t * vm)
{
  srv6_gtp_main_t * sm = &srv6_gtp_main;
  int rv = 0;
  /* Create DPO */
  sm->srv6_gtp_dpo_type = dpo_register_new_type (
    &srv6_gtp_vft, srv6_gtp_nodes);

  /* Register SRv6 LocalSID */
  rv = sr_localsid_register_function (vm, 
                                  srv6_localsid_name,
                                  keyword_str,
                                  def_str,
                                  params_str,
                                  prefix_length,
                                  &sm->srv6_gtp_dpo_type,
                                  format_srv6_gtp, 
                                  unformat_srv6_gtp, 
                                  srv6_localsid_creation_fn, 
                                  srv6_localsid_removal_fn);
  if (rv < 0)
    clib_error_return (0, "SRv6 LocalSID function could not be registered.");
  else
    sm->srv6_localsid_behavior_id = rv;

  return 0;
}

VLIB_INIT_FUNCTION (srv6_gtp_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "SRv6-to-GTP",
};
