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
 * un.c - SRv6 Masquerading Proxy (AM) function
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/adj/adj.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <srv6-un/un.h>

unsigned char function_name[] = "SRv6-uN";
unsigned char keyword_str[] = "uN(32b+16b)";
unsigned char def_str[] = "SRv6 uSID uN";
unsigned char params_str[] = "";
u8 prefix_length = 48;

srv6_un_main_t srv6_un_main;

/*****************************************/
/* SRv6 LocalSID instantiation and removal functions */
static int
srv6_un_localsid_creation_fn (ip6_sr_localsid_t * localsid)
{
  srv6_un_localsid_t *ls_mem = localsid->plugin_mem;
  //Nothing to do here.
  ls_mem->shift = 16;
  return 0;
}

static int
srv6_un_localsid_removal_fn (ip6_sr_localsid_t * localsid)
{
  //Nothing to do here.

  /* Clean up local SID memory */
  clib_mem_free (localsid->plugin_mem);

  return 0;
}

/**********************************/
/* SRv6 LocalSID format functions */
/*
 * Prints nicely the parameters of a localsid
 * Example: print "Table 5"
 */
u8 *
format_srv6_un_localsid (u8 * s, va_list * args)
{
  srv6_un_localsid_t *ls_mem = va_arg (*args, void *);

  return (format (s, "Shift:\t\t%u", ls_mem->shift));
}

/*
 * Process the parameters of a localsid
 * Example: process from:
 * sr localsid address cafe::1 behavior new_srv6_localsid 5
 * everything from behavior on... so in this case 'new_srv6_localsid 5'
 * Notice that it MUST match the keyword_str and params_str defined above.
 */
uword
unformat_srv6_un_localsid (unformat_input_t * input, va_list * args)
{
  void **plugin_mem_p = va_arg (*args, void **);
  srv6_un_localsid_t *ls_mem;

  if (unformat (input, "uN(32b+16b)"))
    {
      /* Allocate a portion of memory */
      ls_mem = clib_mem_alloc_aligned_at_offset (sizeof *ls_mem, 0, 0, 1);

      /* Set to zero the memory */
      clib_memset (ls_mem, 0, sizeof *ls_mem);

      /* Dont forget to add it to the localsid */
      *plugin_mem_p = ls_mem;
      return 1;
    }
  return 0;
}

/*************************/
/* SRv6 LocalSID FIB DPO */
static u8 *
format_srv6_un_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  return (format (s, "SR: shift-and-forward 16b:[%u]", index));
}

void
srv6_un_dpo_lock (dpo_id_t * dpo)
{
}

void
srv6_un_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t srv6_un_vft = {
  .dv_lock = srv6_un_dpo_lock,
  .dv_unlock = srv6_un_dpo_unlock,
  .dv_format = format_srv6_un_dpo,
};

const static char *const srv6_un_ip6_nodes[] = {
  "srv6-un-localsid",
  NULL,
};

const static char *const *const srv6_un_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = srv6_un_ip6_nodes,
};

/**********************/
static clib_error_t *
srv6_un_init (vlib_main_t * vm)
{
  srv6_un_main_t *sm = &srv6_un_main;
  int rv = 0;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  /* Create DPO */
  sm->srv6_un16_dpo_type =
    dpo_register_new_type (&srv6_un_vft, srv6_un_nodes);

  /* Register SRv6 LocalSID */
  rv = sr_localsid_register_function (vm,
				      function_name,
				      keyword_str,
				      def_str,
				      params_str,
				      prefix_length,
				      &sm->srv6_un16_dpo_type,
				      format_srv6_un_localsid,
				      unformat_srv6_un_localsid,
				      srv6_un_localsid_creation_fn,
				      srv6_un_localsid_removal_fn);
  if (rv < 0)
    clib_error_return (0, "SRv6 LocalSID function could not be registered.");
  else
    sm->srv6_localsid_behavior_id = rv;

  return 0;
}


/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (srv6_un_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Segment Routing Shift And Forward uN 16b",
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
