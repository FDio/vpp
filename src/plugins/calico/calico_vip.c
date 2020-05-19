/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <calico/calico_vip.h>
#include <vnet/fib/fib_table.h>

typedef struct calico_vip_db_t_
{
  /* TX VIPs */
  uword *ctd_vip;
} calico_vip_db_t;

calico_vip_t *calico_vip_pool;
dpo_type_t calico_vip_dpo;

calico_vip_db_t calico_vip_db;

static calico_vip_t *
calico_vip_find (const ip_address_t * ip)
{
  uword *p;

  p = hash_get_mem (calico_vip_db.ctd_vip, ip);

  if (p)
    return (pool_elt_at_index (calico_vip_pool, p[0]));

  return (NULL);
}

static void
calico_vip_db_add (const ip_address_t * ip, index_t cvipi)
{
  hash_set_mem_alloc (&calico_vip_db.ctd_vip, ip, cvipi);
}

static void
calico_vip_db_remove (const ip_address_t * ip)
{
  hash_unset_mem_free (&calico_vip_db.ctd_vip, ip);
}

void
calico_vip_add_translation (index_t cvipi,
			    u16 port, ip_protocol_t proto, index_t cti)
{
  calico_vip_t *cvip;
  u32 key;

  cvip = calico_vip_get (cvipi);

  key = proto;
  key = (key << 16) | port;

  hash_set (cvip->cvip_translations, key, cti);
}

void
calico_vip_remove_translation (index_t cvipi, u16 port, ip_protocol_t proto)
{
  calico_vip_t *cvip;
  u32 key;

  cvip = calico_vip_get (cvipi);

  key = proto;
  key = (key << 16) | port;

  hash_unset (cvip->cvip_translations, key);


  if (0 == hash_elts (cvip->cvip_translations))
    {
      calico_vip_db_remove (&cvip->cvip_ip);
      fib_table_entry_delete_index (cvip->cvip_fei, calico_fib_source);
      dpo_reset (&cvip->cvip_dpo);

      hash_free (cvip->cvip_translations);
      pool_put (calico_vip_pool, cvip);
    }
}

index_t
calico_vip_add (const ip_address_t * ip)
{
  calico_vip_t *cvip;
  fib_prefix_t pfx;
  index_t cvipi;

  /* do we know of this ep's vip */
  cvip = calico_vip_find (ip);

  if (NULL == cvip)
    {
      pool_get_zero (calico_vip_pool, cvip);
      cvipi = cvip - calico_vip_pool;

      ip_address_copy (&cvip->cvip_ip, ip);

      calico_vip_db_add (&cvip->cvip_ip, cvipi);

      ip_address_to_fib_prefix (&cvip->cvip_ip, &pfx);
      dpo_set (&cvip->cvip_dpo, calico_vip_dpo,
	       fib_proto_to_dpo (pfx.fp_proto), cvipi);

      cvip->cvip_fei = fib_table_entry_special_dpo_add
	(CALICO_FIB_TABLE,
	 &pfx,
	 calico_fib_source,
	 (FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT |
	  FIB_ENTRY_FLAG_EXCLUSIVE), &cvip->cvip_dpo);
    }

  cvipi = cvip - calico_vip_pool;

  return (cvipi);
}

u8 *
format_calico_vip (u8 * s, va_list * args)
{
  index_t cvipi = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  calico_vip_t *cvip = pool_elt_at_index (calico_vip_pool, cvipi);

  s = format (s, "[%d] calico-vip:[%U]", cvipi,
	      format_ip_address, &cvip->cvip_ip);

  return (s);
}

static u8 *
format_calico_vip_verbose (u8 * s, va_list * args)
{
  index_t cvipi = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  index_t cti;
  u32 key;

  calico_vip_t *cvip = pool_elt_at_index (calico_vip_pool, cvipi);

  s = format (s, "[%d] calico-vip:[%U]", cvipi,
	      format_ip_address, &cvip->cvip_ip);

  /* *INDENT-OFF* */
  hash_foreach(key, cti, cvip->cvip_translations,
  ({
    s = format (s, "\n%U%U", format_white_space, indent + 2,
                format_calico_translation, cti, indent + 4);
  }));
  /* *INDENT-ON* */

  return (s);
}

static clib_error_t *
calico_vip_show (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t cvi;

  cvi = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &cvi))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (INDEX_INVALID == cvi)
    {
      ip_address_t *ip;

      /* *INDENT-OFF* */
      hash_foreach(ip, cvi, calico_vip_db.ctd_vip,
      ({
        vlib_cli_output(vm, "%U", format_calico_vip_verbose, cvi, 0);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      vlib_cli_output (vm, "Invalid policy ID:%d", cvi);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_vip_show_cmd_node, static) = {
  .path = "show calico vip",
  .function = calico_vip_show,
  .short_help = "show calico vip <VIP>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

const static char *const calico_vip_dpo_ip4_nodes[] = {
  "ip4-calico-tx",
  NULL,
};

const static char *const calico_vip_dpo_ip6_nodes[] = {
  "ip6-calico-tx",
  NULL,
};

const static char *const *const calico_vip_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = calico_vip_dpo_ip4_nodes,
  [DPO_PROTO_IP6] = calico_vip_dpo_ip6_nodes,
};

static void
calico_vip_dpo_lock (dpo_id_t * dpo)
{
}

static void
calico_vip_dpo_unlock (dpo_id_t * dpo)
{
}

u8 *
format_calico_vip_dpo (u8 * s, va_list * ap)
{
  index_t cti = va_arg (*ap, index_t);
  u32 indent = va_arg (*ap, u32);

  s = format (s, "%U", format_calico_vip, cti, indent);

  return (s);
}

const static dpo_vft_t calico_vip_dpo_vft = {
  .dv_lock = calico_vip_dpo_lock,
  .dv_unlock = calico_vip_dpo_unlock,
  .dv_format = format_calico_vip_dpo,
};

static clib_error_t *
calico_vip_init (vlib_main_t * vm)
{
  calico_vip_dpo = dpo_register_new_type (&calico_vip_dpo_vft,
					  calico_vip_dpo_nodes);

  calico_vip_db.ctd_vip = hash_create_mem (0,
					   sizeof (ip_address_t),
					   sizeof (uword));
  return (NULL);
}

VLIB_INIT_FUNCTION (calico_vip_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
