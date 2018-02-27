/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/qos/qos_egress_map.h>
#include <vnet/qos/qos_mark.h>

/**
 * Pool from which to allocate table
 */
qos_egress_map_t *qem_pool;

/**
 * DB to map user table-IDs to internal table indicies.
 */
uword *qem_db;

/**
 * per-interface vector of which table is mapped to which interface
 */
index_t *qos_egress_map_configs[QOS_MARK_N_SOURCES];

static qos_egress_map_t *
qos_egress_map_find (qos_egress_map_id_t mid)
{
  qos_egress_map_t *qem;
  uword *p = NULL;

  qem = NULL;
  p = hash_get (qem_db, mid);

  if (NULL != p)
    {
      index_t qemi;

      qemi = p[0];
      qem = pool_elt_at_index (qem_pool, qemi);
    }

  return (qem);
}

static qos_egress_map_t *
qos_egress_map_find_or_create (qos_egress_map_id_t mid)
{
  qos_egress_map_t *qem;

  /*
   * Find the existing or create a new table
   */
  qem = qos_egress_map_find (mid);

  if (NULL == qem)
    {
      index_t qemi;

      pool_get_aligned (qem_pool, qem, CLIB_CACHE_LINE_BYTES);
      qemi = qem - qem_pool;

      memset (qem, 0, sizeof (*qem));
      hash_set (qem_db, mid, qemi);
    }

  return (qem);
}

void
qos_egress_map_update (qos_egress_map_id_t mid,
		       qos_mark_source_t input_source, qos_bits_t * values)
{
  qos_egress_map_t *qem;

  qem = qos_egress_map_find_or_create (mid);

  clib_memcpy (qem->qem_output[input_source],
	       values, sizeof (qem->qem_output[input_source]));
}

void
qos_egress_map_delete (qos_egress_map_id_t mid)
{
  qos_egress_map_t *qem;

  qem = qos_egress_map_find (mid);
  hash_unset (qem_db, mid);

  if (NULL != qem)
    {
      qos_mark_source_t src;
      index_t *ii, qemi;

      qemi = qem - qem_pool;

      /*
       * check and clear any interface mappings
       */
      FOR_EACH_QOS_MARK_SOURCE (src)
      {
	vec_foreach (ii, qos_egress_map_configs[src])
	{
	  if (*ii == qemi)
	    *ii = INDEX_INVALID;
	}
      }

      pool_put (qem_pool, qem);
    }
}

static void
qos_egress_map_feature_config (u32 sw_if_index,
			       qos_mark_source_t qs, u8 enable)
{
  switch (qs)
    {
    case QOS_MARK_SOURCE_EXT:
      ASSERT (0);
      break;
    case QOS_MARK_SOURCE_VLAN:
      qos_mark_vlan_enable_disable (sw_if_index, enable);
      break;
    case QOS_MARK_SOURCE_MPLS:
      qos_mark_mpls_enable_disable (sw_if_index, enable);
      break;
    case QOS_MARK_SOURCE_IP:
      qos_mark_ip_enable_disable (sw_if_index, enable);
      break;
    }
}

int
qos_egress_map_interface_update (u32 sw_if_index,
				 qos_mark_source_t output_source,
				 qos_egress_map_id_t mid)
{
  uword *p;

  vec_validate_init_empty (qos_egress_map_configs[output_source],
			   sw_if_index, ~0);

  p = hash_get (qem_db, mid);

  if (NULL != p)
    {
      if (INDEX_INVALID == qos_egress_map_configs[output_source][sw_if_index])
	{
	  qos_egress_map_feature_config (sw_if_index, output_source, 1);
	}

      qos_egress_map_configs[output_source][sw_if_index] = p[0];

      return (0);
    }
  else if (~0 == mid)
    {
      if (INDEX_INVALID != qos_egress_map_configs[output_source][sw_if_index])
	{
	  qos_egress_map_feature_config (sw_if_index, output_source, 0);
	}

      qos_egress_map_configs[output_source][sw_if_index] = ~0;

      return (0);
    }

  return (VNET_API_ERROR_NO_SUCH_TABLE);
}

static clib_error_t *
qos_egress_map_interface_cli (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  qos_egress_map_id_t map_id;
  u32 sw_if_index, qs;
  vnet_main_t *vnm;
  int rv;

  vnm = vnet_get_main ();
  map_id = ~0;
  qs = 0xff;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "id %d", &map_id))
	;
      else if (unformat (input, "output %U", unformat_qos_mark_source, &qs))
	;
      else if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");
  if (0xff == qs)
    return clib_error_return (0, "output location must be specified");

  rv = qos_egress_map_interface_update (sw_if_index, qs, map_id);

  if (0 == rv)
    return (NULL);

  return clib_error_return (0, "Failed to map interface");
}

/*?
 * Apply a QoS egress mapping table to an interface for QoS marking packets
 * at the given output protocol.
 *
 * @cliexpar
 * @cliexcmd{qos egress interface GigEthernet0/9/0 id 0 output ip}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_egress_map_interface_command, static) = {
  .path = "qos egress interface",
  .short_help = "qos egress interface <INTERFACE> id <MAP> output <PROTO>",
  .function = qos_egress_map_interface_cli,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
qos_egress_map_update_cli (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  qos_egress_map_id_t map_id;
  qos_egress_map_t *qem;
  u8 add;

  add = 1;
  map_id = ~0;
  qem = NULL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "delete") || unformat (input, "del"))
	add = 0;
      else if (unformat (input, "id %d", &map_id))
	qem = qos_egress_map_find_or_create (map_id);
      else
	{
	  int qs, qi, qo;

	  if (NULL == qem)
	    return clib_error_return (0, "map-id must be specified");

	  while (unformat
		 (input, "[%U][%d]=%d", unformat_qos_mark_source, &qs, &qi,
		  &qo))
	    qem->qem_output[qs][qi] = qo;
	  break;
	}
    }

  if (!add)
    qos_egress_map_delete (map_id);

  return (NULL);
}

/*?
 * Update a Egress Qos Map table
 *
 * @cliexpar
 * @cliexcmd{qos egress map id 0 [ip][4]=4}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_egress_map_update_command, static) = {
  .path = "qos egress map",
  .short_help = "qos egress map id %d [delete] {[SOURCE][INPUT]=OUTPUT}",
  .function = qos_egress_map_update_cli,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

u8 *
format_qos_egress_map (u8 * s, va_list * args)
{
  qos_egress_map_t *qem = va_arg (args, qos_egress_map_t *);
  u32 indent = va_arg (args, u32);
  int qs;
  u32 ii;

  FOR_EACH_QOS_MARK_SOURCE (qs)
  {
    s = format (s, "%U%U:[",
		format_white_space, indent, format_qos_mark_source, qs);

    for (ii = 0; ii < ARRAY_LEN (qem->qem_output[qs]) - 1; ii++)
      {
	s = format (s, "%d,", qem->qem_output[qs][ii]);
      }
    s = format (s, "%d]\n", qem->qem_output[qs][ii]);
  }

  return (s);
}

static clib_error_t *
qos_egress_map_show (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  qos_egress_map_id_t map_id;
  qos_egress_map_t *qem;
  clib_error_t *error;

  map_id = ~0;
  qem = NULL;
  error = NULL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "id %d", &map_id))
	;
      else
	{
	  error = unformat_parse_error (input);
	  goto done;
	}
    }

  if (~0 == map_id)
    {
      index_t qemi;

      /* *INDENT-OFF* */
      hash_foreach(map_id, qemi, qem_db,
      ({
          vlib_cli_output (vm, " Map-ID:%d\n%U",
                           map_id,
                           format_qos_egress_map,
                           pool_elt_at_index(qem_pool, qemi), 2);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      qem = qos_egress_map_find (map_id);

      if (NULL == qem)
	{
	  error = clib_error_return (0, "No Map for ID %d", map_id);
	}
      else
	{
	  vlib_cli_output (vm, " Map-ID:%d\n%U",
			   map_id, format_qos_egress_map, qem, 2);
	}
    }

done:
  return (error);
}

/*?
 * Show Egress Qos Maps
 *
 * @cliexpar
 * @cliexcmd{show qos egress map}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_egress_map_show_command, static) = {
  .path = "show qos egress map",
  .short_help = "show qos egress map id %d",
  .function = qos_egress_map_show,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
