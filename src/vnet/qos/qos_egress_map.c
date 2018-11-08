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

index_t
qos_egress_map_find (qos_egress_map_id_t mid)
{
  uword *p = NULL;

  p = hash_get (qem_db, mid);

  if (NULL != p)
    return p[0];

  return (INDEX_INVALID);
}

qos_egress_map_t *
qos_egress_map_find_i (qos_egress_map_id_t mid)
{
  index_t qemi;

  qemi = qos_egress_map_find (mid);

  if (INDEX_INVALID != qemi)
    {
      return (pool_elt_at_index (qem_pool, qemi));
    }

  return (NULL);
}

static qos_egress_map_t *
qos_egress_map_find_or_create (qos_egress_map_id_t mid)
{
  qos_egress_map_t *qem;

  /*
   * Find the existing or create a new table
   */
  qem = qos_egress_map_find_i (mid);

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
		       qos_source_t input_source, qos_bits_t * values)
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

  qem = qos_egress_map_find_i (mid);
  hash_unset (qem_db, mid);

  if (NULL != qem)
    {
      pool_put (qem_pool, qem);
    }
}

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
		 (input, "[%U][%d]=%d", unformat_qos_source, &qs, &qi, &qo))
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
  qos_egress_map_t *qem = va_arg (*args, qos_egress_map_t *);
  u32 indent = va_arg (*args, u32);
  int qs;
  u32 ii;

  FOR_EACH_QOS_SOURCE (qs)
  {
    s = format (s, "%U%U:[",
		format_white_space, indent, format_qos_source, qs);

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
      qem = qos_egress_map_find_i (map_id);

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
