/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <plugins/linux-intf-pair/lip.h>

#include <vnet/plugin/plugin.h>

#include <vnet/ip/ip_punt_drop.h>
#include <vnet/fib/fib_table.h>
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>

/**
 * Pool of LIP objects
 */
static lip_t *lip_pool;

/**
 * DB of LIP policy objects, key Host sw_if_index
 */
static index_t *lip_db;

lip_t *
lip_get (u32 index)
{
  return (pool_elt_at_index (lip_pool, index));
}

static lip_t *
lip_find_i (u32 host_sw_if_index)
{
  u32 api;

  api = lip_find (host_sw_if_index);

  if (INDEX_INVALID != api)
    return (lip_get (api));

  return (NULL);
}

index_t
lip_find (u32 host_sw_if_index)
{
  if (vec_len (lip_db) <= host_sw_if_index)
    return (INDEX_INVALID);

  return lip_db[host_sw_if_index];
}


int
lip_add (u32 host_sw_if_index, u32 phy_sw_if_index)
{
  lip_t *lip;
  u32 lipi;
  int rv;

  lipi = lip_find (host_sw_if_index);

  if (INDEX_INVALID == lipi)
    {
      fib_route_path_t *rpaths = NULL;
      vlib_main_t *vm;

      vm = vlib_get_main ();
      rv = 0;

      /* create a new pair */
      pool_get (lip_pool, lip);

      lipi = lip - lip_pool;

      vec_validate_init_empty (lip_db, host_sw_if_index, INDEX_INVALID);
      lip_db[host_sw_if_index] = lipi;

      lip->lip_host_sw_if_index = host_sw_if_index;
      lip->lip_phy_sw_if_index = phy_sw_if_index;

      /*
       * configure passive punt to the host interface
       */
      {
        /* *INDENT-OFF* */
        fib_route_path_t rpath = {
          .frp_flags = FIB_ROUTE_PATH_DVR,
          .frp_proto = DPO_PROTO_IP4,
          .frp_sw_if_index = lip->lip_host_sw_if_index,
          .frp_weight = 1,
          .frp_fib_index = ~0,
        };
        /* *INDENT-ON* */

	vec_add1 (rpaths, rpath);

	ip4_punt_redirect_add_paths (lip->lip_phy_sw_if_index, rpaths);

	rpaths[0].frp_proto = DPO_PROTO_IP6;

	ip6_punt_redirect_add_paths (lip->lip_phy_sw_if_index, rpaths);

	vec_reset_length (rpaths);

	/* punt all unknown ports */
	udp_punt_unknown (vm, 0, 1);
	udp_punt_unknown (vm, 1, 1);
	tcp_punt_unknown (vm, 0, 1);
	tcp_punt_unknown (vm, 1, 1);
      }

      /*
       * IP enable the physical interface and
       * set the all ones address to punt, so DHCP packets are punted
       */
      {
        /* *INDENT-OFF* */
        fib_route_path_t rpath = {
          .frp_flags = FIB_ROUTE_PATH_LOCAL,
          .frp_proto = DPO_PROTO_IP4,
          .frp_sw_if_index = lip->lip_phy_sw_if_index,
          .frp_weight = 1,
          .frp_fib_index = ~0,
        };
        fib_prefix_t pfx = {
          .fp_addr = {
            .ip4 = {
              .as_u32 = 0xffffffff,
            }
          },
          .fp_proto = FIB_PROTOCOL_IP4,
          .fp_len = 32,
        };
        /* *INDENT-ON* */

	vec_add1 (rpaths, rpath);

	fib_table_entry_path_add2
	  (fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						lip->lip_phy_sw_if_index),
	   &pfx, FIB_SOURCE_PLUGIN_LOW, FIB_ENTRY_FLAG_LOCAL, rpaths);

	ip4_sw_interface_enable_disable (lip->lip_phy_sw_if_index, 1);
	vec_free (rpaths);
      }

      /* enable the x-connect feature on the host to send
       * all packets to the phy */
      vnet_feature_enable_disable ("device-input",
				   "linux-itf-pairing-xc",
				   lip->lip_host_sw_if_index,
				   1, &lipi, sizeof (lipi));

      /* enable ARP duplication feature on the phy */
      vnet_feature_enable_disable ("arp", "linux-itf-pairing-arp",
				   lip->lip_phy_sw_if_index,
				   1, &lipi, sizeof (lipi));

      /* enable the detection of DHCP packets from the trash */
      vnet_feature_enable_disable ("ip4-drop", "ip4-drop-dhcp-client-detect",
				   0, 1, NULL, 0);
    }
  else
    {
      rv = VNET_API_ERROR_VALUE_EXIST;
    }

  return (rv);
}

int
lip_delete (u32 host_sw_if_index)
{
  u32 lipi;
  int rv;

  lipi = lip_find (host_sw_if_index);

  if (INDEX_INVALID == lipi)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }
  else
    {
      vlib_main_t *vm;
      lip_t *lip;

      vm = vlib_get_main ();

      lip = lip_get (lipi);

      vnet_feature_enable_disable ("device-input",
				   "linux-itf-pairing-xc",
				   lip->lip_host_sw_if_index,
				   0, &lipi, sizeof (lipi));
      vnet_feature_enable_disable ("arp",
				   "linux-itf-pairing-arp",
				   lip->lip_phy_sw_if_index,
				   0, &lipi, sizeof (lipi));
      vnet_feature_enable_disable ("ip4-drop", "ip4-drop-dhcp-client-detect",
				   0, 0, NULL, 0);

      ip4_punt_redirect_del (lip->lip_phy_sw_if_index);
      ip6_punt_redirect_del (lip->lip_phy_sw_if_index);
      udp_punt_unknown (vm, 0, 0);
      udp_punt_unknown (vm, 1, 0);
      tcp_punt_unknown (vm, 0, 0);
      tcp_punt_unknown (vm, 1, 0);
      ip4_sw_interface_enable_disable (lip->lip_phy_sw_if_index, 0);

      /* *INDENT-OFF* */
      fib_prefix_t pfx = {
        .fp_addr = {
          .ip4 = {
            .as_u32 = 0xffffffff,
          }
        },
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_len = 32,
      };
      /* *INDENT-ON* */
      fib_table_entry_delete
	(fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
					      lip->lip_phy_sw_if_index),
	 &pfx, FIB_SOURCE_PLUGIN_LOW);

      lip_db[host_sw_if_index] = INDEX_INVALID;
      pool_put (lip_pool, lip);

      rv = 0;
    }

  return (rv);
}

static clib_error_t *
lip_cmd (vlib_main_t * vm,
	 unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 host_sw_if_index, phy_sw_if_index;
  vnet_main_t *vnm = vnet_get_main ();
  u32 is_del;
  int rv = 0;

  is_del = 0;
  host_sw_if_index = phy_sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "host %U",
		    unformat_vnet_sw_interface, vnm, &host_sw_if_index))
	;
      else if (unformat (line_input, "phy %U",
			 unformat_vnet_sw_interface, vnm, &phy_sw_if_index))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input));
    }

  if (~0 == host_sw_if_index || ~0 == phy_sw_if_index)
    {
      vlib_cli_output (vm, "Specify a host and phy interface to pair");
      return 0;
    }

  if (!is_del)
    {
      rv = lip_add (host_sw_if_index, phy_sw_if_index);
    }
  else
    {
      rv = lip_delete (host_sw_if_index);
    }

  if (rv)
    vlib_cli_output (vm, "Failed: %d", rv);

  unformat_free (line_input);
  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Create an LIP policy.
 */
VLIB_CLI_COMMAND (lip_cmd_node, static) = {
  .path = "lip",
  .function = lip_cmd,
  .short_help = "lip [add|del] host <INTERFACE> phy <INTERFACE>",
};
/* *INDENT-ON* */

static u8 *
format_lip (u8 * s, va_list * args)
{
  lip_t *lip = va_arg (*args, lip_t *);
  vnet_main_t *vnm = vnet_get_main ();

  s = format (s, "lip:[%d]: %U <-> %U",
	      lip - lip_pool,
	      format_vnet_sw_if_index_name, vnm,
	      lip->lip_host_sw_if_index, format_vnet_sw_if_index_name,
	      vnm, lip->lip_phy_sw_if_index);

  return (s);
}

void
lip_walk (lip_walk_cb_t cb, void *ctx)
{
  u32 api;

  /* *INDENT-OFF* */
  pool_foreach_index(api, lip_pool,
  ({
    if (!cb(api, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
lip_show_cmd (vlib_main_t * vm,
	      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 host_sw_if_index;
  lip_t *ap;

  host_sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "host %U",
		    unformat_vnet_sw_interface, vnm, &host_sw_if_index))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (~0 == host_sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach(ap, lip_pool,
      ({
        vlib_cli_output(vm, "%U", format_lip, ap);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      ap = lip_find_i (host_sw_if_index);

      if (NULL != ap)
	vlib_cli_output (vm, "%U", format_lip, ap);
      else
	vlib_cli_output (vm, "Invalid Interface");
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lip_show_cmd_node, static) = {
  .path = "show lip",
  .function = lip_show_cmd,
  .short_help = "show lip <INTERFACE>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
lip_init (vlib_main_t * vm)
{
  return (NULL);
}

VLIB_INIT_FUNCTION (lip_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
