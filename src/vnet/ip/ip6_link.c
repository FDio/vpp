/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vnet/ip/ip6_link.h>
#include <vnet/ip/ip6_ll_table.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/adj/adj_mcast.h>

typedef struct ip6_link_delegate_t_
{
  u32 ild_sw_if_index;
  ip6_link_delegate_id_t ild_type;
  index_t ild_index;
} ip6_link_delegate_t;

const static ip6_link_delegate_t ip6_link_delegate_uninit = {
  .ild_sw_if_index = ~0,
};

typedef struct ip6_link_t_
{
  /** interface ip6 is enabled on */
  u32 il_sw_if_index;

  /** link-local address - if unset that IP6 is disabled*/
  ip6_address_t il_ll_addr;

  /** list of delegates */
  ip6_link_delegate_t *il_delegates;

  /** multicast adjacency for this link */
  adj_index_t il_mcast_adj;

  /** number of references to IP6 enabled on this link */
  u32 il_locks;
} ip6_link_t;

#define FOREACH_IP6_LINK_DELEGATE(_ild, _il, body)      \
{                                                       \
 if (NULL != _il) {                                     \
   vec_foreach (_ild, _il->il_delegates) {              \
     if (ip6_link_delegate_is_init(_ild))               \
       body;                                            \
   }                                                    \
 }                                                      \
}

#define FOREACH_IP6_LINK_DELEGATE_ID(_id) \
  for (_id = 0; _id < il_delegate_id; _id++)

/** last used delegate ID */
static ip6_link_delegate_id_t il_delegate_id;

/** VFT registered per-delegate type */
static ip6_link_delegate_vft_t *il_delegate_vfts;

/** Per interface configs */
static ip6_link_t *ip6_links;

/** Randomizer */
static u64 il_randomizer;

/** Logging */
static vlib_log_class_t ip6_link_logger;

#define IP6_LINK_DBG(...)                       \
    vlib_log_debug (ip6_link_logger, __VA_ARGS__);

#define IP6_LINK_INFO(...)                              \
    vlib_log_notice (ip6_link_logger, __VA_ARGS__);

static bool
ip6_link_delegate_is_init (const ip6_link_delegate_t * ild)
{
  return (~0 != ild->ild_sw_if_index);
}

static bool
ip6_link_is_enabled_i (const ip6_link_t * il)
{
  return (!ip6_address_is_zero (&il->il_ll_addr));
}

static void
ip6_link_local_address_from_mac (ip6_address_t * ip, const u8 * mac)
{
  ip->as_u64[0] = clib_host_to_net_u64 (0xFE80000000000000ULL);
  /* Invert the "u" bit */
  ip->as_u8[8] = mac[0] ^ (1 << 1);
  ip->as_u8[9] = mac[1];
  ip->as_u8[10] = mac[2];
  ip->as_u8[11] = 0xFF;
  ip->as_u8[12] = 0xFE;
  ip->as_u8[13] = mac[3];
  ip->as_u8[14] = mac[4];
  ip->as_u8[15] = mac[5];
}

static void
ip6_mac_address_from_link_local (u8 * mac, const ip6_address_t * ip)
{
  /* Invert the previously inverted "u" bit */
  mac[0] = ip->as_u8[8] ^ (1 << 1);
  mac[1] = ip->as_u8[9];
  mac[2] = ip->as_u8[10];
  mac[3] = ip->as_u8[13];
  mac[4] = ip->as_u8[14];
  mac[5] = ip->as_u8[15];
}

static ip6_link_t *
ip6_link_get (u32 sw_if_index)
{
  ip6_link_t *il;

  if (sw_if_index >= vec_len (ip6_links))
    return (NULL);

  il = &ip6_links[sw_if_index];

  if (!ip6_link_is_enabled_i (il))
    return (NULL);

  return (il);
}

bool
ip6_link_is_enabled (u32 sw_if_index)
{
  return (NULL != ip6_link_get (sw_if_index));
}


int
ip6_link_enable (u32 sw_if_index, const ip6_address_t * link_local_addr)
{
  ip6_link_t *il;
  int rv;

  il = ip6_link_get (sw_if_index);

  if (NULL == il)
    {
      const vnet_sw_interface_t *sw, *sw_sup;
      const ethernet_interface_t *eth;
      vnet_main_t *vnm;

      vnm = vnet_get_main ();

      IP6_LINK_INFO ("enable: %U",
		     format_vnet_sw_if_index_name, vnm, sw_if_index);

      sw_sup = vnet_get_sup_sw_interface (vnm, sw_if_index);
      if (sw_sup->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	{
	  rv = VNET_API_ERROR_UNSUPPORTED;
	  goto out;
	}

      eth = ethernet_get_interface (&ethernet_main, sw_sup->hw_if_index);

      if (NULL == eth)
	{
	  rv = VNET_API_ERROR_UNSUPPORTED;
	  goto out;
	}

      vec_validate (ip6_links, sw_if_index);

      il = &ip6_links[sw_if_index];
      il->il_locks = 0;
      il->il_sw_if_index = sw_if_index;

      sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

      if (NULL != link_local_addr)
	ip6_address_copy (&il->il_ll_addr, link_local_addr);
      else if (sw->type == VNET_SW_INTERFACE_TYPE_SUB ||
	       sw->type == VNET_SW_INTERFACE_TYPE_PIPE ||
	       sw->type == VNET_SW_INTERFACE_TYPE_P2P)
	{
	  il->il_ll_addr.as_u64[0] =
	    clib_host_to_net_u64 (0xFE80000000000000ULL);

	  /* make up an interface id */
	  il->il_ll_addr.as_u64[1] = random_u64 (&il_randomizer);

	  /* clear u bit */
	  il->il_ll_addr.as_u8[8] &= 0xfd;
	}
      else
	{
	  ip6_link_local_address_from_mac (&il->il_ll_addr,
					   eth->address.mac.bytes);
	}

      {
	ip6_ll_prefix_t ilp = {
	  .ilp_addr = il->il_ll_addr,
	  .ilp_sw_if_index = sw_if_index,
	};

	ip6_ll_table_entry_update (&ilp, FIB_ROUTE_PATH_LOCAL);
      }

      /* essentially "enables" ipv6 on this interface */
      ip6_mfib_interface_enable_disable (sw_if_index, 1);
      ip6_sw_interface_enable_disable (sw_if_index, 1);

      il->il_mcast_adj = adj_mcast_add_or_lock (FIB_PROTOCOL_IP6,
						VNET_LINK_IP6, sw_if_index);

      /* inform all register clients */
      ip6_link_delegate_id_t id;
      FOREACH_IP6_LINK_DELEGATE_ID (id)
      {
	if (NULL != il_delegate_vfts[id].ildv_enable)
	  il_delegate_vfts[id].ildv_enable (il->il_sw_if_index);
      }

      rv = 0;
    }
  else
    {
      rv = VNET_API_ERROR_VALUE_EXIST;
    }

  il->il_locks++;

out:
  return (rv);
}

static void
ip6_link_delegate_flush (ip6_link_t * il)
{
  ip6_link_delegate_t *ild;

  /* *INDENT-OFF* */
  FOREACH_IP6_LINK_DELEGATE (ild, il,
  ({
    il_delegate_vfts[ild->ild_type].ildv_disable(ild->ild_index);
  }));
  /* *INDENT-ON* */

  vec_free (il->il_delegates);
  il->il_delegates = NULL;
}

static void
ip6_link_last_lock_gone (ip6_link_t * il)
{
  ip6_ll_prefix_t ilp = {
    .ilp_addr = il->il_ll_addr,
    .ilp_sw_if_index = il->il_sw_if_index,
  };

  IP6_LINK_INFO ("last-lock: %U",
		 format_vnet_sw_if_index_name,
		 vnet_get_main (), il->il_sw_if_index);

  ip6_link_delegate_flush (il);
  ip6_ll_table_entry_delete (&ilp);

  ip6_mfib_interface_enable_disable (il->il_sw_if_index, 0);
  ip6_sw_interface_enable_disable (il->il_sw_if_index, 0);

  ip6_address_set_zero (&il->il_ll_addr);
  adj_unlock (il->il_mcast_adj);
  il->il_mcast_adj = ADJ_INDEX_INVALID;
}

static void
ip6_link_unlock (ip6_link_t * il)
{
  if (NULL == il)
    return;

  il->il_locks--;

  if (0 == il->il_locks)
    ip6_link_last_lock_gone (il);
}

int
ip6_link_disable (u32 sw_if_index)
{
  ip6_link_t *il;

  il = ip6_link_get (sw_if_index);

  if (NULL == il)
    return (VNET_API_ERROR_IP6_NOT_ENABLED);

  IP6_LINK_INFO ("disable: %U",
		 format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);

  ip6_link_unlock (il);

  return (0);
}

const ip6_address_t *
ip6_get_link_local_address (u32 sw_if_index)
{
  const ip6_link_t *il;

  vec_validate (ip6_links, sw_if_index);

  il = &ip6_links[sw_if_index];

  return (&il->il_ll_addr);
}

adj_index_t
ip6_link_get_mcast_adj (u32 sw_if_index)
{
  const ip6_link_t *il;

  il = &ip6_links[sw_if_index];

  return (il->il_mcast_adj);
}

int
ip6_link_set_local_address (u32 sw_if_index, const ip6_address_t * address)
{
  ip6_link_delegate_t *ild;
  ip6_link_t *il;

  il = ip6_link_get (sw_if_index);

  if (NULL == il)
    return ip6_link_enable (sw_if_index, address);

  ip6_ll_prefix_t ilp = {
    .ilp_addr = il->il_ll_addr,
    .ilp_sw_if_index = sw_if_index,
  };

  IP6_LINK_INFO ("set-ll: %U -> %U",
		 format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index,
		 format_ip6_address, address);

  ip6_ll_table_entry_delete (&ilp);
  ip6_address_copy (&il->il_ll_addr, address);
  ip6_address_copy (&ilp.ilp_addr, address);
  ip6_ll_table_entry_update (&ilp, FIB_ROUTE_PATH_LOCAL);

  /* *INDENT-OFF* */
  FOREACH_IP6_LINK_DELEGATE (ild, il,
  ({
    if (NULL != il_delegate_vfts[ild->ild_type].ildv_ll_change)
      il_delegate_vfts[ild->ild_type].ildv_ll_change(ild->ild_index,
                                                     &il->il_ll_addr);
  }));
  /* *INDENT-ON* */

  return (0);
}

ip6_link_delegate_id_t
ip6_link_delegate_register (const ip6_link_delegate_vft_t * vft)
{
  ip6_link_delegate_id_t rc = il_delegate_id++;

  ASSERT (vft->ildv_disable);

  vec_validate (il_delegate_vfts, rc);

  il_delegate_vfts[rc] = *vft;

  return (rc);
}

index_t
ip6_link_delegate_get (u32 sw_if_index, ip6_link_delegate_id_t id)
{
  ip6_link_t *il;

  il = ip6_link_get (sw_if_index);

  if (NULL == il)
    return (INDEX_INVALID);

  vec_validate_init_empty (il->il_delegates, id, ip6_link_delegate_uninit);

  if (!ip6_link_delegate_is_init (&il->il_delegates[id]))
    return (INDEX_INVALID);

  return (il->il_delegates[id].ild_index);
}

bool
ip6_link_delegate_update (u32 sw_if_index,
			  ip6_link_delegate_id_t id, index_t ii)
{
  ip6_link_t *il;

  il = ip6_link_get (sw_if_index);

  if (NULL == il)
    return (false);

  vec_validate_init_empty (il->il_delegates, id, ip6_link_delegate_uninit);

  il->il_delegates[id].ild_sw_if_index = sw_if_index;
  il->il_delegates[id].ild_type = id;
  il->il_delegates[id].ild_index = ii;

  return (true);
}

void
ip6_link_delegate_remove (u32 sw_if_index,
			  ip6_link_delegate_id_t id, index_t ii)
{
  ip6_link_t *il;

  il = ip6_link_get (sw_if_index);

  if (NULL != il)
    {
      if (vec_len (il->il_delegates) > id)
	{
	  clib_memcpy (&il->il_delegates[id],
		       &ip6_link_delegate_uninit,
		       sizeof (il->il_delegates[0]));
	}
    }
}

static void
ip6_link_add_del_address (ip6_main_t * im,
			  uword opaque,
			  u32 sw_if_index,
			  ip6_address_t * address,
			  u32 address_length,
			  u32 if_address_index, u32 is_delete)
{
  const ip6_link_delegate_t *ild;
  ip6_link_t *il;

  if (ip6_address_is_link_local_unicast (address))
    // only interested in global addresses here
    return;

  IP6_LINK_INFO ("addr-%s: %U -> %U",
		 (is_delete ? "del" : "add"),
		 format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index,
		 format_ip6_address, address);

  il = ip6_link_get (sw_if_index);

  if (NULL == il)
    return;

  /* *INDENT-OFF* */
  FOREACH_IP6_LINK_DELEGATE (ild, il,
  ({
      if (is_delete)
        {
          if (NULL != il_delegate_vfts[ild->ild_type].ildv_addr_del)
            il_delegate_vfts[ild->ild_type].ildv_addr_del(ild->ild_index,
                                                          address, address_length);
        }
      else
        {
          if (NULL != il_delegate_vfts[ild->ild_type].ildv_addr_add)
            il_delegate_vfts[ild->ild_type].ildv_addr_add(ild->ild_index,
                                                          address, address_length);
        }
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
ip6_link_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  if (!is_add)
    {
      ip6_link_t *il;

      il = ip6_link_get (sw_if_index);

      IP6_LINK_DBG ("link-del: %U",
		    format_vnet_sw_if_index_name, vnet_get_main (),
		    sw_if_index);

      if (NULL != il)
	/* force cleanup */
	ip6_link_last_lock_gone (il);
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ip6_link_interface_add_del);

static clib_error_t *
ip6_link_init (vlib_main_t * vm)
{
  il_randomizer = clib_cpu_time_now ();
  ip6_link_logger = vlib_log_register_class ("ip6", "link");

  {
    ip6_add_del_interface_address_callback_t cb = {
      .function = ip6_link_add_del_address,
    };
    vec_add1 (ip6_main.add_del_interface_address_callbacks, cb);
  }
  return (NULL);
}

VLIB_INIT_FUNCTION (ip6_link_init);


static clib_error_t *
test_ip6_link_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 mac[6];
  ip6_address_t _a, *a = &_a;

  if (unformat (input, "%U", unformat_ethernet_address, mac))
    {
      ip6_link_local_address_from_mac (a, mac);
      vlib_cli_output (vm, "Link local address: %U", format_ip6_address, a);
      ip6_mac_address_from_link_local (mac, a);
      vlib_cli_output (vm, "Original MAC address: %U",
		       format_ethernet_address, mac);
    }

  return 0;
}

/*?
 * This command converts the given MAC Address into an IPv6 link-local
 * address.
 *
 * @cliexpar
 * Example of how to create an IPv6 link-local address:
 * @cliexstart{test ip6 link 16:d9:e0:91:79:86}
 * Link local address: fe80::14d9:e0ff:fe91:7986
 * Original MAC address: 16:d9:e0:91:79:86
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_link_command, static) =
{
  .path = "test ip6 link",
  .function = test_ip6_link_command_fn,
  .short_help = "test ip6 link <mac-address>",
};
/* *INDENT-ON* */

static u8 *
ip6_print_addrs (u8 * s, u32 * addrs)
{
  ip_lookup_main_t *lm = &ip6_main.lookup_main;
  u32 i;

  for (i = 0; i < vec_len (addrs); i++)
    {
      ip_interface_address_t *a =
	pool_elt_at_index (lm->if_address_pool, addrs[i]);
      ip6_address_t *address = ip_interface_address_get_address (lm, a);

      s = format (s, "%U%U/%d\n",
		  format_white_space, 4,
		  format_ip6_address, address, a->address_length);
    }

  return (s);
}

static u8 *
format_ip6_link (u8 * s, va_list * arg)
{
  const ip6_link_t *il = va_arg (*arg, ip6_link_t *);
  ip_lookup_main_t *lm = &ip6_main.lookup_main;
  vnet_main_t *vnm = vnet_get_main ();

  if (!ip6_link_is_enabled_i (il))
    return (s);

  s = format (s, "%U is admin %s\n",
	      format_vnet_sw_interface_name, vnm,
	      vnet_get_sw_interface (vnm, il->il_sw_if_index),
	      (vnet_sw_interface_is_admin_up (vnm, il->il_sw_if_index) ?
	       "up" : "down"));

  u32 ai;
  u32 *link_scope = 0, *global_scope = 0;
  u32 *local_scope = 0, *unknown_scope = 0;
  ip_interface_address_t *a;
  const ip6_link_delegate_t *ild;

  vec_validate_init_empty (lm->if_address_pool_index_by_sw_if_index,
			   il->il_sw_if_index, ~0);
  ai = lm->if_address_pool_index_by_sw_if_index[il->il_sw_if_index];

  while (ai != (u32) ~ 0)
    {
      a = pool_elt_at_index (lm->if_address_pool, ai);
      ip6_address_t *address = ip_interface_address_get_address (lm, a);

      if (ip6_address_is_link_local_unicast (address))
	vec_add1 (link_scope, ai);
      else if (ip6_address_is_global_unicast (address))
	vec_add1 (global_scope, ai);
      else if (ip6_address_is_local_unicast (address))
	vec_add1 (local_scope, ai);
      else
	vec_add1 (unknown_scope, ai);

      ai = a->next_this_sw_interface;
    }

  if (vec_len (link_scope))
    {
      s = format (s, "%ULink-local address(es):\n", format_white_space, 2);
      s = ip6_print_addrs (s, link_scope);
      vec_free (link_scope);
    }

  if (vec_len (local_scope))
    {
      s = format (s, "%ULocal unicast address(es):\n", format_white_space, 2);
      s = ip6_print_addrs (s, local_scope);
      vec_free (local_scope);
    }

  if (vec_len (global_scope))
    {
      s = format (s, "%UGlobal unicast address(es):\n",
		  format_white_space, 2);
      s = ip6_print_addrs (s, global_scope);
      vec_free (global_scope);
    }

  if (vec_len (unknown_scope))
    {
      s = format (s, "%UOther-scope address(es):\n", format_white_space, 2);
      s = ip6_print_addrs (s, unknown_scope);
      vec_free (unknown_scope);
    }

  s = format (s, "%ULink-local address(es):\n", format_white_space, 2);
  s = format (s, "%U%U\n",
	      format_white_space, 4, format_ip6_address, &il->il_ll_addr);

  /* *INDENT-OFF* */
  FOREACH_IP6_LINK_DELEGATE(ild, il,
  ({
    s = format (s, "%U", il_delegate_vfts[ild->ild_type].ildv_format,
                     ild->ild_index, 2);
  }));
  /* *INDENT-ON* */

  return (s);
}

static clib_error_t *
ip6_link_show (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  const ip6_link_t *il;
  vnet_main_t *vnm;
  u32 sw_if_index;

  vnm = vnet_get_main ();
  sw_if_index = ~0;

  if (unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      il = ip6_link_get (sw_if_index);

      if (NULL == il)
	{
	  vlib_cli_output (vm, "IP6 disabled");
	  return (NULL);
	}
      else
	vlib_cli_output (vm, "%U", format_ip6_link, il);
    }
  else
    {
      vec_foreach (il, ip6_links)
	vlib_cli_output (vm, "%U", format_ip6_link, il);
    }

  return (NULL);
}

/*?
 * This command is used to display various IPv6 attributes on a given
 * interface.
 *
 * @cliexpar
 * Example of how to display IPv6 settings:
 * @cliexstart{show ip6 interface GigabitEthernet2/0/0}
 * GigabitEthernet2/0/0 is admin up
 *         Link-local address(es):
 *                 fe80::ab8/64
 *         Joined group address(es):
 *                 ff02::1
 *                 ff02::2
 *                 ff02::16
 *                 ff02::1:ff00:ab8
 *         Advertised Prefixes:
 *                 prefix fe80::fe:28ff:fe9c:75b3,  length 64
 *         MTU is 1500
 *         ICMP error messages are unlimited
 *         ICMP redirects are disabled
 *         ICMP unreachables are not sent
 *         ND DAD is disabled
 *         ND advertised reachable time is 0
 *         ND advertised retransmit interval is 0 (msec)
 *         ND router advertisements are sent every 200 seconds (min interval is 150)
 *         ND router advertisements live for 600 seconds
 *         Hosts use stateless autoconfig for addresses
 *         ND router advertisements sent 19336
 *         ND router solicitations received 0
 *         ND router solicitations dropped 0
 * @cliexend
 * Example of output if IPv6 is not enabled on the interface:
 * @cliexstart{show ip6 interface GigabitEthernet2/0/0}
 * show ip6 interface: IPv6 not enabled on interface
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_link_show_command, static) =
{
  .path = "show ip6 interface",
  .function = ip6_link_show,
  .short_help = "show ip6 interface <interface>",
};
/* *INDENT-ON* */

static clib_error_t *
enable_ip6_interface_cmd (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  u32 sw_if_index;

  sw_if_index = ~0;

  if (unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      if (ip6_link_enable (sw_if_index, NULL))
	error = clib_error_return (0, "Failed\n");
    }
  else
    {
      error = clib_error_return (0, "unknown interface\n'",
				 format_unformat_error, input);

    }
  return error;
}

/*?
 * This command is used to enable IPv6 on a given interface.
 *
 * @cliexpar
 * Example of how enable IPv6 on a given interface:
 * @cliexcmd{enable ip6 interface GigabitEthernet2/0/0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (enable_ip6_interface_command, static) =
{
  .path = "enable ip6 interface",
  .function = enable_ip6_interface_cmd,
  .short_help = "enable ip6 interface <interface>",
};
/* *INDENT-ON* */

static clib_error_t *
disable_ip6_interface_cmd (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  u32 sw_if_index;

  sw_if_index = ~0;

  if (unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      if (ip6_link_disable (sw_if_index))
	error = clib_error_return (0, "Failed\n");
    }
  else
    {
      error = clib_error_return (0, "unknown interface\n'",
				 format_unformat_error, input);

    }
  return error;
}

/*?
 * This command is used to disable IPv6 on a given interface.
 *
 * @cliexpar
 * Example of how disable IPv6 on a given interface:
 * @cliexcmd{disable ip6 interface GigabitEthernet2/0/0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (disable_ip6_interface_command, static) =
{
  .path = "disable ip6 interface",
  .function = disable_ip6_interface_cmd,
  .short_help = "disable ip6 interface <interface>",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
