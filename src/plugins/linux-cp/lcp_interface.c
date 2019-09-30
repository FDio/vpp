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

#include <ctype.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <plugins/linux-cp/lcp_interface.h>

#include <vnet/plugin/plugin.h>
#include <vnet/plugin/plugin.h>

#include <vnet/ip/ip_punt_drop.h>
#include <vnet/fib/fib_table.h>
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vnet/devices/tap/tap.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/netlink.h>
#include <vlibapi/api_helper_macros.h>


static vlib_log_class_t lcp_itf_pair_logger;

/**
 * Pool of LIP objects
 */
static lcp_itf_pair_t *lip_pool;

/**
 * DBs of interface-pair objects:
 *  - key'd by VIF (linux ID)
 *  - key'd by VPP's physical interface
 *  - number of shared uses of VPP's tap/host interface
 */
static uword *lip_db_by_vif;
index_t *lip_db_by_phy;
static u32 *lip_db_by_host;

#define LCP_ITF_PAIR_DBG(...)                             \
  vlib_log_notice (lcp_itf_pair_logger, __VA_ARGS__);

#define LCP_ITF_PAIR_INFO(...)                            \
  vlib_log_notice (lcp_itf_pair_logger, __VA_ARGS__);


u8 *
format_lcp_itf_pair (u8 *s, va_list *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  lcp_itf_pair_t *lip = va_arg (*args, lcp_itf_pair_t *);
  vnet_sw_interface_t *swif_phy;
  vnet_sw_interface_t *swif_host;

  s = format (s, "itf-pair: [%d]", lip - lip_pool);

  swif_phy = vnet_get_sw_interface_or_null (vnm, lip->lip_phy_sw_if_index);
  if (!swif_phy)
    s = format (s, " <no-phy-if>");
  else
    s = format (s, " %U", format_vnet_sw_interface_name, vnm, swif_phy);

  swif_host = vnet_get_sw_interface_or_null (vnm, lip->lip_host_sw_if_index);
  if (!swif_host)
    s = format (s, " <no-host-if>");
  else
    s = format (s, " %U", format_vnet_sw_interface_name, vnm, swif_host);

  s = format (s, " %s %d", lip->lip_host_name, lip->lip_vif_index);

  if (lip->lip_namespace[0])
    s = format (s, " netns %s", lip->lip_namespace);

  return s;
}


static walk_rc_t
lcp_itf_pair_walk_show_cb(index_t api, void *ctx)
{
  vlib_main_t *vm;
  lcp_itf_pair_t *lip;

  lip = lcp_itf_pair_get (api);
  if (!lip)
    return WALK_STOP;

  vm = vlib_get_main ();
  vlib_cli_output (vm, "%U\n", format_lcp_itf_pair, lip);

  return WALK_CONTINUE;
}


void
lcp_itf_pair_show (u32 phy_sw_if_index)
{
  vlib_main_t *vm;
  u8 *ns;
  index_t api;

  vm = vlib_get_main ();
  ns = lcp_get_default_ns ();
  vlib_cli_output(vm,
		  "lcp default netns '%s'\n",
		  ns ? (char *) ns : "<unset>");

  if (phy_sw_if_index == ~0)
    {
      lcp_itf_pair_walk (lcp_itf_pair_walk_show_cb, 0);
    }
  else
    {
      api = lcp_itf_pair_find_by_phy (phy_sw_if_index);
      lcp_itf_pair_walk_show_cb(api, 0);
    }
}


lcp_itf_pair_t *
lcp_itf_pair_get (u32 index)
{
  return pool_elt_at_index (lip_pool, index);
}

index_t
lcp_itf_pair_find_by_vif (u32 vif_index)
{
  uword *p;

  p = hash_get (lip_db_by_vif, vif_index);

  if (p)
    return p[0];

  return INDEX_INVALID;
}

int
lcp_itf_pair_add_sub (u32 vif,
		      u32 sub_sw_if_index,
		      u32 phy_sw_if_index,
		      u8 *ns)
{
  lcp_itf_pair_t *lip;

  lip = lcp_itf_pair_get (lcp_itf_pair_find_by_phy (phy_sw_if_index));

  return lcp_itf_pair_add (lip->lip_host_sw_if_index,
			   sub_sw_if_index, lip->lip_host_name, vif, ns);
}

int
lcp_itf_pair_add (u32 host_sw_if_index,
		  u32 phy_sw_if_index,
		  u8 * host_name,
		  u32 host_index,
		  u8 *ns)
{
  index_t lipi;
  lcp_itf_pair_t *lip;

  lipi = lcp_itf_pair_find_by_phy (phy_sw_if_index);

  LCP_ITF_PAIR_INFO ("add: host:%U phy:%U, tap:%v vif:%d",
		     format_vnet_sw_if_index_name, vnet_get_main (),
		     host_sw_if_index, format_vnet_sw_if_index_name,
		     vnet_get_main (), phy_sw_if_index, host_name,
		     host_index);


  if (lipi != INDEX_INVALID)
    return VNET_API_ERROR_VALUE_EXIST;

  fib_route_path_t *rpaths = NULL;

  /* create a new pair */
  pool_get (lip_pool, lip);

  lipi = lip - lip_pool;

  vec_validate_init_empty (lip_db_by_phy, phy_sw_if_index, INDEX_INVALID);
  lip_db_by_phy[phy_sw_if_index] = lipi;
  hash_set (lip_db_by_vif, host_index, lipi);

  lip->lip_host_sw_if_index = host_sw_if_index;
  lip->lip_phy_sw_if_index = phy_sw_if_index;
  lip->lip_host_name = vec_dup (host_name);
  lip->lip_vif_index = host_index;
  clib_strncpy((char *) lip->lip_host_name, (char *) ns, IFNAMSIZ);

  if (lip->lip_host_sw_if_index == ~0)
    return 0;

  /*
   * configure passive punt to the host interface
   */
  vec_validate_init_empty (lip_db_by_host, lip->lip_host_sw_if_index, 0);

  if (0 == lip_db_by_host[lip->lip_host_sw_if_index]++)
    {
      /* first use of this host interface
       * enable the x-connect feature on the host to send
       * all packets to the phy
       */
      vnet_feature_enable_disable ("device-input",
				   "linux-cp-xc",
				   lip->lip_host_sw_if_index,
				   1, &lipi, sizeof (lipi));
    }

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

  return 0;
}

int
lcp_itf_pair_delete (u32 phy_sw_if_index)
{
  u32 lipi;

  lipi = lcp_itf_pair_find_by_phy (phy_sw_if_index);

  if (lipi == INDEX_INVALID)
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  lcp_itf_pair_t *lip;

  lip = lcp_itf_pair_get (lipi);

  if (~0 != lip->lip_host_sw_if_index &&
      (0 == --lip_db_by_host[lip->lip_host_sw_if_index]))
    {
      /* last shared usage of the host interface */
      vnet_feature_enable_disable ("device-input",
				   "linux-cp-xc",
				   lip->lip_host_sw_if_index,
				   0, &lipi, sizeof (lipi));
    }

  ip4_punt_redirect_del (lip->lip_phy_sw_if_index);
  ip6_punt_redirect_del (lip->lip_phy_sw_if_index);

  /* ip4_sw_interface_enable_disable (lip->lip_phy_sw_if_index, 0); */

  /* /\* *INDENT-OFF* *\/ */
  /* fib_prefix_t pfx = { */
  /*   .fp_addr = { */
  /*     .ip4 = { */
  /*       .as_u32 = 0xffffffff, */
  /*     } */
  /*   }, */
  /*   .fp_proto = FIB_PROTOCOL_IP4, */
  /*   .fp_len = 32, */
  /* }; */
  /* /\* *INDENT-ON* *\/ */
  /* fib_table_entry_delete */
  /*   (fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, */
  /*                                      lip->lip_phy_sw_if_index), */
  /*    &pfx, FIB_SOURCE_PLUGIN_LOW); */

  lip_db_by_phy[phy_sw_if_index] = INDEX_INVALID;
  pool_put (lip_pool, lip);

  return 0;
}

void
lcp_itf_pair_walk (lcp_itf_pair_walk_cb_t cb, void *ctx)
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

typedef struct lcp_itf_pair_names_t_
{
  u8 *lip_host_name;
  u8 *lip_phy_name;
  u8 *lip_namespace;
  u32 lip_phy_sw_if_index;
} lcp_itf_pair_names_t;

static lcp_itf_pair_names_t *lip_names;


static clib_error_t *
lcp_itf_pair_config (vlib_main_t * vm, unformat_input_t * input)
{
  u8 *host, *phy;
  u8 *ns;
  u8 *default_ns;

  host = phy = ns = default_ns = NULL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vec_reset_length (host);

      if (unformat (input, "pair %s %s %s", &phy, &host, &ns))
	{
	  lcp_itf_pair_names_t *lipn;

	  if (vec_len (ns) > IFNAMSIZ)
	    {
	      return clib_error_return (0,
					"linux-cp IF namespace must"
					" be less than %d characters",
					IFNAMSIZ);
	    }

	  vec_add2 (lip_names, lipn, 1);

	  lipn->lip_host_name = vec_dup (host);
	  lipn->lip_phy_name = vec_dup (phy);
	  lipn->lip_namespace = vec_dup (ns);
	}
      else if (unformat (input, "pair %v %v", &phy, &host))
	{
	  lcp_itf_pair_names_t *lipn;

	  vec_add2 (lip_names, lipn, 1);

	  lipn->lip_host_name = vec_dup (host);
	  lipn->lip_phy_name = vec_dup (phy);
	  lipn->lip_namespace = 0;
	}
      else if (unformat (input, "default netns %v", &default_ns))
	{
	  vec_add1 (default_ns, 0);
	  if (lcp_set_default_ns (default_ns) < 0)
	    {
	      return clib_error_return (0,
					"linux-cp default namespace must"
					" be less than %d characters",
					IFNAMSIZ);
	    }
	}
      else
	return clib_error_return (0, "interfaces not found");
    }

  vec_free (host);
  vec_free (phy);
  vec_free (default_ns);

  return NULL;
}

VLIB_EARLY_CONFIG_FUNCTION (lcp_itf_pair_config, "linux-cp");

/*
 * Returns 1 if the tap name is valid.
 * Returns 0 if the tap name is invalid.
 */
static int
lcp_validate_tap_name (u8 *name)
{
  int len;
  char *p;

  p = (char *) name;
  len = clib_strnlen (p, IFNAMSIZ);
  if (len >= IFNAMSIZ)
    return 0;

  for ( ; *p; ++p) {
    if (isalnum (*p))
      continue;

    switch (*p) {
    case '-':
    case '_':
    case '%':
    case '@':
    case ':':
    case '.':
      continue;
    }

    return 0;
  }

  return 1;
}


int
lcp_itf_pair_create(u32 phy_sw_if_index, u8 *host_tap_name, u8 *ns)
{
  vlib_main_t *vm;
  vnet_main_t *vnm;
  vnet_hw_interface_t *hw;
  ethernet_interface_t *ei;

  if (!vnet_sw_if_index_is_api_valid (phy_sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (!lcp_validate_tap_name (host_tap_name))
    return VNET_API_ERROR_INVALID_ARGUMENT;

  vnm = vnet_get_main ();
  hw = vnet_get_sup_hw_interface (vnm, phy_sw_if_index);
  ei = pool_elt_at_index (ethernet_main.interfaces, hw->hw_instance);

  tap_create_if_args_t args = {
    .num_rx_queues = clib_max (1, vlib_num_workers ()),
    .id = hw->hw_if_index,
    .sw_if_index = ~0,
    .rx_ring_sz = 256,
    .tx_ring_sz = 256,
    .host_if_name = host_tap_name,
    .host_namespace = 0,
  };

  memcpy (args.host_mac_addr.bytes, ei->address, sizeof (args.host_mac_addr));

  /*
   * Use interface-specific netns if supplied.
   * Otherwise, use default netns if defined.
   * Otherwise ignore a netns and use the OS default.
   */
  if (ns == 0 || ns[0] == 0)
    ns = lcp_get_default_ns ();
  if (ns && ns[0] != 0)
    args.host_namespace = ns;

  vm = vlib_get_main ();
  tap_create_if (vm, &args);

  if (args.rv < 0)
    {
      return args.rv;
    }

  hw = vnet_get_sup_hw_interface (vnm, args.sw_if_index);

  /*
   * Set the interface down on the host side.
   * This controls whether the host can RX/TX.
   */
  virtio_main_t *mm = &virtio_main;
  virtio_if_t *vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

  vnet_netlink_set_link_state (vif->ifindex, 0 /* down */ );

  /*
   * Leave the TAP permanently up on the VPP side.
   * This TAP will be shared by many sub-interface.
   * Therefore we can't use it to manage admin state.
   */
  vnet_sw_interface_admin_up (vnm, args.sw_if_index);

  lcp_itf_pair_add (args.sw_if_index,
		    phy_sw_if_index,
		    host_tap_name, vif->ifindex, ns);

  return 0;
}


static uword
lcp_itf_pair_process (vlib_main_t * vm,
		      vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  uword *event_data = 0;
  uword *lipn_index;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      vlib_process_get_events (vm, &event_data);

      vec_foreach (lipn_index, event_data)
      {
	lcp_itf_pair_names_t *lipn;

	lipn = &lip_names[*lipn_index];
	lcp_itf_pair_create(lipn->lip_phy_sw_if_index,
			    lipn->lip_host_name,
			    lipn->lip_namespace);
      }

      vec_reset_length (event_data);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (lcp_itf_pair_process_node, static) =
{
  .function = lcp_itf_pair_process,
  .name = "linux-cp-itf-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};
/* *INDENT-ON* */

static clib_error_t *
lcp_itf_phy_add (vnet_main_t * vnm, u32 sw_if_index, u32 is_create)
{
  lcp_itf_pair_names_t *lipn;
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw;

  if (!is_create || vnet_sw_interface_is_sub (vnm, sw_if_index))
    return NULL;

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);

  vec_foreach (lipn, lip_names)
  {
    if (!vec_cmp (hw->name, lipn->lip_phy_name))
      {
	lipn->lip_phy_sw_if_index = sw_if_index;

	vlib_process_signal_event (vm,
				   lcp_itf_pair_process_node.index,
				   0, lipn - lip_names);
	break;
      }
  }

  return NULL;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (lcp_itf_phy_add);

static clib_error_t *
lcp_itf_pair_init (vlib_main_t * vm)
{
  /* punt all unknown ports */
  udp_punt_unknown (vm, 0, 1);
  udp_punt_unknown (vm, 1, 1);
  tcp_punt_unknown (vm, 0, 1);
  tcp_punt_unknown (vm, 1, 1);

  ethernet_register_input_type (vm, ETHERNET_TYPE_ARP,
				lcp_ethernet_node.index);

  lcp_itf_pair_logger = vlib_log_register_class ("linux-cp", "itf");

  return NULL;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (lcp_itf_pair_init) =
{
  .runs_after = VLIB_INITS ("vnet_interface_init", "tcp_init", "udp_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
