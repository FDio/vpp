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

#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>

#include <linux-cp/lcp_nl.h>

#include <netlink/route/rule.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/addr.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/error.h>

#include <vnet/fib/fib_table.h>

#include <libmnl/libmnl.h>

#include <plugins/linux-cp/lcp_interface.h>


typedef enum nl_event_type_t_
{
  NL_EVENT_READ,
} nl_event_type_t;


typedef struct nl_main {

  struct nl_sock *sk_route;
  vlib_log_class_t nl_logger;
  nl_vft_t *nl_vfts;
  struct nl_cache *nl_caches[LCP_NL_N_OBJS];

  u32 rx_buf_size;
  u32 tx_buf_size;

} nl_main_t;

#define NL_RX_BUF_SIZE_DEF (1 << 25)  /* 64 MB */
#define NL_TX_BUF_SIZE_DEF (1 << 18)  /* 256 kB */

static nl_main_t nl_main =
{
  .rx_buf_size = NL_RX_BUF_SIZE_DEF,
  .tx_buf_size = NL_TX_BUF_SIZE_DEF,
};


/* #define foreach_nl_nft_proto  \ */
/*   _(IP4, "ip", AF_INT)  \ */
/*   _(IP6, "ip6", NFPROTO_IPV6) */

/* typedef enum nl_nft_proto_t_ */
/* { */
/* #define _(a,b,c) NL_NFT_PROTO_##a = c, */
/*   foreach_nl_nft_proto */
/* #undef _ */
/* } nl_nft_proto_t; */

#define FOREACH_VFT(__func, __arg)              \
  {                                             \
    nl_main_t *nm = &nl_main;			\
    nl_vft_t *__nv;                             \
    vec_foreach(__nv, nm->nl_vfts)              \
      {                                         \
        if (!__nv->__func.cb)                   \
          continue;                             \
                                                \
        if (!__nv->__func.is_mp_safe)           \
          vlib_worker_thread_barrier_sync (     \
                              vlib_get_main()); \
                                                \
        __nv->__func.cb(__arg);                 \
                                                \
        if (!__nv->__func.is_mp_safe)           \
          vlib_worker_thread_barrier_release (  \
                              vlib_get_main()); \
      }                                         \
    }

void
nl_register_vft (const nl_vft_t * nv)
{
  nl_main_t *nm = &nl_main;

  vec_add1 (nm->nl_vfts, *nv);
}

#define NL_DBG(...)   vlib_log_debug (nl_main.nl_logger, __VA_ARGS__);
#define NL_INFO(...)  vlib_log_notice (nl_main.nl_logger, __VA_ARGS__);
#define NL_ERROR(...) vlib_log_err (nl_main.nl_logger, __VA_ARGS__);

static void
nl_route_del (struct rtnl_route *rr, void *arg)
{
  FOREACH_VFT (nvl_rt_route_del, rr);
}

static void
nl_route_add (struct rtnl_route *rr, void *arg)
{
  FOREACH_VFT (nvl_rt_route_add, rr);
}

static void
nl_neigh_del (struct rtnl_neigh *rn, void *arg)
{
  FOREACH_VFT (nvl_rt_neigh_del, rn);
}

static void
nl_neigh_add (struct rtnl_neigh *rn, void *arg)
{
  FOREACH_VFT (nvl_rt_neigh_add, rn);
}

static void
nl_link_addr_del (struct rtnl_addr *rla, void *arg)
{
  FOREACH_VFT (nvl_rt_addr_del, rla);
}

static void
nl_link_addr_add (struct rtnl_addr *rla, void *arg)
{
  FOREACH_VFT (nvl_rt_addr_add, rla);
}

static void
nl_link_del (struct rtnl_link *rl, void *arg)
{
  FOREACH_VFT (nvl_rt_link_del, rl);
}

static void
nl_link_add (struct rtnl_link *rl, void *arg)
{
  FOREACH_VFT (nvl_rt_link_add, rl);
}

static void
nl_route_dispatch (struct nl_object *obj, void *arg)
{
  /* nothing can be done without interface mappings */
  if (!lcp_itf_num_pairs ())
    return;

  switch (nl_object_get_msgtype (obj))
    {
    case RTM_NEWROUTE:
      nl_route_add ((struct rtnl_route *) obj, arg);
      break;
    case RTM_DELROUTE:
      nl_route_del ((struct rtnl_route *) obj, arg);
      break;
    case RTM_NEWNEIGH:
      nl_neigh_add ((struct rtnl_neigh *) obj, arg);
      break;
    case RTM_DELNEIGH:
      nl_neigh_del ((struct rtnl_neigh *) obj, arg);
      break;
    case RTM_NEWADDR:
      nl_link_addr_add ((struct rtnl_addr *) obj, arg);
      break;
    case RTM_DELADDR:
      nl_link_addr_del ((struct rtnl_addr *) obj, arg);
      break;
    case RTM_NEWLINK:
      nl_link_add ((struct rtnl_link *) obj, arg);
      break;
    case RTM_DELLINK:
      nl_link_del ((struct rtnl_link *) obj, arg);
      break;
    default:
      NL_INFO ("unhandled: %s", nl_object_get_type (obj));
      break;
    }
}

static int
nl_route_cb (struct nl_msg *msg, void *arg)
{
  int err;

  if ((err = nl_msg_parse (msg, nl_route_dispatch, NULL)) < 0)
    NL_ERROR ("Unable to parse object: %s", nl_geterror (err));

  return 0;
}

static uword
nl_route_process (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  uword event_type;
  uword *event_data = 0;
  nl_main_t *nm = &nl_main;

  while (1)
    {
      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &event_data);

      if (event_type == ~0)
	{			//Clock event or no event

	}
      else
	{
	  uword *d;
	  vec_foreach (d, event_data)
	  {

	    switch (event_type)
	      {
	      case NL_EVENT_READ:
		{
		  int err;
		  if ((err = nl_recvmsgs_default (nm->sk_route)) < 0)
		    NL_ERROR ("recv: %s", nl_geterror (err));
		  break;
		}
	      }
	  }
	}

      vec_reset_length (event_data);
    }
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(nl_route_process_node, static) = {
  .function = nl_route_process,
  .name = "nl-route-process",
  .type = VLIB_NODE_TYPE_PROCESS,
};
/* *INDENT-ON* */

int
lcp_nl_drain_messages (void)
{
  int err;
  nl_main_t *nm = &nl_main;

  while ((err = nl_recvmsgs_default (nm->sk_route)) > -1)
    ;

  return err;
}

static clib_error_t *
nl_route_read_cb (struct clib_file *f)
{
  int err;
  err = lcp_nl_drain_messages ();
  if (err < 0 && err != -NLE_AGAIN)
    NL_ERROR ("netlink drain: %s (%d)", nl_geterror (err), err);

  return 0;
}

struct nl_cache *
lcp_nl_get_cache (lcp_nl_obj_t t)
{
  nl_main_t *nm = &nl_main;

  return nm->nl_caches[t];
}

/* Set the RX buffer size to be used on the netlink socket */
void
lcp_nl_set_buffer_size (u32 buf_size)
{
  nl_main_t *nm = &nl_main;

  nm->rx_buf_size = buf_size;

  if (nm->sk_route)
    nl_socket_set_buffer_size (nm->sk_route, nm->rx_buf_size,
			       nm->tx_buf_size);
}


#include <vnet/plugin/plugin.h>
clib_error_t *
lcp_nl_init (vlib_main_t * vm)
{
  int dest_ns_fd, curr_ns_fd;
  nl_main_t *nm = &nl_main;

  nm->nl_logger = vlib_log_register_class ("nl", "nl");

  /* Allocate a new socket for both routes and acls
   * Notifications do not use sequence numbers, disable sequence number
   * checking.
   * Define a callback function, which will be called for each notification
   * received
   */
  nm->sk_route = nl_socket_alloc ();
  nl_socket_disable_seq_check (nm->sk_route);

  dest_ns_fd = lcp_get_default_ns_fd ();
  if (dest_ns_fd)
    {
      curr_ns_fd = open ("/proc/self/ns/net", O_RDONLY);
      setns (dest_ns_fd, CLONE_NEWNET);
    }

  nl_connect (nm->sk_route, NETLINK_ROUTE);

  if (dest_ns_fd)
    {
      setns (curr_ns_fd, CLONE_NEWNET);
      close (curr_ns_fd);
    }


  /* Subscribe to all the 'routing' notifications on the route socket */
  nl_socket_add_memberships (nm->sk_route,
			     RTNLGRP_LINK,
			     RTNLGRP_IPV6_IFADDR,
			     RTNLGRP_IPV4_IFADDR,
			     RTNLGRP_IPV4_ROUTE,
			     RTNLGRP_IPV6_ROUTE,
			     RTNLGRP_NEIGH, RTNLGRP_NOTIFY,
#ifdef RTNLGRP_MPLS_ROUTE	/* not defined on CentOS/RHEL 7 */
			     RTNLGRP_MPLS_ROUTE,
#endif
			     RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_RULE, 0);

  /* Set socket in nonblocking mode and increase buffer sizes */
  nl_socket_set_nonblocking (nm->sk_route);
  nl_socket_set_buffer_size (nm->sk_route, nm->rx_buf_size, nm->tx_buf_size);

  clib_file_t rt_file = {
    .read_function = nl_route_read_cb,
    .file_descriptor = nl_socket_get_fd (nm->sk_route),
    .description = format (0, "linux-cp netlink route socket"),
  };

  clib_file_add (&file_main, &rt_file);

  nl_socket_modify_cb (nm->sk_route, NL_CB_VALID, NL_CB_CUSTOM, nl_route_cb,
		       NULL);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (lcp_nl_init) =
{
  .runs_after =
    VLIB_INITS ("lcp_itf_pair_init", "tuntap_init", "ip_neighbor_init"),
};

#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "linux Control Plane",
  // .default_disabled = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
