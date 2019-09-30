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
  nl_msg_info_t *nl_msg_queue;

  u32 rx_buf_size;
  u32 tx_buf_size;
  u32 batch_size;
  u32 batch_delay_ms;

} nl_main_t;

#define NL_RX_BUF_SIZE_DEF (1 << 25)  /* 64 MB */
#define NL_TX_BUF_SIZE_DEF (1 << 18)  /* 256 kB */
#define NL_BATCH_SIZE_DEF (1 << 11)   /* 2048 */
#define NL_BATCH_DELAY_MS_DEF 50      /* 50 ms, max 20 batch/s */

static nl_main_t nl_main =
{
  .rx_buf_size = NL_RX_BUF_SIZE_DEF,
  .tx_buf_size = NL_TX_BUF_SIZE_DEF,
  .batch_size = NL_BATCH_SIZE_DEF,
  .batch_delay_ms = NL_BATCH_DELAY_MS_DEF,
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

#define FOREACH_VFT_CTX(__func, __arg, __ctx)   \
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
        __nv->__func.cb(__arg, __ctx);          \
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
  FOREACH_VFT_CTX (nvl_rt_link_del, rl, arg);
}

static void
nl_link_add (struct rtnl_link *rl, void *arg)
{
  FOREACH_VFT_CTX (nvl_rt_link_add, rl, arg);
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
nl_route_process_msgs (void)
{
  nl_main_t *nm = &nl_main;
  nl_msg_info_t *msg_info;
  int err, n_msgs = 0;

  /* process a batch of messages. break if we hit our limit */
  vec_foreach (msg_info, nm->nl_msg_queue)
  {
    if ((err = nl_msg_parse (msg_info->msg, nl_route_dispatch, msg_info)) < 0)
      NL_ERROR ("Unable to parse object: %s", nl_geterror (err));
    nlmsg_free (msg_info->msg);
    if (++n_msgs >= nm->batch_size)
      break;
  }

  /* remove the messages we processed from the head of the queue */
  if (n_msgs)
    vec_delete (nm->nl_msg_queue, n_msgs, 0);

  NL_INFO ("Processed %u messages", n_msgs);

  return n_msgs;
}

#define DAY_F64 (1.0 * (24 * 60 * 60))

static uword
nl_route_process (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  nl_main_t *nm = &nl_main;
  uword event_type;
  uword *event_data = 0;
  f64 wait_time = DAY_F64;

  while (1)
    {
      /* If we process a batch of messages and stop because we reached the
       * batch size limit, we want to wake up after the batch delay and
       * process more. Otherwise we just want to wait for a read event.
       */
      vlib_process_wait_for_event_or_clock (vm, wait_time);
      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	/* process batch of queued messages on timeout or read event signal */
	case ~0:
	case NL_EVENT_READ:
	  nl_route_process_msgs ();
	  wait_time = (vec_len (nm->nl_msg_queue) != 0) ?
	    nm->batch_delay_ms * 1e-3 : DAY_F64;
	  break;
	default:
	  NL_ERROR ("Unknown event type: %u", (u32)event_type);
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

static int
nl_route_cb (struct nl_msg *msg, void *arg)
{
  nl_main_t *nm = &nl_main;
  nl_msg_info_t *msg_info = 0;

  /* delay processing - increment ref count and queue for later */
  vec_add2 (nm->nl_msg_queue, msg_info, 1);

  /* store a timestamp for the message */
  msg_info->ts = vlib_time_now (vlib_get_main ());
  msg_info->msg = msg;
  nlmsg_get (msg);

  /* notify process node */
  vlib_process_signal_event (vlib_get_main (), nl_route_process_node.index,
			     NL_EVENT_READ, 0);

  return 0;
}

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

/* Set the batch size - maximum netlink messages to process at one time */
void
lcp_nl_set_batch_size (u32 batch_size)
{
  nl_main_t *nm = &nl_main;

  nm->batch_size = batch_size;
}

/* Set the batch delay - how long to wait in ms between processing batches */
void
lcp_nl_set_batch_delay (u32 batch_delay_ms)
{
  nl_main_t *nm = &nl_main;

  nm->batch_delay_ms = batch_delay_ms;
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
