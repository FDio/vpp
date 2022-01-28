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
  NL_EVENT_ERR,
} nl_event_type_t;

typedef struct nl_main
{

  struct nl_sock *sk_route;
  vlib_log_class_t nl_logger;
  nl_vft_t *nl_vfts;
  struct nl_cache *nl_caches[LCP_NL_N_OBJS];
  nl_msg_info_t *nl_msg_queue;
  uword clib_file_index;

  u32 rx_buf_size;
  u32 tx_buf_size;
  u32 batch_size;
  u32 batch_delay_ms;

} nl_main_t;

#define NL_RX_BUF_SIZE_DEF    (1 << 27) /* 128 MB */
#define NL_TX_BUF_SIZE_DEF    (1 << 18) /* 256 kB */
#define NL_BATCH_SIZE_DEF     (1 << 11) /* 2048 */
#define NL_BATCH_DELAY_MS_DEF 50	/* 50 ms, max 20 batch/s */

static nl_main_t nl_main = {
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

#define FOREACH_VFT(__func, __arg)                                            \
  {                                                                           \
    nl_main_t *nm = &nl_main;                                                 \
    nl_vft_t *__nv;                                                           \
    vec_foreach (__nv, nm->nl_vfts)                                           \
      {                                                                       \
	if (!__nv->__func.cb)                                                 \
	  continue;                                                           \
                                                                              \
	if (!__nv->__func.is_mp_safe)                                         \
	  vlib_worker_thread_barrier_sync (vlib_get_main ());                 \
                                                                              \
	__nv->__func.cb (__arg);                                              \
                                                                              \
	if (!__nv->__func.is_mp_safe)                                         \
	  vlib_worker_thread_barrier_release (vlib_get_main ());              \
      }                                                                       \
  }

#define FOREACH_VFT_CTX(__func, __arg, __ctx)                                 \
  {                                                                           \
    nl_main_t *nm = &nl_main;                                                 \
    nl_vft_t *__nv;                                                           \
    vec_foreach (__nv, nm->nl_vfts)                                           \
      {                                                                       \
	if (!__nv->__func.cb)                                                 \
	  continue;                                                           \
                                                                              \
	if (!__nv->__func.is_mp_safe)                                         \
	  vlib_worker_thread_barrier_sync (vlib_get_main ());                 \
                                                                              \
	__nv->__func.cb (__arg, __ctx);                                       \
                                                                              \
	if (!__nv->__func.is_mp_safe)                                         \
	  vlib_worker_thread_barrier_release (vlib_get_main ());              \
      }                                                                       \
  }

void
nl_register_vft (const nl_vft_t *nv)
{
  nl_main_t *nm = &nl_main;

  vec_add1 (nm->nl_vfts, *nv);
}

#define NL_DBG(...)   vlib_log_debug (nl_main.nl_logger, __VA_ARGS__);
#define NL_INFO(...)  vlib_log_notice (nl_main.nl_logger, __VA_ARGS__);
#define NL_ERROR(...) vlib_log_err (nl_main.nl_logger, __VA_ARGS__);

static void lcp_nl_open_socket (void);
static void lcp_nl_close_socket (void);

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
      if ((err = nl_msg_parse (msg_info->msg, nl_route_dispatch, msg_info)) <
	  0)
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
nl_route_process (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame)
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
			nm->batch_delay_ms * 1e-3 :
			DAY_F64;
	  break;

	/* reopen the socket if there was an error polling/reading it */
	case NL_EVENT_ERR:
	  lcp_nl_close_socket ();
	  lcp_nl_open_socket ();
	  break;

	default:
	  NL_ERROR ("Unknown event type: %u", (u32) event_type);
	}

      vec_reset_length (event_data);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nl_route_process_node, static) = {
  .function = nl_route_process,
  .name = "linux-cp-netlink-process",
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 17,
};

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

  /* Read until there's an error. Unless the error is ENOBUFS, which means
   * the kernel couldn't send a message due to socket buffer overflow.
   * Continue reading when that happens.
   *
   * libnl translates both ENOBUFS and ENOMEM to NLE_NOMEM. So we need to
   * check return status and errno to make sure we should keep going.
   */
  while ((err = nl_recvmsgs_default (nm->sk_route)) > -1 ||
	 (err == -NLE_NOMEM && errno == ENOBUFS))
    ;

  /* If there was an error other then EAGAIN, signal process node */
  if (err != -NLE_AGAIN)
    vlib_process_signal_event (vlib_get_main (), nl_route_process_node.index,
			       NL_EVENT_ERR, 0);

  return err;
}

void
lcp_nl_pair_add_cb (lcp_itf_pair_t *pair)
{
  lcp_nl_drain_messages ();
}

static clib_error_t *
nl_route_read_cb (clib_file_t *f)
{
  int err;
  err = lcp_nl_drain_messages ();
  if (err < 0 && err != -NLE_AGAIN)
    NL_ERROR ("Error reading netlink socket (fd %d): %s (%d)",
	      f->file_descriptor, nl_geterror (err), err);

  return 0;
}

static clib_error_t *
nl_route_error_cb (clib_file_t *f)
{
  NL_ERROR ("Error polling netlink socket (fd %d)", f->file_descriptor);

  /* notify process node */
  vlib_process_signal_event (vlib_get_main (), nl_route_process_node.index,
			     NL_EVENT_ERR, 0);

  return clib_error_return (0, "Error polling netlink socket %d",
			    f->file_descriptor);
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
    nl_socket_set_buffer_size (nm->sk_route, nm->rx_buf_size, nm->tx_buf_size);
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

static clib_error_t *
lcp_itf_pair_config (vlib_main_t *vm, unformat_input_t *input)
{
  u32 buf_size, batch_size, batch_delay_ms;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "nl-rx-buffer-size %u", &buf_size))
	lcp_nl_set_buffer_size (buf_size);
      else if (unformat (input, "nl-batch-size %u", &batch_size))
	lcp_nl_set_batch_size (batch_size);
      else if (unformat (input, "nl-batch-delay-ms %u", &batch_delay_ms))
	lcp_nl_set_batch_delay (batch_delay_ms);
      else
	return clib_error_return (0, "invalid netlink option: %U",
				  format_unformat_error, input);
    }

  return NULL;
}

VLIB_CONFIG_FUNCTION (lcp_itf_pair_config, "linux-nl");

static void
lcp_nl_close_socket (void)
{
  nl_main_t *nm = &nl_main;

  /* delete existing fd from epoll fd set */
  if (nm->clib_file_index != ~0)
    {
      clib_file_main_t *fm = &file_main;
      clib_file_t *f = clib_file_get (fm, nm->clib_file_index);

      if (f)
	{
	  NL_INFO ("Stopping poll of fd %u", f->file_descriptor);
	  fm->file_update (f, UNIX_FILE_UPDATE_DELETE);
	}
      else
	/* stored index was not a valid file, reset stored index to ~0 */
	nm->clib_file_index = ~0;
    }

  /* If we already created a socket, close/free it */
  if (nm->sk_route)
    {
      NL_INFO ("Closing netlink socket %d", nl_socket_get_fd (nm->sk_route));
      nl_socket_free (nm->sk_route);
      nm->sk_route = NULL;
    }
}

static void
lcp_nl_open_socket (void)
{
  nl_main_t *nm = &nl_main;
  int dest_ns_fd, curr_ns_fd;

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

  if (dest_ns_fd && curr_ns_fd >= 0)
    {
      setns (curr_ns_fd, CLONE_NEWNET);
      close (curr_ns_fd);
    }

  /* Subscribe to all the 'routing' notifications on the route socket */
  nl_socket_add_memberships (nm->sk_route, RTNLGRP_LINK, RTNLGRP_IPV6_IFADDR,
			     RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_ROUTE,
			     RTNLGRP_IPV6_ROUTE, RTNLGRP_NEIGH, RTNLGRP_NOTIFY,
#ifdef RTNLGRP_MPLS_ROUTE /* not defined on CentOS/RHEL 7 */
			     RTNLGRP_MPLS_ROUTE,
#endif
			     RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_RULE, 0);

  /* Set socket in nonblocking mode and increase buffer sizes */
  nl_socket_set_nonblocking (nm->sk_route);
  nl_socket_set_buffer_size (nm->sk_route, nm->rx_buf_size, nm->tx_buf_size);

  if (nm->clib_file_index == ~0)
    {
      clib_file_t rt_file = {
	.read_function = nl_route_read_cb,
	.error_function = nl_route_error_cb,
	.file_descriptor = nl_socket_get_fd (nm->sk_route),
	.description = format (0, "linux-cp netlink route socket"),
      };

      nm->clib_file_index = clib_file_add (&file_main, &rt_file);
      NL_INFO ("Added file %u", nm->clib_file_index);
    }
  else
    /* clib file already created and socket was closed due to error */
    {
      clib_file_main_t *fm = &file_main;
      clib_file_t *f = clib_file_get (fm, nm->clib_file_index);

      f->file_descriptor = nl_socket_get_fd (nm->sk_route);
      fm->file_update (f, UNIX_FILE_UPDATE_ADD);
      NL_INFO ("Starting poll of %d", f->file_descriptor);
    }

  nl_socket_modify_cb (nm->sk_route, NL_CB_VALID, NL_CB_CUSTOM, nl_route_cb,
		       NULL);
  NL_INFO ("Opened netlink socket %d", nl_socket_get_fd (nm->sk_route));
}

#include <vnet/plugin/plugin.h>
clib_error_t *
lcp_nl_init (vlib_main_t *vm)
{
  nl_main_t *nm = &nl_main;
  lcp_itf_pair_vft_t nl_itf_pair_vft = {
    .pair_add_fn = lcp_nl_pair_add_cb,
  };

  nm->clib_file_index = ~0;
  nm->nl_logger = vlib_log_register_class ("nl", "nl");

  lcp_nl_open_socket ();
  lcp_itf_pair_register_vft (&nl_itf_pair_vft);

  return (NULL);
}

VLIB_INIT_FUNCTION (lcp_nl_init) = {
  .runs_after = VLIB_INITS ("lcp_interface_init", "tuntap_init",
			    "ip_neighbor_init"),
};

#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "linux Control Plane - Netlink listener",
  .default_disabled = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
