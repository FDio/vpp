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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/error.h>

#include <vnet/fib/fib_table.h>

#include <libmnl/libmnl.h>

#include <plugins/linux-cp/lcp_netlink.h>
#include <plugins/linux-cp/lcp_interface.h>

typedef enum nl_event_type_t_
{
  NL_EVENT_READ,
  NL_EVENT_READ_ERR,
} nl_event_type_t;

typedef struct lcp_nl_main
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
  u32 batch_work_ms;

} lcp_nl_main_t;

#define NL_RX_BUF_SIZE_DEF    (1 << 27) /* 128 MB */
#define NL_TX_BUF_SIZE_DEF    (1 << 18) /* 256 kB */
#define NL_BATCH_SIZE_DEF     (1 << 13) /* 8192 */
#define NL_BATCH_WORK_MS_DEF  40	/* 40 ms */
#define NL_BATCH_DELAY_MS_DEF 10	/* 10 ms */

static lcp_nl_main_t lcp_nl_main = {
  .rx_buf_size = NL_RX_BUF_SIZE_DEF,
  .tx_buf_size = NL_TX_BUF_SIZE_DEF,
  .batch_size = NL_BATCH_SIZE_DEF,
  .batch_delay_ms = NL_BATCH_DELAY_MS_DEF,
  .batch_work_ms = NL_BATCH_WORK_MS_DEF,
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
    lcp_nl_main_t *nm = &lcp_nl_main;                                         \
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
    lcp_nl_main_t *nm = &lcp_nl_main;                                         \
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
lcp_nl_register_vft (const nl_vft_t *nv)
{
  lcp_nl_main_t *nm = &lcp_nl_main;

  vec_add1 (nm->nl_vfts, *nv);
}

#define NL_DBG(...)    vlib_log_debug (lcp_nl_main.nl_logger, __VA_ARGS__);
#define NL_INFO(...)   vlib_log_info (lcp_nl_main.nl_logger, __VA_ARGS__);
#define NL_NOTICE(...) vlib_log_notice (lcp_nl_main.nl_logger, __VA_ARGS__);
#define NL_WARN(...)   vlib_log_warn (lcp_nl_main.nl_logger, __VA_ARGS__);
#define NL_ERROR(...)  vlib_log_err (lcp_nl_main.nl_logger, __VA_ARGS__);

static void lcp_nl_open_socket (void);
static void lcp_nl_close_socket (void);

static void
lcp_nl_route_del (struct rtnl_route *rr, void *arg)
{
  FOREACH_VFT (nvl_rt_route_del, rr);
}

static void
lcp_nl_route_add (struct rtnl_route *rr, void *arg)
{
  FOREACH_VFT (nvl_rt_route_add, rr);
}

static void
lcp_nl_neigh_del (struct rtnl_neigh *rn, void *arg)
{
  FOREACH_VFT (nvl_rt_neigh_del, rn);
}

static void
lcp_nl_neigh_add (struct rtnl_neigh *rn, void *arg)
{
  FOREACH_VFT (nvl_rt_neigh_add, rn);
}

static void
lcp_nl_addr_del (struct rtnl_addr *rla, void *arg)
{
  FOREACH_VFT (nvl_rt_addr_del, rla);
}

static void
lcp_nl_addr_add (struct rtnl_addr *rla, void *arg)
{
  FOREACH_VFT (nvl_rt_addr_add, rla);
}

static void
lcp_nl_link_del (struct rtnl_link *rl, void *arg)
{
  FOREACH_VFT_CTX (nvl_rt_link_del, rl, arg);
}

static void
lcp_nl_link_add (struct rtnl_link *rl, void *arg)
{
  FOREACH_VFT_CTX (nvl_rt_link_add, rl, arg);
}

u8 *
format_nl_object (u8 *s, va_list *args)
{
  int type;
  struct nl_object *obj = va_arg (*args, struct nl_object *);
  if (!obj)
    return s;

  s = format (s, "%s: ", nl_object_get_type (obj));
  type = nl_object_get_msgtype (obj);
  switch (type)
    {
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
      {
	struct rtnl_route *route = (struct rtnl_route *) obj;
	struct nl_addr *a;
	int n;

	char buf[128];
	s = format (
	  s, "%s family %s", type == RTM_NEWROUTE ? "add" : "del",
	  nl_af2str (rtnl_route_get_family (route), buf, sizeof (buf)));
	s = format (
	  s, " type %d proto %d table %d", rtnl_route_get_type (route),
	  rtnl_route_get_protocol (route), rtnl_route_get_table (route));
	if ((a = rtnl_route_get_src (route)))
	  s = format (s, " src %s", nl_addr2str (a, buf, sizeof (buf)));
	if ((a = rtnl_route_get_dst (route)))
	  s = format (s, " dst %s", nl_addr2str (a, buf, sizeof (buf)));

	s = format (s, " nexthops {");
	for (n = 0; n < rtnl_route_get_nnexthops (route); n++)
	  {
	    struct rtnl_nexthop *nh;
	    nh = rtnl_route_nexthop_n (route, n);
	    if ((a = rtnl_route_nh_get_via (nh)))
	      s = format (s, " via %s", nl_addr2str (a, buf, sizeof (buf)));
	    if ((a = rtnl_route_nh_get_gateway (nh)))
	      s =
		format (s, " gateway %s", nl_addr2str (a, buf, sizeof (buf)));
	    if ((a = rtnl_route_nh_get_newdst (nh)))
	      s = format (s, " newdst %s", nl_addr2str (a, buf, sizeof (buf)));
	    s = format (s, " idx %d", rtnl_route_nh_get_ifindex (nh));
	  }
	s = format (s, " }");
      }
      break;
    case RTM_NEWNEIGH:
    case RTM_DELNEIGH:
      {
	struct rtnl_neigh *neigh = (struct rtnl_neigh *) obj;
	int idx = rtnl_neigh_get_ifindex (neigh);
	struct nl_addr *a;
	char buf[128];
	s = format (
	  s, "%s idx %d family %s", type == RTM_NEWNEIGH ? "add" : "del", idx,
	  nl_af2str (rtnl_neigh_get_family (neigh), buf, sizeof (buf)));
	if ((a = rtnl_neigh_get_lladdr (neigh)))
	  s = format (s, " lladdr %s", nl_addr2str (a, buf, sizeof (buf)));
	if ((a = rtnl_neigh_get_dst (neigh)))
	  s = format (s, " dst %s", nl_addr2str (a, buf, sizeof (buf)));

	s = format (s, " state 0x%04x", rtnl_neigh_get_state (neigh));
	rtnl_neigh_state2str (rtnl_neigh_get_state (neigh), buf, sizeof (buf));
	if (buf[0])
	  s = format (s, " (%s)", buf);

	s = format (s, " flags 0x%04x", rtnl_neigh_get_flags (neigh));
	rtnl_neigh_flags2str (rtnl_neigh_get_flags (neigh), buf, sizeof (buf));
	if (buf[0])
	  s = format (s, " (%s)", buf);
      }
      break;
    case RTM_NEWADDR:
    case RTM_DELADDR:
      {
	struct rtnl_addr *addr = (struct rtnl_addr *) obj;
	int idx = rtnl_addr_get_ifindex (addr);
	struct nl_addr *a;
	char buf[128];

	s = format (
	  s, "%s idx %d family %s", type == RTM_NEWADDR ? "add" : "del", idx,
	  nl_af2str (rtnl_addr_get_family (addr), buf, sizeof (buf)));
	if ((a = rtnl_addr_get_local (addr)))
	  s = format (s, " local %s", nl_addr2str (a, buf, sizeof (buf)));
	if ((a = rtnl_addr_get_peer (addr)))
	  s = format (s, " peer %s", nl_addr2str (a, buf, sizeof (buf)));
	if ((a = rtnl_addr_get_broadcast (addr)))
	  s = format (s, " broadcast %s", nl_addr2str (a, buf, sizeof (buf)));

	s = format (s, " flags 0x%04x", rtnl_addr_get_flags (addr));
	rtnl_addr_flags2str (rtnl_addr_get_flags (addr), buf, sizeof (buf));
	if (buf[0])
	  s = format (s, " (%s)", buf);
      }
      break;
    case RTM_NEWLINK:
    case RTM_DELLINK:
      {
	struct rtnl_link *link = (struct rtnl_link *) obj;
	struct nl_addr *a;
	char buf[128];
	// mac_addr = rtnl_link_get_addr (l);
	s =
	  format (s, "%s idx %d name %s", type == RTM_NEWLINK ? "add" : "del",
		  rtnl_link_get_ifindex (link), rtnl_link_get_name (link));

	if ((a = rtnl_link_get_addr (link)))
	  s = format (s, " addr %s", nl_addr2str (a, buf, sizeof (buf)));

	s = format (s, " mtu %u carrier %d", rtnl_link_get_mtu (link),
		    rtnl_link_get_carrier (link));

	s = format (s, " operstate 0x%04x", rtnl_link_get_operstate (link));
	rtnl_link_operstate2str (rtnl_link_get_operstate (link), buf,
				 sizeof (buf));
	if (buf[0])
	  s = format (s, " (%s)", buf);

	s = format (s, " flags 0x%04x", rtnl_link_get_flags (link));
	rtnl_link_flags2str (rtnl_link_get_flags (link), buf, sizeof (buf));
	if (buf[0])
	  s = format (s, " (%s)", buf);

	if (rtnl_link_is_vlan (link))
	  {
	    s =
	      format (s, " vlan { parent-idx %d id %d proto 0x%04x",
		      rtnl_link_get_link (link), rtnl_link_vlan_get_id (link),
		      ntohs (rtnl_link_vlan_get_protocol (link)));
	    s = format (s, " flags 0x%04x", rtnl_link_vlan_get_flags (link));
	    rtnl_link_vlan_flags2str (rtnl_link_vlan_get_flags (link), buf,
				      sizeof (buf));
	    if (buf[0])
	      s = format (s, " (%s)", buf);
	    s = format (s, " }", buf);
	  }
      }
      break;
    default:
      s = format (s, " <unknown>");
      break;
    }
  return s;
}

static void
lcp_nl_dispatch (struct nl_object *obj, void *arg)
{
  /* nothing can be done without interface mappings */
  if (!lcp_itf_num_pairs ())
    return;

  switch (nl_object_get_msgtype (obj))
    {
    case RTM_NEWROUTE:
      lcp_nl_route_add ((struct rtnl_route *) obj, arg);
      break;
    case RTM_DELROUTE:
      lcp_nl_route_del ((struct rtnl_route *) obj, arg);
      break;
    case RTM_NEWNEIGH:
      lcp_nl_neigh_add ((struct rtnl_neigh *) obj, arg);
      break;
    case RTM_DELNEIGH:
      lcp_nl_neigh_del ((struct rtnl_neigh *) obj, arg);
      break;
    case RTM_NEWADDR:
      lcp_nl_addr_add ((struct rtnl_addr *) obj, arg);
      break;
    case RTM_DELADDR:
      lcp_nl_addr_del ((struct rtnl_addr *) obj, arg);
      break;
    case RTM_NEWLINK:
      lcp_nl_link_add ((struct rtnl_link *) obj, arg);
      break;
    case RTM_DELLINK:
      lcp_nl_link_del ((struct rtnl_link *) obj, arg);
      break;
    default:
      NL_WARN ("dispatch: ignored %U", format_nl_object, obj);
      break;
    }
}

static int
lcp_nl_process_msgs (void)
{
  lcp_nl_main_t *nm = &lcp_nl_main;
  nl_msg_info_t *msg_info;
  int err, n_msgs = 0;
  f64 start = vlib_time_now (vlib_get_main ());
  u64 usecs = 0;

  /* To avoid loops where VPP->LCP sync fights with LCP->VPP
   * sync, we turn off the former if it's enabled, while we consume
   * the netlink messages in this function, and put it back at the
   * end of the function.
   */
  lcp_main_t *lcpm = &lcp_main;
  u8 old_lcp_sync = lcpm->lcp_sync;
  lcpm->lcp_sync = 0;

  /* process a batch of messages. break if we hit our limit */
  vec_foreach (msg_info, nm->nl_msg_queue)
    {
      if ((err = nl_msg_parse (msg_info->msg, lcp_nl_dispatch, msg_info)) < 0)
	NL_ERROR ("process_msgs: Unable to parse object: %s",
		  nl_geterror (err));
      nlmsg_free (msg_info->msg);
      if (++n_msgs >= nm->batch_size)
	{
	  NL_INFO ("process_msgs: batch_size %u reached, yielding",
		   nm->batch_size);
	  break;
	}
      usecs = (u64) (1e6 * (vlib_time_now (vlib_get_main ()) - start));
      if (usecs >= 1e3 * nm->batch_work_ms)
	{
	  NL_INFO ("process_msgs: batch_work_ms %u reached, yielding",
		   nm->batch_work_ms);
	  break;
	}
    }

  /* remove the messages we processed from the head of the queue */
  if (n_msgs)
    vec_delete (nm->nl_msg_queue, n_msgs, 0);

  if (n_msgs > 0)
    {
      if (vec_len (nm->nl_msg_queue))
	{
	  NL_WARN ("process_msgs: Processed %u messages in %llu usecs, %u "
		   "left in queue",
		   n_msgs, usecs, vec_len (nm->nl_msg_queue));
	}
      else
	{
	  NL_INFO ("process_msgs: Processed %u messages in %llu usecs", n_msgs,
		   usecs);
	}
    }

  lcpm->lcp_sync = old_lcp_sync;

  return n_msgs;
}

#define DAY_F64 (1.0 * (24 * 60 * 60))

static uword
lcp_nl_process (vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_frame_t *frame)
{
  lcp_nl_main_t *nm = &lcp_nl_main;
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
	  lcp_nl_process_msgs ();
	  wait_time = (vec_len (nm->nl_msg_queue) != 0) ?
			nm->batch_delay_ms * 1e-3 :
			DAY_F64;
	  break;

	/* reopen the socket if there was an error polling/reading it */
	case NL_EVENT_READ_ERR:
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

VLIB_REGISTER_NODE (lcp_nl_process_node, static) = {
  .function = lcp_nl_process,
  .name = "linux-cp-netlink-process",
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 17,
};

static int
lcp_nl_callback (struct nl_msg *msg, void *arg)
{
  lcp_nl_main_t *nm = &lcp_nl_main;
  nl_msg_info_t *msg_info = 0;

  /* delay processing - increment ref count and queue for later */
  vec_add2 (nm->nl_msg_queue, msg_info, 1);

  /* store a timestamp for the message */
  msg_info->ts = vlib_time_now (vlib_get_main ());
  msg_info->msg = msg;
  nlmsg_get (msg);

  /* notify process node */
  vlib_process_signal_event (vlib_get_main (), lcp_nl_process_node.index,
			     NL_EVENT_READ, 0);

  return 0;
}

static clib_error_t *
lcp_nl_read_cb (clib_file_t *f)
{
  int err;
  lcp_nl_main_t *nm = &lcp_nl_main;

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
  if (err < 0 && err != -NLE_AGAIN)
    {
      NL_ERROR ("read_cb: Error reading netlink socket (fd %d): %s (%d)",
		f->file_descriptor, nl_geterror (err), err);
      vlib_process_signal_event (vlib_get_main (), lcp_nl_process_node.index,
				 NL_EVENT_READ_ERR, 0);
    }

  return 0;
}

static clib_error_t *
lcp_nl_error_cb (clib_file_t *f)
{
  NL_ERROR ("error_cb: Error polling netlink socket (fd %d)",
	    f->file_descriptor);

  /* notify process node */
  vlib_process_signal_event (vlib_get_main (), lcp_nl_process_node.index,
			     NL_EVENT_READ_ERR, 0);

  return clib_error_return (0, "Error polling netlink socket %d",
			    f->file_descriptor);
}

struct nl_cache *
lcp_nl_get_cache (lcp_nl_obj_t t)
{
  lcp_nl_main_t *nm = &lcp_nl_main;

  return nm->nl_caches[t];
}

/* Set the RX buffer size to be used on the netlink socket */
void
lcp_nl_set_buffer_size (u32 buf_size)
{
  lcp_nl_main_t *nm = &lcp_nl_main;

  nm->rx_buf_size = buf_size;

  if (nm->sk_route)
    nl_socket_set_buffer_size (nm->sk_route, nm->rx_buf_size, nm->tx_buf_size);
}

/* Set the batch size - maximum netlink messages to process at one time */
void
lcp_nl_set_batch_size (u32 batch_size)
{
  lcp_nl_main_t *nm = &lcp_nl_main;

  nm->batch_size = batch_size;
}

/* Set the batch delay - how long to wait in ms between processing batches */
void
lcp_nl_set_batch_delay (u32 batch_delay_ms)
{
  lcp_nl_main_t *nm = &lcp_nl_main;

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
  lcp_nl_main_t *nm = &lcp_nl_main;

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
  lcp_nl_main_t *nm = &lcp_nl_main;
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

  if (dest_ns_fd)
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
	.read_function = lcp_nl_read_cb,
	.error_function = lcp_nl_error_cb,
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

  nl_socket_modify_cb (nm->sk_route, NL_CB_VALID, NL_CB_CUSTOM,
		       lcp_nl_callback, NULL);
  NL_INFO ("Opened netlink socket %d", nl_socket_get_fd (nm->sk_route));
}

#include <vnet/plugin/plugin.h>
clib_error_t *
lcp_nl_init (vlib_main_t *vm)
{
  lcp_nl_main_t *nm = &lcp_nl_main;

  nm->clib_file_index = ~0;
  nm->nl_logger = vlib_log_register_class ("linux-cp", "nl");

  lcp_nl_open_socket ();

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
