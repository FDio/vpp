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
#include <vppinfra/linux/netns.h>

#include <vnet/fib/fib_table.h>

#include <libmnl/libmnl.h>

#include <plugins/linux-cp/lcp_interface.h>

typedef enum nl_status_t_
{
  NL_STATUS_NOTIF_PROC,
  NL_STATUS_SYNC,
} nl_status_t;

typedef enum nl_sock_type_t_
{
  NL_SOCK_TYPE_LINK,
  NL_SOCK_TYPE_ADDR,
  NL_SOCK_TYPE_NEIGH,
  NL_SOCK_TYPE_ROUTE,
} nl_sock_type_t;

#define NL_SOCK_TYPES_N (NL_SOCK_TYPE_ROUTE + 1)

/* Socket type, message type, type name, function subname */
#define foreach_sock_type                                                     \
  _ (NL_SOCK_TYPE_LINK, RTM_GETLINK, "link", link)                            \
  _ (NL_SOCK_TYPE_ADDR, RTM_GETADDR, "address", link_addr)                    \
  _ (NL_SOCK_TYPE_NEIGH, RTM_GETNEIGH, "neighbor", neigh)                     \
  _ (NL_SOCK_TYPE_ROUTE, RTM_GETROUTE, "route", route)

typedef enum nl_event_type_t_
{
  NL_EVENT_READ,
  NL_EVENT_ERR,
} nl_event_type_t;

typedef struct nl_main
{

  nl_status_t nl_status;

  struct nl_sock *sk_route;
  struct nl_sock *sk_route_sync[NL_SOCK_TYPES_N];
  vlib_log_class_t nl_logger;
  nl_vft_t *nl_vfts;
  struct nl_cache *nl_caches[LCP_NL_N_OBJS];
  nl_msg_info_t *nl_msg_queue;
  uword clib_file_index;

  u32 rx_buf_size;
  u32 tx_buf_size;
  u32 batch_size;
  u32 batch_delay_ms;

  u32 sync_batch_limit;
  u32 sync_batch_delay_ms;
  u32 sync_attempt_delay_ms;

} nl_main_t;

#define NL_RX_BUF_SIZE_DEF    (1 << 27) /* 128 MB */
#define NL_TX_BUF_SIZE_DEF    (1 << 18) /* 256 kB */
#define NL_BATCH_SIZE_DEF     (1 << 11) /* 2048 */
#define NL_BATCH_DELAY_MS_DEF 50	/* 50 ms, max 20 batch/s */

#define NL_SYNC_BATCH_LIMIT_DEF	     (1 << 10) /* 1024 */
#define NL_SYNC_BATCH_DELAY_MS_DEF   20	       /* 20ms, max 50 batch/s */
#define NL_SYNC_ATTEMPT_DELAY_MS_DEF 2000      /* 2s */

static nl_main_t nl_main = {
  .rx_buf_size = NL_RX_BUF_SIZE_DEF,
  .tx_buf_size = NL_TX_BUF_SIZE_DEF,
  .batch_size = NL_BATCH_SIZE_DEF,
  .batch_delay_ms = NL_BATCH_DELAY_MS_DEF,
  .sync_batch_limit = NL_SYNC_BATCH_LIMIT_DEF,
  .sync_batch_delay_ms = NL_SYNC_BATCH_DELAY_MS_DEF,
  .sync_attempt_delay_ms = NL_SYNC_ATTEMPT_DELAY_MS_DEF,
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

#define FOREACH_VFT_NO_ARG(__func)                                            \
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
	__nv->__func.cb ();                                                   \
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
static void lcp_nl_open_sync_socket (nl_sock_type_t sock_type);
static void lcp_nl_close_sync_socket (nl_sock_type_t sock_type);

static void
nl_route_del (struct rtnl_route *rr, void *arg)
{
  FOREACH_VFT (nvl_rt_route_del, rr);
}

static void
nl_route_add (struct rtnl_route *rr, void *arg)
{
  int is_replace = 0;

  if (arg)
    {
      nl_msg_info_t *msg_info = (nl_msg_info_t *) arg;
      struct nlmsghdr *nlh = nlmsg_hdr (msg_info->msg);

      is_replace = (nlh->nlmsg_flags & NLM_F_REPLACE);
    }

  FOREACH_VFT_CTX (nvl_rt_route_add, rr, is_replace);
}

static void
nl_route_sync_begin (void)
{
  FOREACH_VFT_NO_ARG (nvl_rt_route_sync_begin);
}

static void
nl_route_sync_end (void)
{
  FOREACH_VFT_NO_ARG (nvl_rt_route_sync_end);
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
nl_neigh_sync_begin (void)
{
  FOREACH_VFT_NO_ARG (nvl_rt_neigh_sync_begin);
}

static void
nl_neigh_sync_end (void)
{
  FOREACH_VFT_NO_ARG (nvl_rt_neigh_sync_end);
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
nl_link_addr_sync_begin (void)
{
  FOREACH_VFT_NO_ARG (nvl_rt_addr_sync_begin);
}

static void
nl_link_addr_sync_end (void)
{
  FOREACH_VFT_NO_ARG (nvl_rt_addr_sync_end);
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
nl_link_sync_begin (void)
{
  FOREACH_VFT_NO_ARG (nvl_rt_link_sync_begin);
}

static void
nl_link_sync_end (void)
{
  FOREACH_VFT_NO_ARG (nvl_rt_link_sync_end);
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

  NL_DBG ("Processed %u messages", n_msgs);

  return n_msgs;
}

static int
lcp_nl_route_discard_msgs (void)
{
  nl_main_t *nm = &nl_main;
  nl_msg_info_t *msg_info;
  int n_msgs;

  n_msgs = vec_len (nm->nl_msg_queue);
  if (n_msgs == 0)
    return 0;

  vec_foreach (msg_info, nm->nl_msg_queue)
    {
      nlmsg_free (msg_info->msg);
    }

  vec_reset_length (nm->nl_msg_queue);

  NL_INFO ("Discarded %u messages", n_msgs);

  return n_msgs;
}

static int
lcp_nl_route_send_dump_req (nl_sock_type_t sock_type, int msg_type)
{
  nl_main_t *nm = &nl_main;
  struct nl_sock *sk_route = nm->sk_route_sync[sock_type];
  int err;
  struct rtgenmsg rt_hdr = {
    .rtgen_family = AF_UNSPEC,
  };

  err =
    nl_send_simple (sk_route, msg_type, NLM_F_DUMP, &rt_hdr, sizeof (rt_hdr));

  if (err < 0)
    {
      NL_ERROR ("Unable to send a dump request: %s", nl_geterror (err));
    }
  else
    NL_INFO ("Dump request sent via socket %d of type %d",
	     nl_socket_get_fd (sk_route), sock_type);

  return err;
}

static int
lcp_nl_route_dump_cb (struct nl_msg *msg, void *arg)
{
  int err;

  if ((err = nl_msg_parse (msg, nl_route_dispatch, NULL)) < 0)
    NL_ERROR ("Unable to parse object: %s", nl_geterror (err));

  return NL_OK;
}

static int
lcp_nl_recv_dump_replies (nl_sock_type_t sock_type, int msg_limit,
			  int *is_done_rcvd)
{
  nl_main_t *nm = &nl_main;
  struct nl_sock *sk_route = nm->sk_route_sync[sock_type];
  struct sockaddr_nl nla;
  uint8_t *buf = NULL;
  int n_bytes;
  struct nlmsghdr *hdr;
  struct nl_msg *msg = NULL;
  int err = 0;
  int done = 0;
  int n_msgs = 0;

continue_reading:
  n_bytes = nl_recv (sk_route, &nla, &buf, /* creds */ NULL);
  if (n_bytes <= 0)
    return n_bytes;

  hdr = (struct nlmsghdr *) buf;
  while (nlmsg_ok (hdr, n_bytes))
    {
      nlmsg_free (msg);
      msg = nlmsg_convert (hdr);
      if (!msg)
	{
	  err = -NLE_NOMEM;
	  goto out;
	}

      n_msgs++;

      nlmsg_set_proto (msg, NETLINK_ROUTE);
      nlmsg_set_src (msg, &nla);

      /* Message that terminates a multipart message. Finish parsing and signal
       * the caller that all dump replies have been received
       */
      if (hdr->nlmsg_type == NLMSG_DONE)
	{
	  done = 1;
	  goto out;
	}
      /* Message to be ignored. Continue parsing */
      else if (hdr->nlmsg_type == NLMSG_NOOP)
	;
      /* Message that indicates data was lost. Finish parsing and return an
       * error
       */
      else if (hdr->nlmsg_type == NLMSG_OVERRUN)
	{
	  err = -NLE_MSG_OVERFLOW;
	  goto out;
	}
      /* Message that indicates an error. Finish parsing, extract the error
       * code, and return it */
      else if (hdr->nlmsg_type == NLMSG_ERROR)
	{
	  struct nlmsgerr *e = nlmsg_data (hdr);

	  if (hdr->nlmsg_len < nlmsg_size (sizeof (*e)))
	    {
	      err = -NLE_MSG_TRUNC;
	      goto out;
	    }
	  else if (e->error)
	    {
	      err = -nl_syserr2nlerr (e->error);
	      goto out;
	    }
	  /* Message is an acknowledgement (err_code = 0). Continue parsing */
	  else
	    ;
	}
      /* Message that contains the requested data. Pass it for processing and
       * continue parsing
       */
      else
	{
	  lcp_nl_route_dump_cb (msg, NULL);
	}

      hdr = nlmsg_next (hdr, &n_bytes);
    }

  nlmsg_free (msg);
  free (buf);
  msg = NULL;
  buf = NULL;

  if (!done && n_msgs < msg_limit)
    goto continue_reading;

out:
  nlmsg_free (msg);
  free (buf);

  if (err)
    return err;

  *is_done_rcvd = done;

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
  int n_msgs;
  int is_done;

  while (1)
    {
      if (nm->nl_status == NL_STATUS_NOTIF_PROC)
	{
	  /* If we process a batch of messages and stop because we reached the
	   * batch size limit, we want to wake up after the batch delay and
	   * process more. Otherwise we just want to wait for a read event.
	   */
	  vlib_process_wait_for_event_or_clock (vm, wait_time);
	  event_type = vlib_process_get_events (vm, &event_data);
	  vec_reset_length (event_data);

	  switch (event_type)
	    {
	    /* Process batch of queued messages on timeout or read event
	     * signal
	     */
	    case ~0:
	    case NL_EVENT_READ:
	      nl_route_process_msgs ();
	      wait_time = (vec_len (nm->nl_msg_queue) != 0) ?
			    nm->batch_delay_ms * 1e-3 :
			    DAY_F64;
	      break;

	    /* Initiate synchronization if there was an error polling or
	     * reading the notification socket
	     */
	    case NL_EVENT_ERR:
	      nm->nl_status = NL_STATUS_SYNC;
	      break;

	    default:
	      NL_ERROR ("Unknown event type: %u", (u32) event_type);
	    }
	}
      else if (nm->nl_status == NL_STATUS_SYNC)
	{
	  /* Stop processing notifications - close the notification socket and
	   * discard all messages that are currently in the queue
	   */
	  lcp_nl_close_socket ();
	  lcp_nl_route_discard_msgs ();

	  /* Wait some time before next synchronization attempt. Allows to
	   * reduce the number of failed attempts that stall the main thread by
	   * waiting out the notification storm
	   */
	  NL_INFO ("Wait before next synchronization attempt for %ums",
		   nm->sync_attempt_delay_ms);
	  vlib_process_suspend (vm, nm->sync_attempt_delay_ms * 1e-3);

	  /* Open netlink synchronization socket, one for every data type of
	   * interest: link, address, neighbor, and route. That is needed to
	   * be able to send dump requests for every data type simultaneously.
	   * If send a dump request while the previous one is in progress,
	   * the request will fail and EBUSY returned
	   */
#define _(stype, mtype, tname, fn) lcp_nl_open_sync_socket (stype);
	  foreach_sock_type
#undef _

	  /* Start reading notifications and enqueueing them for further
	   * processing. The notifications will serve as a difference between
	   * the snapshot made after the dump request and the actual state at
	   * the moment. Once all the dump replies are processed, the
	   * notifications will be processed
	   */
	  lcp_nl_open_socket ();

	  /* Request the current entry set from the kernel for every data type
	   * of interest. Thus requesting a snapshot of the current routing
	   * state that the kernel will make and then reply with
	   */
#define _(stype, mtype, tname, fn) lcp_nl_route_send_dump_req (stype, mtype);
	  foreach_sock_type
#undef _

	  /* Process all the dump replies */
#define _(stype, mtype, tname, fn)                                            \
  nl_##fn##_sync_begin ();                                                    \
  is_done = 0;                                                                \
  do                                                                          \
    {                                                                         \
      n_msgs =                                                                \
	lcp_nl_recv_dump_replies (stype, nm->sync_batch_limit, &is_done);     \
      if (n_msgs < 0)                                                         \
	{                                                                     \
	  NL_ERROR ("Error receiving dump replies of type " tname             \
		    ": %s (%d)",                                              \
		    nl_geterror (n_msgs), n_msgs);                            \
	  break;                                                              \
	}                                                                     \
      else if (n_msgs == 0)                                                   \
	{                                                                     \
	  NL_ERROR ("EOF while receiving dump replies of type " tname);       \
	  break;                                                              \
	}                                                                     \
      else                                                                    \
	NL_INFO ("Processed %u dump replies of type " tname, n_msgs);         \
                                                                              \
      /* Suspend the processing loop and wait until event signal is           \
       * received or timeout expires. During synchronization, only            \
       * error event is expected because read event is suppressed.            \
       * Allows not to stall the main thread and detect errors on the         \
       * notification socket that will make synchronization                   \
       * incomplete                                                           \
       */                                                                     \
      vlib_process_wait_for_event_or_clock (vm,                               \
					    nm->sync_batch_delay_ms * 1e-3);  \
      event_type = vlib_process_get_events (vm, &event_data);                 \
      vec_reset_length (event_data);                                          \
                                                                              \
      /* If error event received, stop synchronization and repeat an          \
       * attempt later                                                        \
       */                                                                     \
      if (event_type == NL_EVENT_ERR)                                         \
	goto sync_later;                                                      \
    }                                                                         \
  while (!is_done);                                                           \
  nl_##fn##_sync_end ();

	    foreach_sock_type
#undef _

	      /* Start processing notifications */
	      nm->nl_status = NL_STATUS_NOTIF_PROC;

	  /* Trigger messages processing if there are notifications received
	   * during synchronization
	   */
	  wait_time = (vec_len (nm->nl_msg_queue) != 0) ? 1e-3 : DAY_F64;

	sync_later:
	  /* Close netlink synchronization sockets */
#define _(stype, mtype, tname, fn) lcp_nl_close_sync_socket (stype);
	  foreach_sock_type
#undef _
	}
      else
	NL_ERROR ("Unknown status: %d", nm->nl_status);
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

  return 0;
}

int
lcp_nl_drain_messages (void)
{
  int err;
  nl_main_t *nm = &nl_main;

  /* Read until there's an error */
  while ((err = nl_recvmsgs_default (nm->sk_route)) > -1)
    ;

  /* If there was an error other then EAGAIN, signal process node */
  if (err != -NLE_AGAIN)
    vlib_process_signal_event (vlib_get_main (), nl_route_process_node.index,
			       NL_EVENT_ERR, 0);
  else
    {
      /* If netlink notification processing is active, signal process node
       * there were notifications read
       */
      if (nm->nl_status == NL_STATUS_NOTIF_PROC)
	vlib_process_signal_event (
	  vlib_get_main (), nl_route_process_node.index, NL_EVENT_READ, 0);
    }

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

static void
lcp_nl_open_sync_socket (nl_sock_type_t sock_type)
{
  nl_main_t *nm = &nl_main;
  int dest_ns_fd, curr_ns_fd;
  struct nl_sock *sk_route;

  /* Allocate a new blocking socket for routes that will be used for dump
   * requests. Buffer sizes are left default because replies to dump requests
   * are flow-controlled and the kernel will not overflow the socket by sending
   * these
   */

  nm->sk_route_sync[sock_type] = sk_route = nl_socket_alloc ();

  dest_ns_fd = lcp_get_default_ns_fd ();
  if (dest_ns_fd > 0)
    {
      curr_ns_fd = clib_netns_open (NULL /* self */);
      if (clib_setns (dest_ns_fd) == -1)
	NL_ERROR ("Cannot set destination ns");
    }

  nl_connect (sk_route, NETLINK_ROUTE);

  if (dest_ns_fd > 0)
    {
      if (curr_ns_fd == -1)
	{
	  NL_ERROR ("No previous ns to set");
	}
      else
	{
	  if (clib_setns (curr_ns_fd) == -1)
	    NL_ERROR ("Cannot set previous ns");
	  close (curr_ns_fd);
	}
    }

  NL_INFO ("Opened netlink synchronization socket %d of type %d",
	   nl_socket_get_fd (sk_route), sock_type);
}

static void
lcp_nl_close_sync_socket (nl_sock_type_t sock_type)
{
  nl_main_t *nm = &nl_main;
  struct nl_sock *sk_route = nm->sk_route_sync[sock_type];

  if (sk_route)
    {
      NL_INFO ("Closing netlink synchronization socket %d of type %d",
	       nl_socket_get_fd (sk_route), sock_type);
      nl_socket_free (sk_route);
      nm->sk_route_sync[sock_type] = NULL;
    }
}

#include <vnet/plugin/plugin.h>
clib_error_t *
lcp_nl_init (vlib_main_t *vm)
{
  nl_main_t *nm = &nl_main;
  lcp_itf_pair_vft_t nl_itf_pair_vft = {
    .pair_add_fn = lcp_nl_pair_add_cb,
  };

  nm->nl_status = NL_STATUS_NOTIF_PROC;
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
