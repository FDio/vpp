
#include <vnet/dhcp/client6.h>
#include <vnet/dhcp/dhcp6_packet.h>

#define DHCP6_DEBUG(args...) do {} while (0)
//#define DHCP6_DEBUG(args...) clib_warning (args)

#define DHCP6_ERROR(args...) clib_warning (args)

dhcp6_client_main_t dhcp6_client_main;

ip6_address_t all_dhcp6_relay_agents_and_servers = {
    .as_u8 = {0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
              0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x02}
};

ip6_address_t link_local = { .as_u8 = {0xfe,0x80} };

struct {
  const char *s;
  u16 min_size;
} dhcpv6_options[DHCPV6_OPTION_MAX] =
    {
#define _(a,b,c) [b] = {.s = #a, .min_size = c },
        dhcpv6_foreach_option
#undef _
    };

#define EVENT_DHCP6_CLIENT_WAKEUP 1

#define SOL_TIMEOUT 1.0
#define SOL_MAX_RT 120.0

#define REQ_TIMEOUT 1.0
#define REQ_MAX_RT  20.0
#define REQ_MAX_RC  10

#define REN_TIMEOUT 10.0
#define REN_MAX_RT 600.0

#define DHCPV6_SOL_MAX_RT_MIN 60
#define DHCPV6_SOL_MAX_RT_MAX 86400
#define DHCPV6_INF_MAX_RT_MIN 60
#define DHCPV6_INF_MAX_RT_MAX 86400

u8 *
format_dhcpv6_opt_status_code (u8 * s, va_list * args)
{
  dhcpv6_status_t *o = va_arg (*args, dhcpv6_status_t *);
  u8 *c = 0;
  vec_validate(c, dhcpv6_optlen(&o->opt));
  memcpy(c, o->message, dhcpv6_optlen(&o->opt) - sizeof(o->status_code));
  c[dhcpv6_optlen(&o->opt) - sizeof(o->status_code)] = 0;
  s = format(s, "%s (%d)", c, o->status_code);
  vec_free(c);
  return s;
}

f64 dhcp6_retransmission_timer(f64 rt, f64 irt, f64 mrt)
{
  dhcp6_client_main_t * dcm = &dhcp6_client_main;
  if (rt == 0)
    rt = irt + random_f64(&dcm->seed) * irt;
  else
    rt = 2*rt + random_f64(&dcm->seed) * rt;

  if (rt > mrt)
    rt = mrt;

  return rt;
}

static int dhcp6_send_pkt (dhcp6_client_t * c,
                           dhcpv6_msg_type_t type)
{
  vlib_main_t * vm = vlib_get_main();
  vnet_main_t * vnm = vnet_get_main();
  vnet_hw_interface_t * hw = vnet_get_sup_hw_interface (vnm, c->sw_if_index);
  vnet_sw_interface_t * sup_sw = vnet_get_sup_sw_interface (vnm, c->sw_if_index);
  vnet_sw_interface_t * sw = vnet_get_sw_interface (vnm, c->sw_if_index);
  vlib_buffer_t * b;
  u32 bi;
  ip6_header_t * ip;
  udp_header_t * udp;
  dhcpv6_header_t * dhcp;
  ip6_address_t *src_addr;
  u32 dhcp_opt_len = 0;
  int bogus_length = 0;
  f64 now = vlib_time_now(vm);

  /* Interface(s) down? */
  if ((hw->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    return 1;
  if ((sup_sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    return 1;
  if ((sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    return 1;

  /* Get a link-local address */
  src_addr = ip6_interface_get_link_local_address (&ip6_main,
                                                   &link_local,
                                                   c->sw_if_index,
                                                   NULL);

  if (!src_addr)
    {
      DHCP6_ERROR("Could not find source address to send DHCPv6 packet");
      return 1;
    }

  if (vlib_buffer_alloc (vm, &bi, 1) != 1) {
      DHCP6_ERROR("Buffer allocation failed");
      return 1;
  }

  b = vlib_get_buffer (vm, bi);
  vnet_buffer(b)->sw_if_index[VLIB_RX] = c->sw_if_index;
  vnet_buffer(b)->sw_if_index[VLIB_TX] = c->sw_if_index;

  ip = (ip6_header_t *)vlib_buffer_get_current (b);
  udp = (udp_header_t *)(ip + 1);
  dhcp = (dhcpv6_header_t *)(udp + 1);

  ip->src_address = *src_addr;
  ip->hop_limit = 255;
  ip->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6<<28);
  ip->payload_length = 0;
  ip->protocol = IP_PROTOCOL_UDP;

  udp->src_port = clib_host_to_net_u16(DHCPV6_CLIENT_PORT);
  udp->dst_port = clib_host_to_net_u16(DHCPV6_SERVER_PORT);
  udp->checksum = 0;
  udp->length = 0;

  dhcp->msg_type = type;
  dhcp->xid[0] = (c->transaction_id & 0x00ff0000) >> 16;
  dhcp->xid[1] = (c->transaction_id & 0x0000ff00) >> 8;
  dhcp->xid[2] = (c->transaction_id & 0x000000ff) >> 0;

  void *d = (void *) dhcp->data;
  dhcpv6_option_t *duid;
  dhcpv6_elapsed_t *elapsed;
  dhcpv6_ia_header_t *ia_hdr;
  dhcpv6_ia_opt_pd_t *pd;
  if (type == DHCPV6_MSG_SOLICIT)
    {
      duid = (dhcpv6_option_t *)d;
      duid->option = clib_host_to_net_u16(DHCPV6_OPTION_CLIENTID);
      duid->length = clib_host_to_net_u16(c->duid_length);
      clib_memcpy(duid + 1, c->duid, c->duid_length);
      d += sizeof(*duid) + c->duid_length;

      elapsed = (dhcpv6_elapsed_t *)d;
      elapsed->opt.option = clib_host_to_net_u16(DHCPV6_OPTION_ELAPSED_TIME);
      elapsed->opt.length = clib_host_to_net_u16(sizeof(*elapsed) - sizeof(elapsed->opt));
      elapsed->elapsed_10ms = clib_host_to_net_u16((u16)((now - c->transaction_start)*100));
      d += sizeof(*elapsed);

      ia_hdr = (dhcpv6_ia_header_t *)d;
      ia_hdr->opt.option = clib_host_to_net_u16(DHCPV6_OPTION_IA_PD);
      ia_hdr->opt.length = clib_host_to_net_u16(sizeof(*ia_hdr) + sizeof(*pd) - sizeof(ia_hdr->opt));
      ia_hdr->iaid = 1;
      ia_hdr->t1 = 0;
      ia_hdr->t2 = 0;
      d += sizeof(*ia_hdr);

      pd = (dhcpv6_ia_opt_pd_t *)d;
      pd->opt.option = clib_host_to_net_u16(DHCPV6_OPTION_IAPREFIX);
      pd->opt.length = clib_host_to_net_u16(sizeof(*pd) - sizeof(pd->opt));
      pd->prefix = 56;
      pd->valid = 0;
      pd->preferred = 0;
      d += sizeof(*pd);
    }
  else if (type == DHCPV6_MSG_REQUEST || type == DHCPV6_MSG_RENEW)
    {
      duid = (dhcpv6_option_t *)d;
      duid->option = clib_host_to_net_u16(DHCPV6_OPTION_CLIENTID);
      duid->length = clib_host_to_net_u16(c->duid_length);
      clib_memcpy(duid + 1, c->duid, c->duid_length);
      d += sizeof(*duid) + c->duid_length;

      memcpy(d, &c->opt_server_duid, sizeof(c->opt_server_duid));
      d += sizeof(c->opt_server_duid);
      memcpy(d, c->opt_server_duid_data, vec_len(c->opt_server_duid_data));
      d += vec_len(c->opt_server_duid_data);

      memcpy(d, &c->opt_ia_pd, sizeof(c->opt_ia_pd));
      ((dhcpv6_ia_header_t *)d)->t1 = 0;
      ((dhcpv6_ia_header_t *)d)->t2 = 0;
      d += sizeof(c->opt_ia_pd);

      memcpy(d, &c->opt_iaprefix, sizeof(c->opt_iaprefix));
      ((dhcpv6_ia_opt_pd_t *)d)->preferred = 0;
      ((dhcpv6_ia_opt_pd_t *)d)->valid = 0;
      d += sizeof(c->opt_iaprefix);

      elapsed = (dhcpv6_elapsed_t *)d;
      elapsed->opt.option = clib_host_to_net_u16(DHCPV6_OPTION_ELAPSED_TIME);
      elapsed->opt.length = clib_host_to_net_u16(sizeof(*elapsed) - sizeof(elapsed->opt));
      elapsed->elapsed_10ms = clib_host_to_net_u16((u16)((now - c->transaction_start)*100));
      d += sizeof(*elapsed);
    }
  else
    {
      DHCP6_ERROR("State not implemented");
    }

  dhcp_opt_len = ((u8 *)d) - dhcp->data;
  udp->length = clib_host_to_net_u16(sizeof(*udp) + sizeof(*dhcp) + dhcp_opt_len);
  ip->payload_length = udp->length;
  b->current_length = sizeof(*ip) + sizeof(*udp) + sizeof(*dhcp) + dhcp_opt_len;

  ip->dst_address = all_dhcp6_relay_agents_and_servers;
  clib_memcpy (((char *) ip) - vec_len(c->l2_rewrite),
               c->l2_rewrite, vec_len(c->l2_rewrite));
  vlib_buffer_advance (b, - ((int)vec_len(c->l2_rewrite)));

  udp->checksum =
      ip6_tcp_udp_icmp_compute_checksum (vm, 0, ip, &bogus_length);

  {
    vlib_frame_t *f = vlib_get_frame_to_node (vm, hw->output_node_index);
    u32 *to_next = vlib_frame_vector_args (f);
    to_next[0] = bi;
    f->n_vectors = 1;
    vlib_put_frame_to_node (vm, hw->output_node_index, f);
  }

  return 0;
}

static int
dhcp6_solicit_state (dhcp6_client_t * c, f64 now)
{
  dhcp6_send_pkt (c, DHCPV6_MSG_SOLICIT);

  c->retransmission_timer =
      dhcp6_retransmission_timer(c->retransmission_timer,
                                 SOL_TIMEOUT, SOL_MAX_RT);
  c->next_transmit = now + c->retransmission_timer;
  return 0;
}

static int
dhcp6_request_state (dhcp6_client_t * c, f64 now)
{
  if (now >= c->last_state_time + clib_net_to_host_u32(c->opt_ia_pd.t2))
    {
      DHCP6_DEBUG("T2 timeout: Back to discovery state");
      c->state = DHCP6_SOLICIT;
      c->retransmission_timer = 0;
      dhcp6_solicit_state(c, now);
      return 0;
    }

  dhcp6_send_pkt (c, DHCPV6_MSG_REQUEST);

  c->retransmission_timer =
      dhcp6_retransmission_timer(c->retransmission_timer,
                                 REQ_TIMEOUT, REQ_MAX_RT);
  c->next_transmit = now + c->retransmission_timer;

  if (c->next_transmit > c->last_state_time +
      clib_net_to_host_u32(c->opt_ia_pd.t2))
    c->next_transmit = c->last_state_time +
    clib_net_to_host_u32(c->opt_ia_pd.t2) + 0.1;
  return 0;
}

static int
dhcp6_bound_state (dhcp6_client_t * c, f64 now)
{
  if (now >= c->last_state_time + clib_net_to_host_u32(c->opt_ia_pd.t2))
    {
      DHCP6_DEBUG("T2 timeout: Back to discovery state");
      c->state = DHCP6_SOLICIT;
      c->retransmission_timer = 0;
      dhcp6_solicit_state(c, now);
      return 0;
    }

  dhcp6_send_pkt (c, DHCPV6_MSG_RENEW);

  c->retransmission_timer =
      dhcp6_retransmission_timer(c->retransmission_timer,
                                 REN_TIMEOUT, REN_MAX_RT);
  c->next_transmit = now + c->retransmission_timer;

  if (c->next_transmit > c->last_state_time +
      clib_net_to_host_u32(c->opt_ia_pd.t2))
    c->next_transmit = c->last_state_time +
    clib_net_to_host_u32(c->opt_ia_pd.t2) + 0.1;

  return 0;
}

static f64 dhcp6_client_sm (f64 now, f64 timeout, uword pool_index)
{
  DHCP6_DEBUG("dhcpv6 state machine for client %d ", pool_index);
  dhcp6_client_main_t * dcm = &dhcp6_client_main;
  dhcp6_client_t * c;

  if (pool_is_free_index (dcm->clients, pool_index))
    return timeout;

  c = pool_elt_at_index (dcm->clients, pool_index);

  if (now < c->next_transmit)
    goto end;

  again:
  switch (c->state)
  {
    case DHCP6_SOLICIT:         /* send a discover */
      if (dhcp6_solicit_state (c, now))
        goto again;
      break;

    case DHCP6_REQUEST:          /* send a request */
      if (dhcp6_request_state (c, now))
        goto again;
      break;

    case DHCP6_BOUND:            /* bound, renew needed? */
      if (dhcp6_bound_state (c, now))
        goto again;
      break;

    default:
      DHCP6_ERROR("dhcp client %d bogus state %d",
                  c - dcm->clients, c->state);
      break;
  }

  end:
  return (c->next_transmit - now < timeout)?c->next_transmit - now:timeout;
}

static uword
dhcp6_client_process (vlib_main_t * vm,
                      vlib_node_runtime_t * rt,
                      vlib_frame_t * f)
{
  f64 timeout = 100.0;
  f64 now;
  uword event_type;
  uword * event_data = 0;
  dhcp6_client_main_t * dcm = &dhcp6_client_main;
  dhcp6_client_t * c;
  int i;

  while (1)
    {
      timeout = vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, &event_data);

      now = vlib_time_now (vm);

      switch (event_type)
      {
        case EVENT_DHCP6_CLIENT_WAKEUP:
          vec_foreach_index(i, event_data)
          {
            timeout = dhcp6_client_sm (now, timeout, event_data[i]);
          }
          break;
        case ~0:
        timeout = 100.0;
        pool_foreach (c, dcm->clients,
                      ({
          timeout = dhcp6_client_sm (now, timeout,
                                     (uword)(c - dcm->clients));
        }));
        break;
      }

      vec_reset_length (event_data);
    }

  /* NOTREACHED */
  return 0;
}

VLIB_REGISTER_NODE (dhcp6_client_process_node,static) = {
    .function = dhcp6_client_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "dhcp6-client-process",
    .process_log2_n_stack_bytes = 16,
};

int dhcp6_parse_options(u8 *b, u32 len,
                        void **options[DHCPV6_OPTION_MAX])
{
  dhcpv6_option_t *o;
  for (int i=0; i<DHCPV6_OPTION_MAX; i++)
    options[i] = 0;

  o = (dhcpv6_option_t *)b;
  while (len)
    {
      if (len < sizeof(dhcpv6_option_t))
        return -1;

      u16 opt_id = clib_net_to_host_u16(o->option);
      u16 opt_len = clib_net_to_host_u16(o->length);

      if (opt_id >= DHCPV6_OPTION_MAX)
        return -2;
      else if (opt_len + sizeof(*o) > len)
        {
          DHCP6_ERROR("Found option %s (%d): Overflow",
                      dhcpv6_options[opt_id].s, opt_id);
          return -3;
        }
      else if (opt_len < dhcpv6_options[opt_id].min_size)
        {
          DHCP6_ERROR("Found option %s (%d): Too small",
                      dhcpv6_options[opt_id].s, opt_id);
          return -4;
        }
      else
        {
          DHCP6_DEBUG("Found option %s (%d)",
                      dhcpv6_options[opt_id].s, opt_id);
          vec_add1(options[opt_id], o);
        }
      len -= opt_len + sizeof(*o);
      o = (dhcpv6_option_t *) (((u8 *)o) + opt_len + sizeof(*o));
    }

  return 0;
}

void dhcp6_parse_options_free(void **options[DHCPV6_OPTION_MAX])
{
  for (int i=0; i<DHCPV6_OPTION_MAX; i++)
    vec_free(options[i]);
}

void dhcp6_client_for_us_state_solicit (vlib_main_t *vm,
                                        dhcp6_client_t * c,
                                        dhcpv6_header_t *dhcpv6_hdr,
                                        void **options[DHCPV6_OPTION_MAX])
{
  dhcp6_client_main_t * dcm = &dhcp6_client_main;
  if (dhcpv6_hdr->msg_type != DHCPV6_MSG_ADVERTISE)
    {
      DHCP6_DEBUG("Ignoring non advertise message while in solicit state");
      return;
    }

  if (!vec_len(options[DHCPV6_OPTION_IA_PD]))
    {
      DHCP6_ERROR("Ignore message with no PD offer");
      return;
    }

  dhcpv6_ia_header_t *ia = options[DHCPV6_OPTION_IA_PD][0];
  void **ia_options[DHCPV6_OPTION_MAX];
  if (dhcp6_parse_options((u8 *)(ia + 1),
                          clib_net_to_host_u16(ia->opt.length) +
                          sizeof(ia->opt) - sizeof(*ia), ia_options))
    {
      DHCP6_ERROR("Error parsing DHCP ia pd options");
      return;
    }

  if (vec_len(ia_options[DHCPV6_OPTION_STATUS_CODE]))
    {
      DHCP6_ERROR("Status code in PD option: %U",
                  format_dhcpv6_opt_status_code,
                  (dhcpv6_status_t *)ia_options[DHCPV6_OPTION_STATUS_CODE][0]);
      goto end;
    }

  if (vec_len(ia_options[DHCPV6_OPTION_IAPREFIX]))
    {
      memcpy(&c->opt_iaprefix,
             ia_options[DHCPV6_OPTION_IAPREFIX][0],
             sizeof(c->opt_iaprefix));
      memcpy(&c->opt_ia_pd,
             options[DHCPV6_OPTION_IA_PD][0],
             sizeof(c->opt_ia_pd));
      memcpy(&c->opt_server_duid,
             options[DHCPV6_OPTION_SERVERID][0],
             sizeof(c->opt_server_duid));

      dhcpv6_duid_t *duid =
          (dhcpv6_duid_t *) options[DHCPV6_OPTION_SERVERID][0];
      vec_reset_length(c->opt_server_duid_data);
      vec_add(c->opt_server_duid_data, duid->id,
              clib_net_to_host_u16(duid->opt.length) -
              sizeof(*duid) + sizeof(dhcpv6_option_t));

      /* Switch to request state */
      c->last_state_time = vlib_time_now(vm);
      c->state = DHCP6_REQUEST;
      c->retransmission_timer =
          dhcp6_retransmission_timer(0, REQ_TIMEOUT, REQ_MAX_RT);
      c->next_transmit = vlib_time_now(vm) + c->retransmission_timer;
      vlib_process_signal_event (vm, dhcp6_client_process_node.index,
                                 EVENT_DHCP6_CLIENT_WAKEUP, c - dcm->clients);
    }

  end:
  dhcp6_parse_options_free(ia_options);
}

void dhcp6_client_for_us_state_request (vlib_main_t *vm,
                                        dhcp6_client_t * c,
                                        dhcpv6_header_t *dhcpv6_hdr,
                                        void **options[DHCPV6_OPTION_MAX])
{
  dhcp6_client_main_t * dcm = &dhcp6_client_main;
  if (dhcpv6_hdr->msg_type != DHCPV6_MSG_REPLY)
    {
      DHCP6_ERROR("Ignoring non reply message while in request state");
      return;
    }

  if (!vec_len(options[DHCPV6_OPTION_IA_PD]))
    {
      DHCP6_ERROR("Error: Reply with no PD offer");
      return;
    }

  dhcpv6_ia_header_t *ia = options[DHCPV6_OPTION_IA_PD][0];
  void **ia_options[DHCPV6_OPTION_MAX];
  if (dhcp6_parse_options((u8 *)(ia + 1),
                          clib_net_to_host_u16(ia->opt.length) +
                          sizeof(ia->opt) - sizeof(*ia), ia_options))
    {
      DHCP6_ERROR("Error parsing DHCP ia pd options");
      return;
    }

  if (vec_len(ia_options[DHCPV6_OPTION_STATUS_CODE]))
    {
      DHCP6_ERROR("Status code in PD option: %U",
                  format_dhcpv6_opt_status_code,
                  (dhcpv6_status_t *)ia_options[DHCPV6_OPTION_STATUS_CODE][0]);
      goto end;
    }

  if (vec_len(ia_options[DHCPV6_OPTION_IAPREFIX]))
    {
      memcpy(&c->opt_iaprefix,
             ia_options[DHCPV6_OPTION_IAPREFIX][0],
             sizeof(c->opt_iaprefix));
      memcpy(&c->opt_ia_pd,
             options[DHCPV6_OPTION_IA_PD][0],
             sizeof(c->opt_ia_pd));
      memcpy(&c->opt_server_duid,
             options[DHCPV6_OPTION_SERVERID][0],
             sizeof(c->opt_server_duid));

      dhcpv6_duid_t *duid =
          (dhcpv6_duid_t *) options[DHCPV6_OPTION_SERVERID][0];
      vec_reset_length(c->opt_server_duid_data);
      vec_add(c->opt_server_duid_data, duid->id,
              clib_net_to_host_u16(duid->opt.length) -
              sizeof(*duid) + sizeof(dhcpv6_option_t));

      /* Switch to request state */
      c->last_state_time = vlib_time_now(vm);
      c->state = DHCP6_BOUND;
      c->retransmission_timer = 0;
      c->next_transmit = vlib_time_now(vm) + clib_net_to_host_u32(c->opt_ia_pd.t1);
      vlib_process_signal_event (vm, dhcp6_client_process_node.index,
                                 EVENT_DHCP6_CLIENT_WAKEUP, c - dcm->clients);

      DHCP6_DEBUG("Obtained lease %U/%d lifetime %u:%u",
                  format_ip6_address, &c->opt_iaprefix.addr,
                  c->opt_iaprefix.prefix,
                  clib_net_to_host_u32(c->opt_iaprefix.preferred),
                  clib_net_to_host_u32(c->opt_iaprefix.valid));
    }

  end:
  dhcp6_parse_options_free(ia_options);
}

void dhcp6_client_for_us_state_bound (vlib_main_t *vm,
                                      dhcp6_client_t * c,
                                      dhcpv6_header_t *dhcpv6_hdr,
                                      void **options[DHCPV6_OPTION_MAX])
{
  if (dhcpv6_hdr->msg_type != DHCPV6_MSG_REPLY)
    {
      DHCP6_DEBUG("Ignoring non reply message while in bound state");
      return;
    }

  dhcp6_client_for_us_state_request(vm, c, dhcpv6_hdr, options);
}

int dhcp6_client_for_us (vlib_main_t *vm, u32 bi)
{
  dhcp6_client_main_t * dcm = &dhcp6_client_main;
  vlib_buffer_t *b = vlib_get_buffer(vm, bi);
  dhcpv6_header_t *dhcpv6_hdr = vlib_buffer_get_current(b);
  dhcp6_client_t * c;
  uword * p;

  if (b->current_length < sizeof(*dhcpv6_hdr))
    {
      DHCP6_ERROR("Missing DHCP header");
      return 1;
    }

  p = hash_get (dcm->client_by_sw_if_index,
                vnet_buffer(b)->sw_if_index [VLIB_RX]);
  if (p == 0)
    return 0;

  c = pool_elt_at_index (dcm->clients, p[0]);

  if (dhcpv6_hdr->xid[0] != ((c->transaction_id & 0x00ff0000) >> 16) ||
      dhcpv6_hdr->xid[1] != ((c->transaction_id & 0x0000ff00) >> 8) ||
      dhcpv6_hdr->xid[2] != ((c->transaction_id & 0x000000ff) >> 0))
    return 0;

  void **options[DHCPV6_OPTION_MAX];
  if (dhcp6_parse_options(dhcpv6_hdr->data,
                          b->current_length - sizeof(*dhcpv6_hdr), options))
    {
      DHCP6_ERROR("Error parsing DHCP main level options");
      vlib_buffer_free (vm, &bi, 1);
      return 1;
    }

  if (!vec_len(options[DHCPV6_OPTION_SERVERID]))
    {
      DHCP6_ERROR("Ignore message with no PD offer");
      goto end;
    }

  switch (c->state) {
    case DHCP6_SOLICIT:
      dhcp6_client_for_us_state_solicit(vm, c, dhcpv6_hdr, options);
      break;
    case DHCP6_REQUEST:
      dhcp6_client_for_us_state_request(vm, c, dhcpv6_hdr, options);
      break;
    case DHCP6_BOUND:
      dhcp6_client_for_us_state_bound(vm, c, dhcpv6_hdr, options);
      break;
    default:
      break;
  }

  end:
  dhcp6_parse_options_free(options);
  vlib_buffer_free (vm, &bi, 1);
  return 1;
}

int dhcp6_client_add_del (dhcp6_client_add_del_args_t * a)
{
  dhcp6_client_main_t * dcm = &dhcp6_client_main;
  vlib_main_t * vm = vlib_get_main();
  dhcp6_client_t * c;
  uword * p;

  p = hash_get (dcm->client_by_sw_if_index, a->sw_if_index);

  if ((p && a->is_add) || (!p && a->is_add == 0))
    return VNET_API_ERROR_INVALID_VALUE;

  if (a->duid_length > DHCPV6_DUID_MAX_LEN)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (a->is_add)
    {
      pool_get (dcm->clients, c);
      memset (c, 0, sizeof (*c));
      c->state = DHCP6_SOLICIT;
      c->sw_if_index = a->sw_if_index;
      c->duid_length = a->duid_length;
      memcpy(c->duid, a->duid, a->duid_length);
      c->transaction_id = random_u32(&dcm->seed) & 0x00ffffff;
      c->retransmission_timer =
          dhcp6_retransmission_timer(0, SOL_TIMEOUT, SOL_MAX_RT);
      c->next_transmit = vlib_time_now(vm) + c->retransmission_timer;
      c->transaction_start = vlib_time_now(vm);

      c->l2_rewrite = vnet_build_rewrite_for_sw_interface(
          vnet_get_main(),
          c->sw_if_index,
          VNET_LINK_IP6,
          0 /* broadcast */);

      if (c->duid_length == 0)
        {
          /* duid type */
          *((u16 *)&c->duid[0]) = clib_host_to_net_u16(3);

          /* duid hardware type */
          *((u16 *)&c->duid[2]) = clib_host_to_net_u16(1);

          ip6_address_t *ll_address =
              ip6_interface_get_link_local_address (&ip6_main,
                                                    &link_local,
                                                    c->sw_if_index,
                                                    NULL);
          memcpy(&c->duid[4], ll_address, sizeof(*ll_address));
          c->duid_length = 20;
        }

      hash_set (dcm->client_by_sw_if_index, a->sw_if_index, c - dcm->clients);

      ip6_sw_interface_enable_disable (c->sw_if_index, 1);

      vlib_process_signal_event (vm, dhcp6_client_process_node.index,
                                 EVENT_DHCP6_CLIENT_WAKEUP, c - dcm->clients);
    }
  else
    {
      c = pool_elt_at_index (dcm->clients, p[0]);
      ip6_sw_interface_enable_disable (c->sw_if_index, 0);
      vec_free (c->l2_rewrite);
      hash_unset (dcm->client_by_sw_if_index, c->sw_if_index);
      pool_put (dcm->clients, c);
    }
  return 0;
}

static clib_error_t *
dhcpv6_client_set_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main();
  u32 sw_if_index = ~0;
  u8 * duid = 0;
  int is_add = 1;
  dhcp6_client_add_del_args_t _a, *a = &_a;
  int rv;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "iface %U",
                    unformat_vnet_sw_interface, vnm,
                    &sw_if_index))
        ;
      else if (unformat (input, "duid %U", unformat_hex_string, &duid))
        ;
      else if (unformat (input, "del"))
        is_add = 0;
      else
        break;
    }

  if (vec_len(duid) > DHCPV6_DUID_MAX_LEN)
    {
      vec_free(duid);
      return clib_error_return (0, "DUID too long");
    }

  memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->sw_if_index = sw_if_index;
  a->duid_length = vec_len(duid);
  memcpy(a->duid, duid, vec_len(duid));
  vec_free(duid);

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface not specified");

  if ((rv = dhcp6_client_add_del (a)))
    return clib_error_return (0, "dhcp6_client_add_del returned %d", rv);

  return 0;
}

VLIB_CLI_COMMAND (dhcp6_client_set_command, static) = {
    .path = "set dhcpv6 client",
    .short_help = "set dhcpv6 client [del] iface <interface> [hostname <name>]",
    .function = dhcpv6_client_set_command_fn,
};

static u8 * format_dhcp6_client_state (u8 * s, va_list * va)
{
  dhcp6_client_state_t state = va_arg (*va, dhcp6_client_state_t);
  char * str = "BOGUS!";

  switch (state)
  {
#define _(a)                                    \
    case a:                                     \
    str = #a;                                 \
    break;
    foreach_dhcp6_client_state;
#undef _
    default:
      break;
  }

  s = format (s, "%s", str);
  return s;
}

static u8 * format_dhcp6_client (u8 * s, va_list * va)
{
  dhcp6_client_main_t * dcm = &dhcp6_client_main;
  dhcp6_client_t * c = va_arg (*va, dhcp6_client_t *);
  int verbose = va_arg (*va, int);
  f64 now = vlib_time_now(vlib_get_main());

  s = format (s, "[%d] %U %U", c - dcm->clients,
              format_vnet_sw_if_index_name, vnet_get_main(), c->sw_if_index,
              format_dhcp6_client_state, c->state);

  if (c->state == DHCP6_BOUND)
    {
      u32 age = now - c->last_state_time;
      s = format(s, " %U/%d %ld/%ld",
                 format_ip6_address, &c->opt_iaprefix.addr,
                 (int) c->opt_iaprefix.prefix, ((i64)clib_net_to_host_u32(c->opt_iaprefix.preferred)) - age,
                 ((i64)clib_net_to_host_u32(c->opt_iaprefix.valid)) - age);
    }

  if (verbose)
    {
      s = format (s, "\n   duid: %U", format_hex_bytes, c->duid, c->duid_length);
      s = format (s, "\n   transaction-id: %x", c->transaction_id);
      s = format (s, "\n   next-transmission: %ds", (int) (c->next_transmit - now));
      if (c->state == DHCP6_BOUND)
        {
          s = format(s, "\n   t1:%d t2:%d",
                     clib_net_to_host_u32(c->opt_ia_pd.t1),
                     clib_net_to_host_u32(c->opt_ia_pd.t2));
        }
    }
  return s;
}

static clib_error_t *
show_dhcp6_client_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  dhcp6_client_main_t * dcm = &dhcp6_client_main;
  dhcp6_client_t * c;
  int verbose = 0;
  u32 sw_if_index = ~0;
  uword * p;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "intfc %U",
                    unformat_vnet_sw_interface, vnet_get_main(),
                    &sw_if_index))
        ;
      else if (unformat (input, "verbose"))
        verbose = 1;
      else
        break;
    }

  if (sw_if_index != ~0)
    {
      p = hash_get (dcm->client_by_sw_if_index, sw_if_index);
      if (p == 0)
        return clib_error_return (0, "dhcpv6 client not configured");
      c = pool_elt_at_index (dcm->clients, p[0]);
      vlib_cli_output (vm, "%U", format_dhcp6_client, c, verbose);
      return 0;
    }

  pool_foreach (c, dcm->clients,
                ({
    vlib_cli_output (vm, "%U", format_dhcp6_client, c, verbose);
  }));

  return 0;
}

VLIB_CLI_COMMAND (show_dhcp6_client_command, static) = {
    .path = "show dhcpv6 client",
    .short_help = "show dhcpv6 client [intfc <intfc>][verbose]",
    .function = show_dhcp6_client_command_fn,
};

static clib_error_t *
dhcp6_client_init (vlib_main_t * vm)
{
  dhcp6_client_main_t * dcm = &dhcp6_client_main;
  dcm->seed = 0xdeaddabe;
  return 0;
}

VLIB_INIT_FUNCTION (dhcp6_client_init);
