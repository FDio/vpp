/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>

typedef struct nwreno_cfg_
{
  u32 ssthresh;
} newreno_cfg_t;

static newreno_cfg_t newreno_cfg = {
  .ssthresh = 0x7FFFFFFFU,
};

static void
newreno_congestion (tcp_connection_t * tc)
{
  tc->ssthresh = clib_max (tcp_flight_size (tc) / 2, 2 * tc->snd_mss);
  tc->cwnd = tc->ssthresh;
}

static void
newreno_loss (tcp_connection_t * tc)
{
  tc->cwnd = tcp_loss_wnd (tc);
}

static void
newreno_recovered (tcp_connection_t * tc)
{
  if (tcp_in_recovery (tc))
    return;

  tc->cwnd = tc->ssthresh;
}

static void
newreno_rcv_ack (tcp_connection_t *tc, tcp_ack_ctx_t *ac)
{
  if (!tcp_cc_is_cwnd_limited (tc, ac))
    return;

  if (tcp_in_slowstart (tc))
    {
      tc->cwnd += clib_min (tc->snd_mss, ac->acked_and_sacked);
    }
  else
    {
      /* tc->cwnd += clib_max ((tc->snd_mss * tc->snd_mss) / tc->cwnd, 1); */
      tcp_cwnd_accumulate (tc, tc->cwnd, ac->acked_and_sacked);
    }
}

static int
newreno_conn_init (tcp_connection_t *tc)
{
  tc->ssthresh = newreno_cfg.ssthresh;
  tc->cwnd = tcp_initial_cwnd (tc);
  return 0;
}

static uword
newreno_unformat_config (unformat_input_t * input)
{
  u32 ssthresh = 0x7FFFFFFFU;

  if (!input)
    return 0;

  unformat_skip_white_space (input);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ssthresh %u", &ssthresh))
	newreno_cfg.ssthresh = ssthresh;
      else
	return 0;
    }
  return 1;
}

const static tcp_cc_algorithm_t tcp_newreno = {
  .name = "newreno",
  .unformat_cfg = newreno_unformat_config,
  .congestion = newreno_congestion,
  .loss = newreno_loss,
  .recovered = newreno_recovered,
  .rcv_ack = newreno_rcv_ack,
  .init = newreno_conn_init,
};

clib_error_t *
newreno_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  tcp_cc_algo_register (TCP_CC_NEWRENO, &tcp_newreno);

  return error;
}

VLIB_INIT_FUNCTION (newreno_init);
