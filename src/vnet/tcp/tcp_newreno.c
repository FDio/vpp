/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <vnet/tcp/tcp.h>

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
  tc->cwnd = tc->ssthresh;
}

static void
newreno_rcv_ack (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  if (tcp_in_slowstart (tc))
    {
      tc->cwnd += clib_min (tc->snd_mss, tc->bytes_acked);
    }
  else
    {
      /* tc->cwnd += clib_max ((tc->snd_mss * tc->snd_mss) / tc->cwnd, 1); */
      tcp_cwnd_accumulate (tc, tc->cwnd, tc->bytes_acked);
    }
}

void
newreno_rcv_cong_ack (tcp_connection_t * tc, tcp_cc_ack_t ack_type,
		      tcp_rate_sample_t * rs)
{
  if (ack_type == TCP_CC_DUPACK)
    {
      if (!tcp_opts_sack_permitted (tc))
	tc->cwnd += tc->snd_mss;
    }
  else if (ack_type == TCP_CC_PARTIALACK)
    {
      /* RFC 6582 Sec. 3.2 */
      if (!tcp_opts_sack_permitted (&tc->rcv_opts))
	{
	  /* Deflate the congestion window by the amount of new data
	   * acknowledged by the Cumulative Acknowledgment field.
	   * If the partial ACK acknowledges at least one SMSS of new data,
	   * then add back SMSS bytes to the congestion window. This
	   * artificially inflates the congestion window in order to reflect
	   * the additional segment that has left the network. This "partial
	   * window deflation" attempts to ensure that, when fast recovery
	   * eventually ends, approximately ssthresh amount of data will be
	   * outstanding in the network.*/
	  tc->cwnd = (tc->cwnd > tc->bytes_acked + tc->snd_mss) ?
	    tc->cwnd - tc->bytes_acked : tc->snd_mss;
	  if (tc->bytes_acked > tc->snd_mss)
	    tc->cwnd += tc->snd_mss;
	}
    }
}

static void
newreno_conn_init (tcp_connection_t * tc)
{
  tc->ssthresh = newreno_cfg.ssthresh;
  tc->cwnd = tcp_initial_cwnd (tc);
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
  .rcv_cong_ack = newreno_rcv_cong_ack,
  .init = newreno_conn_init
};

clib_error_t *
newreno_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  tcp_cc_algo_register (TCP_CC_NEWRENO, &tcp_newreno);

  return error;
}

VLIB_INIT_FUNCTION (newreno_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
