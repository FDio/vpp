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

#ifndef SRC_VNET_TCP_TCP_CC_H_
#define SRC_VNET_TCP_TCP_CC_H_

#include <vnet/tcp/tcp_types.h>

always_inline void
tcp_cc_rcv_ack (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  tc->cc_algo->rcv_ack (tc, rs);
  tc->tsecr_last_ack = tc->rcv_opts.tsecr;
}

static inline void
tcp_cc_rcv_cong_ack (tcp_connection_t * tc, tcp_cc_ack_t ack_type,
		     tcp_rate_sample_t * rs)
{
  tc->cc_algo->rcv_cong_ack (tc, ack_type, rs);
}

static inline void
tcp_cc_congestion (tcp_connection_t * tc)
{
  tc->cc_algo->congestion (tc);
}

static inline void
tcp_cc_loss (tcp_connection_t * tc)
{
  tc->cc_algo->loss (tc);
}

static inline void
tcp_cc_recovered (tcp_connection_t * tc)
{
  tc->cc_algo->recovered (tc);
}

static inline void
tcp_cc_undo_recovery (tcp_connection_t * tc)
{
  if (tc->cc_algo->undo_recovery)
    tc->cc_algo->undo_recovery (tc);
}

static inline void
tcp_cc_event (tcp_connection_t * tc, tcp_cc_event_t evt)
{
  if (tc->cc_algo->event)
    tc->cc_algo->event (tc, evt);
}

static inline u64
tcp_cc_get_pacing_rate (tcp_connection_t * tc)
{
  if (tc->cc_algo->get_pacing_rate)
    return tc->cc_algo->get_pacing_rate (tc);

  f64 srtt = clib_min ((f64) tc->srtt * TCP_TICK, tc->mrtt_us);

  /* TODO should constrain to interface's max throughput but
   * we don't have link speeds for sw ifs ..*/
  return ((f64) tc->cwnd / srtt);
}

static inline void *
tcp_cc_data (tcp_connection_t * tc)
{
  return (void *) tc->cc_data;
}

/**
 * Register exiting cc algo type
 */
void tcp_cc_algo_register (tcp_cc_algorithm_type_e type,
			   const tcp_cc_algorithm_t * vft);

/**
 * Register new cc algo type
 */
tcp_cc_algorithm_type_e tcp_cc_algo_new_type (const tcp_cc_algorithm_t * vft);
tcp_cc_algorithm_t *tcp_cc_algo_get (tcp_cc_algorithm_type_e type);


void newreno_rcv_cong_ack (tcp_connection_t * tc, tcp_cc_ack_t ack_type,
			   tcp_rate_sample_t * rs);


#endif /* SRC_VNET_TCP_TCP_CC_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
