/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <math.h>

#define beta_cubic 	0.7
#define cubic_c		0.4
#define west_const 	(3 * (1 - beta_cubic) / (1 + beta_cubic))

typedef struct cubic_data_
{
  /** time period (in seconds) needed to increase the current window
   *  size to W_max if there are no further congestion events */
  f64 K;

  /** time (in sec) since the start of current congestion avoidance */
  f64 t_start;

  /** Inflection point of the cubic function */
  u32 w_max;

} __clib_packed cubic_data_t;

STATIC_ASSERT (sizeof (cubic_data_t) <= TCP_CC_DATA_SZ, "cubic data len");

static inline f64
cubic_time (u32 thread_index)
{
  return transport_time_now (thread_index);
}

/**
 * RFC 8312 Eq. 1
 *
 * CUBIC window increase function. Time and K need to be provided in seconds.
 */
static inline u64
W_cubic (cubic_data_t * cd, f64 t)
{
  f64 diff = t - cd->K;

  /* W_cubic(t) = C*(t-K)^3 + W_max */
  return cubic_c * diff * diff * diff + cd->w_max;
}

/**
 * RFC 8312 Eq. 2
 */
static inline f64
K_cubic (cubic_data_t * cd)
{
  /* K = cubic_root(W_max*(1-beta_cubic)/C) */
  return pow ((f64)cd->w_max * (1 - beta_cubic), 1 / 3.0);
}

/**
 * RFC 8312 Eq. 4
 *
 * Estimates the window size of AIMD(alpha_aimd, beta_aimd) for
 * alpha_aimd=3*(1-beta_cubic)/(1+beta_cubic) and beta_aimd=beta_cubic.
 * Time (t) and rtt should be provided in seconds
 */
static inline u32
W_est (cubic_data_t * cd, f64 t, f64 rtt)
{
  /* W_est(t) = W_max*beta_cubic+[3*(1-beta_cubic)/(1+beta_cubic)]*(t/RTT) */
  return cd->w_max * beta_cubic + west_const * (t / rtt);
}

static void
cubic_congestion (tcp_connection_t * tc)
{
  cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);

  cd->w_max = tc->cwnd;
  tc->ssthresh = clib_max (tc->cwnd * beta_cubic, 2 * tc->snd_mss);
}

static void
cubic_recovered (tcp_connection_t * tc)
{
  cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);
  cd->t_start = cubic_time (tc->c_thread_index);
  cd->K = K_cubic (cd);
  tc->cwnd = tc->ssthresh;
}

static void
cubic_rcv_ack (tcp_connection_t * tc)
{
  cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);
  u64 w_cubic, w_aimd;
  f64 t, rtt_sec;
  u32 wnd;

  /* Constrained by tx fifo, can't grow further */
  if (tc->cwnd >= transport_tx_fifo_size (&tc->connection))
    return;

  if (tcp_in_slowstart (tc))
    {
      tc->cwnd += clib_min (tc->snd_mss, tc->bytes_acked);
      return;
    }

  t = cubic_time (tc->c_thread_index) - cd->t_start;
  rtt_sec = clib_min (tc->mrtt_us, (f64) tc->srtt * TCP_TICK);

  w_cubic = W_cubic (cd, t + rtt_sec);
  w_aimd = W_est (cd, t, rtt_sec);
  if (w_cubic < w_aimd)
    {
      tcp_cwnd_accumulate (tc, tc->cwnd, tc->bytes_acked);
    }
  else
    {
      if (tc->cwnd > w_cubic)
	{
	  clib_warning ("cubic time %.5f start %.5f diff %.5f",
	                cubic_time (tc->c_thread_index), cd->t_start, t);
	  clib_warning ("cwnd %u cubic %u w_aimd %u", tc->cwnd, w_cubic, w_aimd);
	  os_panic();
	}
      wnd = w_cubic > tc->cwnd ? (tc->snd_mss * tc->cwnd) / (w_cubic - tc->cwnd) : 100 * tc->cwnd;
      wnd = clib_max (wnd, 2 * tc->snd_mss);
      tcp_cwnd_accumulate (tc, wnd, tc->bytes_acked);
    }
}

static void
cubic_conn_init (tcp_connection_t * tc)
{
  cubic_data_t *cd = (cubic_data_t *) tcp_cc_data (tc);
  tc->ssthresh = tc->snd_wnd;
  tc->cwnd = tcp_initial_cwnd (tc);
  cd->w_max = 0;
  cd->K = 0;
  cd->t_start = cubic_time (tc->c_thread_index);
}

const static tcp_cc_algorithm_t tcp_cubic = {
  .congestion = cubic_congestion,
  .recovered = cubic_recovered,
  .rcv_ack = cubic_rcv_ack,
  .rcv_cong_ack = newreno_rcv_cong_ack,
  .init = cubic_conn_init
};

clib_error_t *
cubic_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  tcp_cc_algo_register (TCP_CC_CUBIC, &tcp_cubic);

  return error;
}

VLIB_INIT_FUNCTION (cubic_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
