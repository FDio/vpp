/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <hs_apps/builtin_echo/echo_stats.h>
#include <vnet/tcp/tcp_types.h>

static inline void
echo_update_rtt_stats (f64 session_rtt, echo_rtt_stat_t *rtt_stats)
{
  clib_spinlock_lock (&rtt_stats->w_lock);
  rtt_stats->last_rtt = session_rtt;
  rtt_stats->sum_rtt += session_rtt;
  rtt_stats->n_sum++;
  if (session_rtt < rtt_stats->min_rtt)
    rtt_stats->min_rtt = session_rtt;
  if (session_rtt > rtt_stats->max_rtt)
    rtt_stats->max_rtt = session_rtt;
  clib_spinlock_unlock (&rtt_stats->w_lock);
}

void
echo_update_rtt_stats_tcp (echo_test_session_t *es, echo_rtt_stat_t *rtt_stats)
{
  session_t *s = session_get_from_handle_if_valid (es->vpp_session_handle);
  if (s)
    {
      transport_connection_t *tc;
      tcp_connection_t *tcpc;
      tc = transport_get_connection (TRANSPORT_PROTO_TCP, s->connection_index, s->thread_index);
      if (PREDICT_TRUE (tc != NULL))
	{
	  tcpc = tcp_get_connection_from_transport (tc);
	  echo_update_rtt_stats (tcpc->srtt * TCP_TICK, rtt_stats);
	}
    }
}

void
echo_update_rtt_stats_udp (echo_test_session_t *es, echo_rtt_stat_t *rtt_stats)
{
  echo_update_rtt_stats (es->rtt, rtt_stats);
}

#define ECHO_SEPARATOR "-------------------------------------------------------------"

#define ECHO_SEPARATOR_UDP                                                                         \
  "------------------------------------------------------------------------------------"

void
echo_print_footer (vlib_main_t *vm, transport_proto_t proto)
{
  if (proto == TRANSPORT_PROTO_UDP)
    echo_cli (ECHO_SEPARATOR_UDP);
  else
    echo_cli (ECHO_SEPARATOR);
}

void
echo_print_periodic_stats (vlib_main_t *vm, u8 print_header, echo_test_cfg_t *cfg,
			   echo_stats_t *stats, echo_test_worker_t *wrks)
{
  f64 time_now, print_delta, interval_start, interval_end, rtt = 0.0, jitter = 0.0;
  u64 total_bytes, received_bytes = 0, sent_bytes = 0, dgrams_sent = 0, dgrams_received = 0,
		   last_total_bytes = stats->last_total_tx_bytes + stats->last_total_rx_bytes;
  echo_test_worker_t *wrk;
  echo_test_session_t *sess;
  vec_foreach (wrk, wrks)
    {
      pool_foreach (sess, wrk->sessions)
	{
	  received_bytes += sess->bytes_received;
	  sent_bytes += sess->bytes_sent;
	  if (cfg->proto == TRANSPORT_PROTO_UDP)
	    {
	      echo_update_rtt_stats_udp (sess, &stats->rtt_stats);
	      dgrams_received += sess->dgrams_received;
	      dgrams_sent += sess->dgrams_sent;
	      sess->rtt_stat = 0;
	      jitter += sess->jitter;
	    }
	  else if (cfg->proto == TRANSPORT_PROTO_TCP)
	    {
	      session_t *s = session_get_from_handle_if_valid (sess->vpp_session_handle);
	      if (s)
		{
		  echo_update_rtt_stats_tcp (sess, &stats->rtt_stats);
		  rtt += stats->rtt_stats.last_rtt;
		}
	    }
	}
    }
  time_now = vlib_time_now (vm);
  interval_end = time_now - stats->test_start_time;
  interval_start = stats->last_print_time - stats->test_start_time;
  total_bytes = received_bytes + sent_bytes;
  print_delta = time_now - stats->last_print_time;

  if (cfg->proto == TRANSPORT_PROTO_UDP)
    {
      jitter /= cfg->n_clients;
      rtt = stats->rtt_stats.last_rtt * 1000;
      if (print_header)
	{
	  echo_cli (ECHO_SEPARATOR_UDP);
	  if (cfg->report_interval_total)
	    echo_cli ("Run time (s)  Transmitted   Received   Throughput   "
		      "%sSent/received dgrams",
		      (cfg->report_interval_jitter ? "Jitter      " : "Roundtrip   "));
	  else
	    echo_cli ("Interval (s)  Transmitted   Received   Throughput   "
		      "%sSent/received dgrams",
		      (cfg->report_interval_jitter ? "Jitter      " : "Roundtrip   "));
	}
      if (cfg->report_interval_total)
	{
	  echo_cli ("%-13.1f %-13U %-10U %+9Ub/s %+9.3fms %llu/%llu", interval_end, format_base10,
		    sent_bytes, format_base10, received_bytes, format_base10,
		    flt_round_nearest ((f64) (total_bytes - last_total_bytes) / print_delta) * 8,
		    (cfg->report_interval_jitter ? jitter : rtt), dgrams_sent, dgrams_received);
	}
      else
	{
	  rtt /= cfg->n_clients;
	  echo_cli ("%.1f-%-9.1f %-13U %-10U %+9Ub/s %+9.3fms %llu/%llu", interval_start,
		    interval_end, format_base10, sent_bytes - stats->last_total_tx_bytes,
		    format_base10, received_bytes - stats->last_total_rx_bytes, format_base10,
		    flt_round_nearest ((f64) (total_bytes - last_total_bytes) / print_delta) * 8,
		    (cfg->report_interval_jitter ? jitter : rtt),
		    (dgrams_sent - stats->last_total_tx_dgrams),
		    (dgrams_received - stats->last_total_rx_dgrams));
	}
      stats->last_total_tx_dgrams = dgrams_sent;
      stats->last_total_rx_dgrams = dgrams_received;
    }
  else
    {
      if (print_header)
	{
	  echo_cli (ECHO_SEPARATOR);
	  if (cfg->report_interval_total)
	    echo_cli ("Run time (s)  Transmitted   Received   Throughput   Roundtrip");
	  else
	    echo_cli ("Interval (s)  Transmitted   Received   Throughput   Roundtrip");
	}
      if (cfg->report_interval_total)
	echo_cli ("%-13.1f %-13U %-10U %+9Ub/s %+7.3fms", interval_end, format_base10, sent_bytes,
		  format_base10, received_bytes, format_base10,
		  flt_round_nearest ((f64) total_bytes / (time_now - stats->test_start_time)) * 8,
		  rtt * 1000);
      else
	echo_cli ("%.1f-%-9.1f %-13U %-10U %+9Ub/s %+7.3fms", interval_start, interval_end,
		  format_base10, sent_bytes - stats->last_total_tx_bytes, format_base10,
		  received_bytes - stats->last_total_rx_bytes, format_base10,
		  flt_round_nearest (((f64) (total_bytes - last_total_bytes)) / print_delta) * 8,
		  rtt * 1000);
    }
  stats->last_print_time = time_now;
  stats->last_total_tx_bytes = sent_bytes;
  stats->last_total_rx_bytes = received_bytes;
}

void
echo_print_final_stats (vlib_main_t *vm, f64 total_delta, echo_test_cfg_t *cfg, echo_stats_t *stats)
{
  u64 total_bytes;
  f64 dgram_loss;
  char *transfer_type;

  if (cfg->proto == TRANSPORT_PROTO_TCP || (cfg->proto == TRANSPORT_PROTO_UDP && cfg->echo_bytes))
    {
      /* display rtt stats in milliseconds */
      if (stats->rtt_stats.n_sum == 1)
	echo_cli ("%.05fms roundtrip", stats->rtt_stats.min_rtt * 1000);
      else if (stats->rtt_stats.n_sum > 1)
	echo_cli ("%.05fms/%.05fms/%.05fms min/avg/max roundtrip", stats->rtt_stats.min_rtt * 1000,
		  stats->rtt_stats.sum_rtt / stats->rtt_stats.n_sum * 1000,
		  stats->rtt_stats.max_rtt * 1000);
      else
	echo_cli ("error measuring roundtrip time");
    }
  if (cfg->proto == TRANSPORT_PROTO_UDP)
    {
      if (cfg->echo_bytes)
	{
	  dgram_loss =
	    (stats->tx_total_dgrams ? ((f64) (stats->tx_total_dgrams - stats->rx_total_dgrams) /
				       (f64) stats->tx_total_dgrams * 100.0) :
				      0.0);
	  echo_cli ("sent total %llu datagrams, received total %llu datagrams, lost %llu datagrams "
		    "(%.2f%%)",
		    stats->tx_total_dgrams, stats->rx_total_dgrams,
		    stats->tx_total_dgrams - stats->rx_total_dgrams, dgram_loss);
	}
      else
	{
	  dgram_loss = (stats->tx_total_dgrams ?
			  ((f64) (stats->tx_total_dgrams - stats->peer_dgrams_received) /
			   (f64) stats->tx_total_dgrams * 100.0) :
			  0.0);
	  echo_cli ("sent total %llu datagrams, lost %llu datagrams (%.2f%%)",
		    stats->tx_total_dgrams, stats->tx_total_dgrams - stats->peer_dgrams_received,
		    dgram_loss);
	}
    }
  total_bytes = (cfg->echo_bytes ? stats->rx_total : stats->tx_total);
  transfer_type = cfg->echo_bytes ? "full-duplex" : "half-duplex";
  echo_cli ("%lld bytes (%lld mbytes, %lld gbytes) in %.2f seconds", total_bytes,
	    total_bytes / (1ULL << 20), total_bytes / (1ULL << 30), total_delta);
  echo_cli ("%u bytes/second %s", flt_round_nearest (((f64) total_bytes) / (total_delta)),
	    transfer_type);
  echo_cli ("%UB/s %s", format_base10, flt_round_nearest (((f64) total_bytes) / (total_delta)),
	    transfer_type);
}
