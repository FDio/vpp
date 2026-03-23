/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/*
 * vpp_get_stats.c
 */
#include <errno.h>
#include <time.h>
#include <vpp-api/client/stat_client.h>
#include <vlib/vlib.h>
#include <vpp/vnet/config.h>

bool f_machine = false;
bool f_summary = false;
bool f_timestamp = false;
bool f_no_zeros = false;
f64 o_interval = 1;
uint o_only_index = ~0;

static void
dump_stats_result (stat_segment_data_t *res)
{
  int i, j, k;
  vlib_counter_t empty = {};
  vlib_counter_t *vcounter = NULL;
  counter_t *counter = NULL;
  struct timespec ts;
  char timestamp[80] = "";

  if (f_timestamp)
    {
      if (clock_gettime (CLOCK_REALTIME, &ts) < 0)
	{
	  fprintf (stderr, "bad timespec_get return %s\n", strerror (errno));
	  exit (1);
	}
      u64 ns = (u64) (ts.tv_sec) * (u64) 1000000000 + (u64) (ts.tv_nsec);
      f64 sec = (f64) ns / 1e9;
      snprintf (timestamp, sizeof (timestamp) - 1, "%0.06f:", sec);
    }

  for (i = 0; i < vec_len (res); i++)
    {
      switch (res[i].type)
	{
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  if (res[i].simple_counter_vec == 0)
	    continue;
	  if (f_summary)
	    {
	      for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
		for (j = 0; j < vec_len (res[i].simple_counter_vec[k]); j++)
		  {
		    if (o_only_index != ~0 && o_only_index != j)
		      continue;
		    vec_validate_init_empty (counter, j, 0);
		    counter[j] += res[i].simple_counter_vec[k][j];
		  }
	      for (j = 0; j < vec_len (counter); j++)
		if (o_only_index != ~0 && o_only_index != j)
		  continue;
		else if (!counter[j] && f_no_zeros)
		  continue;
		else if (f_machine)
		  fformat (stdout, "%s%d:%d:%llu:%s\n", timestamp, res[i].type, j, counter[j],
			   res[i].name);
		else
		  fformat (stdout, "%s[%d]: %llu packets %s\n", timestamp, j, counter[j],
			   res[i].name);
	      vec_reset_length (counter);
	    }
	  else
	    for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
	      for (j = 0; j < vec_len (res[i].simple_counter_vec[k]); j++)
		if (o_only_index != ~0 && o_only_index != j)
		  continue;
		else if (!res[i].simple_counter_vec[k][j] && f_no_zeros)
		  continue;
		else if (f_machine)
		  fformat (stdout, "%s%d:%d:%d:%llu:%s\n", timestamp, res[i].type, j, k,
			   res[i].simple_counter_vec[k][j], res[i].name);
		else
		  fformat (stdout, "%s[%d @ %d]: %llu packets %s\n", timestamp, j, k,
			   res[i].simple_counter_vec[k][j], res[i].name);
	  break;

	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  if (res[i].combined_counter_vec == 0)
	    continue;
	  if (f_summary)
	    {
	      for (k = 0; k < vec_len (res[i].combined_counter_vec); k++)
		for (j = 0; j < vec_len (res[i].combined_counter_vec[k]); j++)
		  {
		    if (o_only_index != ~0 && o_only_index != j)
		      continue;
		    vec_validate_init_empty (vcounter, j, empty);
		    vcounter[j].packets += res[i].combined_counter_vec[k][j].packets;
		    vcounter[j].bytes += res[i].combined_counter_vec[k][j].bytes;
		  }
	      for (j = 0; j < vec_len (vcounter); j++)
		if (o_only_index != ~0 && o_only_index != j)
		  continue;
		else if (!vcounter[j].packets && f_no_zeros)
		  continue;
		else if (f_machine)
		  fformat (stdout, "%s%d:%d:%llu:%llu:%s\n", timestamp, res[i].type, j,
			   vcounter[j].packets, vcounter[j].bytes, res[i].name);
		else
		  fformat (stdout, "%s[%d]: %llu packets, %llu bytes %s\n", timestamp, j,
			   vcounter[j].packets, vcounter[j].bytes, res[i].name);
	      vec_reset_length (vcounter);
	    }
	  else
	    for (k = 0; k < vec_len (res[i].combined_counter_vec); k++)
	      for (j = 0; j < vec_len (res[i].combined_counter_vec[k]); j++)
		if (o_only_index != ~0 && o_only_index != j)
		  continue;
		else if (!res[i].combined_counter_vec[k][j].packets && f_no_zeros)
		  continue;
		else if (f_machine)
		  fformat (stdout, "%s%d:%d:%d:%llu:%llu:%s\n", timestamp, res[i].type, j, k,
			   res[i].combined_counter_vec[k][j].packets,
			   res[i].combined_counter_vec[k][j].bytes, res[i].name);
		else
		  fformat (stdout, "%s[%d @ %d]: %llu packets, %llu bytes %s\n", timestamp, j, k,
			   res[i].combined_counter_vec[k][j].packets,
			   res[i].combined_counter_vec[k][j].bytes, res[i].name);
	  break;

	case STAT_DIR_TYPE_SCALAR_INDEX:
	case STAT_DIR_TYPE_GAUGE:
	  if (f_machine)
	    fformat (stdout, "%s%d:%.2f:%s\n", timestamp, res[i].type, res[i].scalar_value,
		     res[i].name);
	  else
	    fformat (stdout, "%s%.2f %s\n", timestamp, res[i].scalar_value, res[i].name);
	  break;

	case STAT_DIR_TYPE_HISTOGRAM_LOG2:
	  for (k = 0; k < vec_len (res[i].log2_histogram_bins); k++)
	    {
	      u64 *bins = res[i].log2_histogram_bins[k];
	      int n_bins = vec_len (bins);
	      if (n_bins < 2) // Need at least min_exp + one bin
		continue;
	      u32 min_exp = bins[0];
	      u64 cumulative = 0;
	      u64 sum = 0;
	      fformat (stdout, "Histogram %s (thread %d):\n", res[i].name, k);
	      for (int j = 1; j < n_bins; ++j)
		{
		  cumulative += bins[j];
		  sum += bins[j] * (1ULL << (min_exp + j - 1)); // midpoint approx
		  fformat (stdout, "  <= %llu: %llu (cumulative: %llu)\n",
			   (1ULL << (min_exp + j - 1)), bins[j], cumulative);
		}
	      fformat (stdout, "  +Inf: %llu (total count: %llu, sum: %llu)\n", cumulative,
		       cumulative, sum);
	    }
	  break;

	case STAT_DIR_TYPE_NAME_VECTOR:
	  if (res[i].name_vector == 0)
	    continue;
	  for (k = 0; k < vec_len (res[i].name_vector); k++)
	    if (res[i].name_vector[k])
	      {
		if (f_machine)
		  fformat (stdout, "%s%d:%d:%s:%s\n", timestamp, res[i].type, k,
			   res[i].name_vector[k], res[i].name);
		else
		  fformat (stdout, "%s[%d]: %s %s\n", timestamp, k, res[i].name_vector[k],
			   res[i].name);
	      }
	  break;

	case STAT_DIR_TYPE_EMPTY:
	  break;

	default:;
	}
    }
}

static int
stat_poll_loop (u8 ** patterns)
{
  struct timespec ts, tsrem;
  stat_segment_data_t *res;
  int lost_connection = 0;
  f64 heartbeat, prev_heartbeat = 0;
  u32 *stats = stat_segment_ls (patterns);
  if (!stats)
    {
      return -1;
    }

  printf ("\033[2J");		/*  clear the screen  */
  while (1)
    {
      heartbeat = stat_segment_heartbeat ();
      if (heartbeat > prev_heartbeat)
	{
	  prev_heartbeat = heartbeat;
	  lost_connection = 0;
	}
      else
	{
	  lost_connection++;
	}
      if (lost_connection > 10)
	{
	  fformat (stderr, "Lost connection to VPP...\n");
	  return -1;
	}

      printf ("\033[H");	/* Cursor top left corner */
      res = stat_segment_dump (stats);
      if (!res)
	{
	  stats = stat_segment_ls (patterns);
	  continue;
	}
      dump_stats_result (res);
      stat_segment_data_free (res);
      /* Scrape stats every 5 seconds */
      ts.tv_sec = (u64) o_interval;
      ts.tv_nsec = (o_interval - ts.tv_sec) * 1e9;
      while (nanosleep (&ts, &tsrem) < 0)
	ts = tsrem;

    }
}

enum stat_client_cmd_e
{
  STAT_CLIENT_CMD_UNKNOWN,
  STAT_CLIENT_CMD_LS,
  STAT_CLIENT_CMD_POLL,
  STAT_CLIENT_CMD_DUMP,
  STAT_CLIENT_CMD_TIGHTPOLL,
};

#ifdef CLIB_SANITIZE_ADDR
/* default options for Address Sanitizer */
const char *
__asan_default_options (void)
{
  return VPP_SANITIZE_ADDR_OPTIONS;
}
#endif /* CLIB_SANITIZE_ADDR */

static void
usage (char *argv0)
{
  fformat (stderr,
	   "usage:\n"
	   "%s: [socket-name <name>] [ls|dump|poll] [OPTIONS] <patterns> ...\n"
	   "  OPTIONS:\n"
	   "    interval x[.y]     polling interval in seconds (default 1.0)\n"
	   "    machine            machine-parseable format\n"
	   "    no-zeros           omit 0-valued entries\n"
	   "    only-index IDX     print value(s) for specified index only\n"
	   "    summary            print counter summaries only\n"
	   "    timestamp          print timestamp\n",
	   argv0);
  exit (1);
}

int
main (int argc, char **argv)
{
  unformat_input_t _argv, *a = &_argv;
  u8 *stat_segment_name, *pattern = 0, **patterns = 0;
  int rv;
  enum stat_client_cmd_e cmd = STAT_CLIENT_CMD_UNKNOWN;

  /* Create a heap of 64MB */
  clib_mem_init (0, 64 << 20);

  unformat_init_command_line (a, argv);

  stat_segment_name = (u8 *) STAT_SEGMENT_SOCKET_FILE;

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "socket-name %s", &stat_segment_name))
	;
      else if (unformat (a, "interval %f", &o_interval))
	;
      else if (unformat (a, "machine"))
	f_machine = true;
      else if (unformat (a, "only-index %u", &o_only_index))
	;
      else if (unformat (a, "no-zeros"))
	f_no_zeros = true;
      else if (unformat (a, "summary"))
	f_summary = true;
      else if (unformat (a, "timestamp"))
	f_timestamp = true;
      else if (unformat (a, "ls"))
	{
	  cmd = STAT_CLIENT_CMD_LS;
	}
      else if (unformat (a, "dump"))
	{
	  cmd = STAT_CLIENT_CMD_DUMP;
	}
      else if (unformat (a, "poll"))
	{
	  cmd = STAT_CLIENT_CMD_POLL;
	}
      else if (unformat (a, "tightpoll"))
	{
	  cmd = STAT_CLIENT_CMD_TIGHTPOLL;
	}
      else if (unformat (a, "%s", &pattern))
	{
	  vec_add1 (patterns, pattern);
	}
      else
	{
	  usage (argv[0]);
	}
    }
reconnect:
  rv = stat_segment_connect ((char *) stat_segment_name);
  if (rv)
    {
      fformat (stderr, "Couldn't connect to vpp, does %s exist?\n",
	       stat_segment_name);
      exit (1);
    }

  u32 *dir;
  int i;
  stat_segment_data_t *res;

  dir = stat_segment_ls (patterns);

  switch (cmd)
    {
    case STAT_CLIENT_CMD_LS:
      /* List all counters */
      for (i = 0; i < vec_len (dir); i++)
	{
	  char *n = stat_segment_index_to_name (dir[i]);
	  if (!n)
	    continue;
	  printf ("%s\n", n);
	  free (n);
	}
      break;

    case STAT_CLIENT_CMD_DUMP:
      res = stat_segment_dump (dir);
      dump_stats_result (res);
      stat_segment_data_free (res);
      break;

    case STAT_CLIENT_CMD_POLL:
      stat_poll_loop (patterns);
      /* We can only exist the pool loop if we lost connection to VPP */
      stat_segment_disconnect ();
      goto reconnect;
      break;

    case STAT_CLIENT_CMD_TIGHTPOLL:
      while (1)
	{
	  res = stat_segment_dump (dir);
	  if (res == 0)
	    {
	      /* Refresh */
	      vec_free (dir);
	      dir = stat_segment_ls (patterns);
	      continue;
	    }
	  stat_segment_data_free (res);
	}
      break;

    default:
      usage (argv[0]);
    }

  stat_segment_disconnect ();

  exit (0);
}
