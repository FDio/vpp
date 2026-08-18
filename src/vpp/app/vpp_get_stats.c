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
#include <unistd.h>

/*
 * "directory" mode: the segment's STRUCTURE as JSON, for machines.
 *
 * Distinct from "dump", which prints values for humans. This prints what a schema
 * or catalog tool needs and values are deliberately absent: every entry's name, its
 * exact type, the shape of its vector, what a symlink points at, the contents of a
 * name vector, and a histogram's bin parameters -- plus the segment-level facts
 * (version, epoch, size, host, capture time) that make a captured snapshot
 * self-describing rather than something you have to do archaeology on.
 *
 * Type names are emitted as short lower-case strings rather than the C enum
 * spelling so the output is a stable contract independent of enum renumbering.
 */

static const char *
stat_type_name (stat_directory_type_t t)
{
  switch (t)
    {
    case STAT_DIR_TYPE_SCALAR_INDEX:
      return "scalar";
    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      return "simple";
    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      return "combined";
    case STAT_DIR_TYPE_NAME_VECTOR:
      return "name";
    case STAT_DIR_TYPE_EMPTY:
      return "empty";
    case STAT_DIR_TYPE_SYMLINK:
      return "symlink";
    case STAT_DIR_TYPE_HISTOGRAM_LOG2:
      return "hist";
    case STAT_DIR_TYPE_RING_BUFFER:
      return "ring";
    case STAT_DIR_TYPE_GAUGE:
      return "gauge";
    default:
      return "illegal";
    }
}

/* Append v to s as a JSON string literal. Stat names are built with format(),
 * so assume nothing about their contents. */
static u8 *
json_string (u8 *s, const char *v)
{
  const unsigned char *p;

  vec_add1 (s, '"');
  for (p = (const unsigned char *) v; p && *p; p++)
    {
      if (*p == '"' || *p == '\\')
	{
	  vec_add1 (s, '\\');
	  vec_add1 (s, *p);
	}
      else if (*p >= 0x20)
	vec_add1 (s, *p);
      else if (*p == '\n')
	s = format (s, "\\n");
      else if (*p == '\r')
	s = format (s, "\\r");
      else if (*p == '\t')
	s = format (s, "\\t");
      else
	s = format (s, "\\u%04x", *p);
    }
  vec_add1 (s, '"');
  return s;
}

/* get_stat_vector_r() is private to stat_client.c; stat_segment_adjust() and the
 * shared header are public, so re-derive it here rather than widen that API. */
static vlib_stats_entry_t *
directory_vector (stat_client_main_t *sm)
{
  return stat_segment_adjust (sm, (void *) sm->shared_header->directory_vector);
}

/*
 * Build the whole document inside ONE epoch window and write it outside.
 *
 * The window is validated, not held: stat_segment_access_end() fails if the epoch
 * moved while we read, and the caller retries. Doing I/O inside it would widen the
 * race for no reason -- a slow consumer on stdout could make the read fail
 * indefinitely -- so the document is buffered first. It is a few hundred KB for a
 * segment with thousands of entries, well inside this program's 64MB heap.
 */
static u8 *
stat_directory_json (stat_client_main_t *sm, u32 *dir, const char *socket_name)
{
  stat_segment_access_t sa;
  vlib_stats_entry_t *dirv;
  u8 *s = 0;
  u32 n_by_type[STAT_DIR_TYPE_GAUGE + 2] = { 0 };
  u32 n_entries = 0;
  int i, j, first = 1;
  char host[256];

  if (gethostname (host, sizeof (host)) != 0)
    host[0] = 0;
  host[sizeof (host) - 1] = 0;

  if (stat_segment_access_start (&sa, sm))
    return 0;

  dirv = directory_vector (sm);

  s = format (s, "{\n  \"entries\": [\n");

  for (i = 0; i < vec_len (dir); i++)
    {
      vlib_stats_entry_t *ep = vec_elt_at_index (dirv, dir[i]);
      stat_directory_type_t t = ep->type;

      if ((u32) t < ARRAY_LEN (n_by_type))
	n_by_type[t]++;

      /* An EMPTY slot is a hole left by a removed entry, not a counter. */
      if (t == STAT_DIR_TYPE_EMPTY)
	continue;
      n_entries++;

      s = format (s, "%s    {\"name\": ", first ? "" : ",\n");
      first = 0;
      s = json_string (s, ep->name);
      s = format (s, ", \"type\": ");
      s = json_string (s, stat_type_name (t));

      switch (t)
	{
	case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	  {
	    counter_t **cb = stat_segment_adjust (sm, ep->data);
	    counter_t *c0 = vec_len (cb) ? stat_segment_adjust (sm, cb[0]) : 0;
	    s = format (s, ", \"nthreads\": %d, \"nindices\": %d", vec_len (cb),
			c0 ? vec_len (c0) : 0);
	  }
	  break;

	case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	  {
	    vlib_counter_t **cb = stat_segment_adjust (sm, ep->data);
	    vlib_counter_t *c0 = vec_len (cb) ? stat_segment_adjust (sm, cb[0]) : 0;
	    s = format (s, ", \"nthreads\": %d, \"nindices\": %d", vec_len (cb),
			c0 ? vec_len (c0) : 0);
	  }
	  break;

	case STAT_DIR_TYPE_HISTOGRAM_LOG2:
	  {
	    /* [thread][bin], and bin 0 holds min_exp rather than a count --
	     * see vlib_validate_log2_histogram() in vlib/counter.c. */
	    uint64_t **bins = stat_segment_adjust (sm, ep->data);
	    uint64_t *b0 = vec_len (bins) ? stat_segment_adjust (sm, bins[0]) : 0;
	    u32 n = b0 ? vec_len (b0) : 0;
	    s = format (s, ", \"nthreads\": %d, \"nindices\": %d", vec_len (bins), n);
	    if (n)
	      s = format (s, ", \"min_exp\": %llu, \"n_bins\": %d", b0[0], n - 1);
	  }
	  break;

	case STAT_DIR_TYPE_NAME_VECTOR:
	  {
	    uint8_t **nv = stat_segment_adjust (sm, ep->data);
	    s = format (s, ", \"nindices\": %d, \"names\": [", vec_len (nv));
	    for (j = 0; j < vec_len (nv); j++)
	      {
		u8 *n = nv[j] ? stat_segment_adjust (sm, nv[j]) : 0;
		if (j)
		  s = format (s, ", ");
		if (n)
		  s = json_string (s, (char *) n);
		else
		  s = format (s, "null");
	      }
	    s = format (s, "]");
	  }
	  break;

	case STAT_DIR_TYPE_SYMLINK:
	  {
	    /* index1 = backing entry, index2 = which column of it. Resolving
	     * the target NAME here is the whole point: it is what lets a
	     * consumer rebuild the /err/<node>/<reason> fan onto /node/errors
	     * without a second pass. */
	    vlib_stats_entry_t *tp = vec_elt_at_index (dirv, ep->index1);
	    s = format (s, ", \"target\": [");
	    s = json_string (s, tp->name);
	    s = format (s, ", %d]", ep->index2);
	  }
	  break;

	default:
	  /* scalar, gauge: the value belongs to "dump", not here.
	   * ring: its config and embedded schema live in the ring itself and
	   * the client does not map them; reported by type only. */
	  break;
	}
      s = format (s, "}");
    }

  s = format (s, "\n  ],\n  \"segment\": {\n");
  s = format (s, "    \"socket\": ");
  s = json_string (s, socket_name);
  s = format (s, ",\n    \"host\": ");
  s = json_string (s, host);
  s = format (s, ",\n    \"captured_at\": %lld", (long long) time (0));
  s = format (s, ",\n    \"version\": %llu", stat_segment_version_r (sm));
  s = format (s, ",\n    \"epoch\": %llu", sa.epoch);
  s = format (s, ",\n    \"in_progress\": %llu", (u64) sm->shared_header->in_progress);
  s = format (s, ",\n    \"memory_size\": %lld", (long long) sm->memory_size);
  s = format (s, ",\n    \"directory_size\": %d", vec_len (dirv));
  s = format (s, ",\n    \"entries\": %d", n_entries);
  s = format (s, ",\n    \"by_type\": {");
  for (i = 0, first = 1; i < ARRAY_LEN (n_by_type); i++)
    {
      if (!n_by_type[i])
	continue;
      s = format (s, "%s", first ? "" : ", ");
      first = 0;
      s = json_string (s, stat_type_name (i));
      s = format (s, ": %d", n_by_type[i]);
    }
  s = format (s, "}\n  }\n}\n");

  if (!stat_segment_access_end (&sa, sm))
    {
      /* The epoch moved under us: everything above may be inconsistent. */
      vec_free (s);
      return 0;
    }
  sm->current_epoch = sa.epoch;
  return s;
}

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
  STAT_CLIENT_CMD_DIRECTORY,
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
	   "%s: [socket-name <name>] [ls|dump|directory|poll] [OPTIONS] <patterns> ...\n"
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
      else if (unformat (a, "directory"))
	{
	  cmd = STAT_CLIENT_CMD_DIRECTORY;
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

    case STAT_CLIENT_CMD_DIRECTORY:
      {
	/* stat_segment_ls() and the walk each validate the epoch; either can
	 * legitimately lose the race, so retry rather than fail. */
	u8 *json = 0;
	int tries;

	for (tries = 0; tries < 10 && !json; tries++)
	  {
	    if (!dir)
	      {
		/* stat_client_main is the client stat_segment_connect() and
		 * stat_segment_ls() operate on; stat_client_get() is a
		 * constructor for a fresh, unconnected one. */
		uint64_t epoch = stat_client_main.shared_header->epoch;

		dir = stat_segment_ls (patterns);
		/* A NULL result is ambiguous: either the patterns matched
		 * nothing, or we lost the epoch race. Only the latter is worth
		 * retrying; the former is an empty document, not an error. */
		if (!dir && stat_client_main.shared_header->epoch != epoch)
		  continue;
	      }
	    json = stat_directory_json (&stat_client_main, dir, (char *) stat_segment_name);
	    if (!json)
	      {
		vec_free (dir);
		dir = 0;
	      }
	  }
	if (!json)
	  {
	    fformat (stderr, "Segment kept changing under us, giving up.\n");
	    stat_segment_disconnect ();
	    exit (1);
	  }
	fformat (stdout, "%v", json);
	vec_free (json);
      }
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
