/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/*
 * dump_metrics.c
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <vpp-api/client/stat_client.h>
#include <vlib/vlib.h>
#include <vlib/stats/shared.h>
#include <ctype.h>
#include "dump_metrics.h"

#define MAX_TOKENS 10

static char *
prom_string (char *s)
{
  char *p = s;
  while (*p)
    {
      if (!isalnum (*p))
	*p = '_';
      p++;
    }
  return s;
}

// For STAT_DIR_TYPE_HISTOGRAM_LOG2, the data is in res->log2_histogram_bins
static void
print_log2_histogram_metric (FILE *stream, stat_segment_data_t *res)
{
  int n_threads = vec_len (res->log2_histogram_bins);
  char sanitized_name[VLIB_STATS_MAX_NAME_SZ];
  strncpy (sanitized_name, res->name, VLIB_STATS_MAX_NAME_SZ - 1);
  sanitized_name[VLIB_STATS_MAX_NAME_SZ - 1] = '\0';
  prom_string (sanitized_name);

  for (int thread = 0; thread < n_threads; ++thread)
    {
      u64 *bins = res->log2_histogram_bins[thread];
      int n_bins = vec_len (bins);
      if (n_bins < 2) // Need at least min_exp + one bin
	continue;
      u32 min_exp = bins[0];
      u64 cumulative = 0;
      u64 sum = 0;
      fformat (stream, "# TYPE %s histogram\n", sanitized_name);
      for (int i = 1; i < n_bins; ++i)
	{
	  cumulative += bins[i];
	  sum += bins[i] * (1ULL << (min_exp + i - 1)); // midpoint approx
	  fformat (stream, "%s{le=\"%llu\",thread=\"%d\"} %llu\n",
		   sanitized_name, (1ULL << (min_exp + i - 1)), thread,
		   cumulative);
	}
      // +Inf bucket
      fformat (stream, "%s{le=\"+Inf\",thread=\"%d\"} %llu\n", sanitized_name,
	       thread, cumulative);
      // _count and _sum
      fformat (stream, "%s_count{thread=\"%d\"} %llu\n", sanitized_name,
	       thread, cumulative);
      fformat (stream, "%s_sum{thread=\"%d\"} %llu\n", sanitized_name, thread,
	       sum);
    }
}

static void
print_metric_v1 (FILE *stream, stat_segment_data_t *res)
{
  int j, k;

  switch (res->type)
    {
    case STAT_DIR_TYPE_HISTOGRAM_LOG2:
      print_log2_histogram_metric (stream, res);
      break;
    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      fformat (stream, "# TYPE %s counter\n", prom_string (res->name));
      for (k = 0; k < vec_len (res->simple_counter_vec); k++)
	for (j = 0; j < vec_len (res->simple_counter_vec[k]); j++)
	  fformat (stream, "%s{thread=\"%d\",interface=\"%d\"} %lld\n",
		   prom_string (res->name), k, j,
		   res->simple_counter_vec[k][j]);
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      fformat (stream, "# TYPE %s_packets counter\n", prom_string (res->name));
      fformat (stream, "# TYPE %s_bytes counter\n", prom_string (res->name));
      for (k = 0; k < vec_len (res->simple_counter_vec); k++)
	for (j = 0; j < vec_len (res->combined_counter_vec[k]); j++)
	  {
	    fformat (stream,
		     "%s_packets{thread=\"%d\",interface=\"%d\"} %lld\n",
		     prom_string (res->name), k, j,
		     res->combined_counter_vec[k][j].packets);
	    fformat (stream, "%s_bytes{thread=\"%d\",interface=\"%d\"} %lld\n",
		     prom_string (res->name), k, j,
		     res->combined_counter_vec[k][j].bytes);
	  }
      break;
    case STAT_DIR_TYPE_SCALAR_INDEX:
      fformat (stream, "# TYPE %s counter\n", prom_string (res->name));
      fformat (stream, "%s %.2f\n", prom_string (res->name),
	       res->scalar_value);
      break;
    case STAT_DIR_TYPE_GAUGE:
      fformat (stream, "# TYPE %s gauge\n", prom_string (res->name));
      fformat (stream, "%s %.2f\n", prom_string (res->name),
	       res->scalar_value);
      break;
    case STAT_DIR_TYPE_NAME_VECTOR:
      fformat (stream, "# TYPE %s_info gauge\n", prom_string (res->name));
      for (k = 0; k < vec_len (res->name_vector); k++)
	if (res->name_vector[k])
	  fformat (stream, "%s_info{index=\"%d\",name=\"%s\"} 1\n",
		   prom_string (res->name), k, res->name_vector[k]);
      break;

    case STAT_DIR_TYPE_EMPTY:
      break;

    default:
      fformat (stderr, "Unknown value %d\n", res->type);
      ;
    }
}

static void
sanitize (char *str, int len)
{
  for (int i = 0; i < len; i++)
    {
      if (str[i] == '/')
	str[i] = '_';
      else if (str[i] == '-')
	continue;
      else if (!isalnum (str[i]))
	str[i] = '_';
    }
}

static int
tokenize (const char *name, char **tokens, int *lengths, int max_tokens)
{
  char *p = (char *) name;
  char *savep = p;

  int i = 0;
  if (strncmp (p, "/interfaces/", 12) == 0)
    {
      /*
	 Special case for interfaces as its sometimes contains '/' in the id.
	 Split the string into interface id and token name
		      /interfaces/<id>/<name>
      */
      tokens[i] = p;
      lengths[i] = 0;
      i++;
      p++;
      tokens[i] = p;
      lengths[i] = 10;
      i++;
      p += 11;
      savep = p;
      p = p + strlen (p) - 1;
      while (*p != '/' && p != savep)
	p--;
      tokens[i] = savep;
      lengths[i] = (int) (p - savep);
      p++; // skip '/'
      i++;
      tokens[i] = p;
      lengths[i] = (int) (strlen (p));
      return i + 1;
    }
  while (*p && i < max_tokens - 1)
    {
      if (*p == '/')
	{
	  tokens[i] = (char *) savep;
	  lengths[i] = (int) (p - savep);
	  i++;
	  p++;
	  savep = p;
	}
      else
	{
	  p++;
	}
    }
  tokens[i] = (char *) savep;
  lengths[i] = (int) (p - savep);

  i++;
  return i;
}

static void
print_metric_v2 (FILE *stream, stat_segment_data_t *res)
{
  int num_tokens = 0;
  char *tokens[MAX_TOKENS];
  int lengths[MAX_TOKENS];
  int j, k;

  num_tokens = tokenize (res->name, tokens, lengths, MAX_TOKENS);
  switch (res->type)
    {
    case STAT_DIR_TYPE_HISTOGRAM_LOG2:
      print_log2_histogram_metric (stream, res);
      break;
    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      if (res->simple_counter_vec == 0)
	return;

      for (k = 0; k < vec_len (res->simple_counter_vec); k++)
	for (j = 0; j < vec_len (res->simple_counter_vec[k]); j++)
	  {
	    if ((num_tokens == 4) &&
		(!strncmp (tokens[1], "nodes", lengths[1]) ||
		 !strncmp (tokens[1], "interfaces", lengths[1])))
	      {
		sanitize (tokens[1], lengths[1]);
		sanitize (tokens[2], lengths[2]);
		sanitize (tokens[3], lengths[3]);
		fformat (
		  stream,
		  "%.*s_%.*s{%.*s=\"%.*s\",index=\"%d\",thread=\"%d\"} %lu\n",
		  lengths[1], tokens[1], lengths[3], tokens[3], lengths[1] - 1,
		  tokens[1], lengths[2], tokens[2], j, k,
		  res->simple_counter_vec[k][j]);
	      }
	    else if ((num_tokens == 3) &&
		     !strncmp (tokens[1], "sys", lengths[1]))
	      {
		sanitize (tokens[1], lengths[1]);
		fformat (stream, "%.*s_%.*s{index=\"%d\",thread=\"%d\"} %lu\n",
			 lengths[1], tokens[1], lengths[2], tokens[2], j, k,
			 res->simple_counter_vec[k][j]);
	      }
	    else if (!strncmp (tokens[1], "mem", lengths[1]))
	      {
		if (num_tokens == 3)
		  {
		    fformat (
		      stream,
		      "%.*s{heap=\"%.*s\",index=\"%d\",thread=\"%d\"} %lu\n",
		      lengths[1], tokens[1], lengths[2], tokens[2], j, k,
		      res->simple_counter_vec[k][j]);
		  }
		else if (num_tokens == 4)
		  {
		    fformat (stream,
			     "%.*s_%.*s{heap=\"%.*s\",index=\"%d\",thread=\"%"
			     "d\"} %lu\n",
			     lengths[1], tokens[1], lengths[3], tokens[3],
			     lengths[2], tokens[2], j, k,
			     res->simple_counter_vec[k][j]);
		  }
		else
		  {
		    print_metric_v1 (stream, res);
		    return;
		  }
	      }
	    else if (!strncmp (tokens[1], "err", lengths[1]))
	      {
		// NOTE: the error is in token3, but it may contain '/'.
		// Considering this is the last token, it is safe to print
		// token3 until the end of res->name
		fformat (stream,
			 "%.*s{node=\"%.*s\",error=\"%s\",index=\"%d\",thread="
			 "\"%d\"} %lu\n",
			 lengths[1], tokens[1], lengths[2], tokens[2],
			 tokens[3], j, k, res->simple_counter_vec[k][j]);
	      }
	    else
	      {
		print_metric_v1 (stream, res);
		return;
	      }
	  }
      break;

    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      if (res->combined_counter_vec == 0)
	return;
      for (k = 0; k < vec_len (res->combined_counter_vec); k++)
	for (j = 0; j < vec_len (res->combined_counter_vec[k]); j++)
	  {
	    if ((num_tokens == 4) &&
		!strncmp (tokens[1], "interfaces", lengths[1]))
	      {
		sanitize (tokens[1], lengths[1]);
		sanitize (tokens[3], lengths[3]);
		fformat (stream,
			 "%.*s_%.*s_packets{interface=\"%.*s\",index=\"%d\","
			 "thread=\"%d\"} %lu\n",
			 lengths[1], tokens[1], lengths[3], tokens[3],
			 lengths[2], tokens[2], j, k,
			 res->combined_counter_vec[k][j].packets);
		fformat (stream,
			 "%.*s_%.*s_bytes{interface=\"%.*s\",index=\"%d\","
			 "thread=\"%d\"} %lu\n",
			 lengths[1], tokens[1], lengths[3], tokens[3],
			 lengths[2], tokens[2], j, k,
			 res->combined_counter_vec[k][j].bytes);
	      }
	    else
	      {
		print_metric_v1 (stream, res);
		return;
	      }
	  }
      break;

    case STAT_DIR_TYPE_SCALAR_INDEX:
    case STAT_DIR_TYPE_GAUGE:
      if ((num_tokens == 4) &&
	  !strncmp (tokens[1], "buffer-pools", lengths[1]))
	{
	  sanitize (tokens[1], lengths[1]);
	  sanitize (tokens[3], lengths[3]);
	  fformat (stream, "%.*s_%.*s{pool=\"%.*s\"} %.2f\n", lengths[1],
		   tokens[1], lengths[3], tokens[3], lengths[2], tokens[2],
		   res->scalar_value);
	}
      else if ((num_tokens == 3) && !strncmp (tokens[1], "sys", lengths[1]))
	{
	  sanitize (tokens[1], lengths[1]);
	  sanitize (tokens[2], lengths[2]);
	  fformat (stream, "%.*s_%.*s %.2f\n", lengths[1], tokens[1],
		   lengths[2], tokens[2], res->scalar_value);
	  if (!strncmp (tokens[2], "boottime", lengths[2]))
	    {
	      struct timeval tv;
	      gettimeofday (&tv, NULL);
	      fformat (stream, "sys_uptime %.2f\n",
		       tv.tv_sec - res->scalar_value);
	    }
	}
      else
	{
	  print_metric_v1 (stream, res);
	  return;
	}
      break;

    default:;
      fformat (stderr, "Unhandled type %d name %s\n", res->type, res->name);
    }
}

void
dump_metrics (FILE *stream, u8 **patterns, u8 v2, stat_client_main_t *shm)
{
  stat_segment_data_t *res;
  int i;
  static u32 *stats = 0;

retry:
  res = stat_segment_dump_r (stats, shm);
  if (res == 0)
    { /* Memory layout has changed */
      if (stats)
	vec_free (stats);
      stats = stat_segment_ls_r (patterns, shm);
      goto retry;
    }

  for (i = 0; i < vec_len (res); i++)
    {
      if (v2)
	print_metric_v2 (stream, &res[i]);
      else
	print_metric_v1 (stream, &res[i]);
    }
  stat_segment_data_free (res);
}
