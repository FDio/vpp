/*
 *------------------------------------------------------------------
 * vpp_get_stats.c
 *
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
 *------------------------------------------------------------------
 */

#include <vpp-api/client/stat_client.h>
#include <vlib/vlib.h>

static int
stat_poll_loop (u8 ** patterns)
{
  struct timespec ts, tsrem;
  stat_segment_data_t *res;
  stat_directory_type_t type;
  int i, j, k, lost_connection = 0;
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
      for (i = 0; i < vec_len (res); i++)
	{
	  type = res[i].type;
	  if (type == STAT_DIR_TYPE_SYMLINK)
	    {
	      type = res[i].symlink_type;
	    }
	  switch (type)
	    {
	    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	      for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
		for (j = 0; j < vec_len (res[i].simple_counter_vec[k]); j++)
		  fformat (stdout, "[%d]: %llu packets %s\n",
			   j, res[i].simple_counter_vec[k][j], res[i].name);
	      break;

	    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	      for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
		for (j = 0; j < vec_len (res[i].combined_counter_vec[k]); j++)
		  fformat (stdout, "[%d]: %llu packets, %llu bytes %s\n",
			   j, res[i].combined_counter_vec[k][j].packets,
			   res[i].combined_counter_vec[k][j].bytes,
			   res[i].name);
	      break;

	    case STAT_DIR_TYPE_ERROR_INDEX:
	      for (j = 0; j < vec_len (res[i].error_vector); j++)
		fformat (stdout, "%llu %s\n", res[i].error_vector[j],
			 res[i].name);
	      break;

	    case STAT_DIR_TYPE_SCALAR_INDEX:
	      fformat (stdout, "%.2f %s\n", res[i].scalar_value, res[i].name);
	      break;

	    case STAT_DIR_TYPE_EMPTY:
	      break;

	    default:
	      printf ("Unknown value\n");
	      ;
	    }
	}
      stat_segment_data_free (res);
      /* Scrape stats every 5 seconds */
      ts.tv_sec = 1;
      ts.tv_nsec = 0;
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
	  fformat (stderr,
		   "%s: usage [socket-name <name>] [ls|dump|poll] <patterns> ...\n",
		   argv[0]);
	  exit (1);
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
  int i, j, k;
  stat_segment_data_t *res;
  stat_directory_type_t type;

  dir = stat_segment_ls (patterns);

  switch (cmd)
    {
    case STAT_CLIENT_CMD_LS:
      /* List all counters */
      for (i = 0; i < vec_len (dir); i++)
	{
	  char *n = stat_segment_index_to_name (dir[i]);
	  printf ("%s\n", n);
	  free (n);
	}
      break;

    case STAT_CLIENT_CMD_DUMP:
      res = stat_segment_dump (dir);
      for (i = 0; i < vec_len (res); i++)
	{
	  type = res[i].type;
	  if (type == STAT_DIR_TYPE_SYMLINK)
	    {
	      type = res[i].symlink_type;
	    }
	  switch (type)
	    {
	    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	      if (res[i].simple_counter_vec == 0)
		continue;
	      for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
		for (j = 0; j < vec_len (res[i].simple_counter_vec[k]); j++)
		  fformat (stdout, "[%d @ %d]: %llu packets %s\n",
			   j, k, res[i].simple_counter_vec[k][j],
			   res[i].name);
	      break;

	    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	      if (res[i].combined_counter_vec == 0)
		continue;
	      for (k = 0; k < vec_len (res[i].combined_counter_vec); k++)
		for (j = 0; j < vec_len (res[i].combined_counter_vec[k]); j++)
		  fformat (stdout, "[%d @ %d]: %llu packets, %llu bytes %s\n",
			   j, k, res[i].combined_counter_vec[k][j].packets,
			   res[i].combined_counter_vec[k][j].bytes,
			   res[i].name);
	      break;

	    case STAT_DIR_TYPE_ERROR_INDEX:
	      for (j = 0; j < vec_len (res[i].error_vector); j++)
		fformat (stdout, "[@%d] %llu %s\n", j, res[i].error_vector[j],
			 res[i].name);
	      break;

	    case STAT_DIR_TYPE_SCALAR_INDEX:
	      fformat (stdout, "%.2f %s\n", res[i].scalar_value, res[i].name);
	      break;

	    case STAT_DIR_TYPE_NAME_VECTOR:
	      if (res[i].name_vector == 0)
		continue;
	      for (k = 0; k < vec_len (res[i].name_vector); k++)
		if (res[i].name_vector[k])
		  fformat (stdout, "[%d]: %s %s\n", k, res[i].name_vector[k],
			   res[i].name);
	      break;

	    case STAT_DIR_TYPE_EMPTY:
	      break;

	    default:
	      ;
	    }
	}
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
      fformat (stderr,
	       "%s: usage [socket-name <name>] [ls|dump|poll] <patterns> ...\n",
	       argv[0]);
    }

  stat_segment_disconnect ();

  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
