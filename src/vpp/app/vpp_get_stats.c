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
#include <vpp/stats/stats.h>

static int
stat_poll_loop (stat_segment_cached_pointer_t * cp)
{
  struct timespec ts, tsrem;
  stat_segment_data_t *res;
  int i, j, k, lost_connection = 0;
  f64 heartbeat, prev_heartbeat = 0;

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
      res = stat_segment_collect (cp);
      for (i = 0; i < vec_len (res); i++)
	{
	  switch (res[i].type)
	    {
	    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	      for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
		for (j = 0; j < vec_len (res[i].simple_counter_vec[k]); j++)
		  fformat (stdout, "[%d]: %lld packets %s\n",
			   j, res[i].simple_counter_vec[k][j], res[i].name);
	      break;

	    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	      for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
		for (j = 0; j < vec_len (res[i].combined_counter_vec[k]); j++)
		  fformat (stdout, "[%d]: %lld packets, %lld bytes %s\n",
			   j, res[i].combined_counter_vec[k][j].packets,
			   res[i].combined_counter_vec[k][j].bytes,
			   res[i].name);
	      break;

	    case STAT_DIR_TYPE_ERROR_INDEX:
	      fformat (stdout, "%lld %s\n", res[i].error_value, res[i].name);
	      break;

	    case STAT_DIR_TYPE_SCALAR_POINTER:
	      fformat (stdout, "%.2f %s\n", res[i].scalar_value, res[i].name);
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
};

int
main (int argc, char **argv)
{
  unformat_input_t _argv, *a = &_argv;
  u8 *stat_segment_name, *pattern = 0, **patterns = 0;
  int rv;
  enum stat_client_cmd_e cmd = STAT_CLIENT_CMD_UNKNOWN;
  void *heap_base;

  heap_base = clib_mem_vm_map ((void *) 0x10000000ULL, 128 << 20);
  clib_mem_init (heap_base, 128 << 20);

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

  u8 **dir;
  int i, j, k;
  stat_segment_data_t *res;
  stat_segment_cached_pointer_t *cp;

  dir = stat_segment_ls (patterns);

  switch (cmd)
    {
    case STAT_CLIENT_CMD_LS:
      /* List all counters */
      for (i = 0; i < vec_len (dir); i++)
	{
	  printf ("%s\n", (char *) dir[i]);
	}
      break;

    case STAT_CLIENT_CMD_DUMP:
      res = stat_segment_dump (dir);
      for (i = 0; i < vec_len (res); i++)
	{
	  switch (res[i].type)
	    {
	    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
	      for (k = 0; k < vec_len (res[i].simple_counter_vec) - 1; k++)
		for (j = 0; j < vec_len (res[i].simple_counter_vec[k]); j++)
		  fformat (stdout, "[%d @ %d]: %lld packets %s\n",
			   j, k, res[i].simple_counter_vec[k][j],
			   res[i].name);
	      break;

	    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
	      for (k = 0; k < vec_len (res[i].simple_counter_vec); k++)
		for (j = 0; j < vec_len (res[i].combined_counter_vec[k]); j++)
		  fformat (stdout, "[%d @ %d]: %lld packets, %lld bytes %s\n",
			   j, k, res[i].combined_counter_vec[k][j].packets,
			   res[i].combined_counter_vec[k][j].bytes,
			   res[i].name);
	      break;

	    case STAT_DIR_TYPE_ERROR_INDEX:
	      fformat (stdout, "%lld %s\n", res[i].error_value, dir[i]);
	      break;

	    case STAT_DIR_TYPE_SCALAR_POINTER:
	      fformat (stdout, "%.2f %s\n", dir[i], res[i].scalar_value,
		       res[i].name);
	      break;

	    default:
	      ;
	    }
	}
      stat_segment_data_free (res);
      break;

    case STAT_CLIENT_CMD_POLL:
      cp = stat_segment_register (dir);
      if (!cp)
	{
	  fformat (stderr,
		   "Couldn't register required counters with stat segment\n");
	  exit (1);
	}
      stat_poll_loop (cp);
      /* We can only exist the pool loop if we lost connection to VPP */
      stat_segment_disconnect ();
      goto reconnect;
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
