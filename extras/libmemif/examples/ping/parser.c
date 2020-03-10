/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <sched.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "parser.h"

#define PARSER_ERROR_MODE              "Different roles on single socket not supported"
#define PARSER_ERROR_ROLE_PARAMETER    "Unsuported parameter for 'role'"
#define PARSER_ERROR_NAME_MISSING      "Missing name of connection"
#define PARSER_ERROR_NAME_EXIST        "Name of connection exist"

#define PARSER_ERROR_AFFINITY          "Missing parameters for setting of cpu affinity"
#define PARSER_ERORR_AFFINITY_NUM      "Bad parameter for affinity cpu"

#define PARSER_ERROR_PARAMETER_ID      "Invalid parameter for 'id'"
#define PARSER_ERROR_USED_ID           "Parameter of 'id' previously used"

#define PARSER_ERROR_QUEUES_RANGE      "Number for parameter 'qpairs' beyond of range <1,255>"
#define PARSER_ERROR_QUEUES_FORMAT     "Argument of parameter 'qpairs' isn't numeric value"

#define PARSER_ERROR_RSIZE_RANGE       "Number for parameter 'rsize' beyond of range <1,14>"
#define PARSER_ERROR_RSIZE_FORMAT      "Argument of parameter 'rsize' isn't numeric value"

#define PARSER_ERROR_BSIZE_FORMAT      "Argument of parameter 'bsize' isn't numeric value"

#define PARSER_ERROR_IP_FORMAT         "Non valid ip address"
#define PARSER_ERROR_MOD_Q0_PARAMETER  "Unsuported parameter for 'q0-rxmode'"
#define PARSER_ERORR_DOMAIN_NUM        "Bad number for 'domain'."
#define PARSER_ERROR_MAX_DOMAIN        "Number of domain achieved maximum number"
#define PARSER_ERROR_MAX_CONNECTION    "Number of connections achieved maximum number"
#define PARSER_ERROR_EMPTY_ARGUMENT    "Empty argument"
#define PARSER_ERROR_PARAMETER_MISSING "Missing parameter"
#define PARSER_ERROR_UKNOWN_SETTING    "Unknown setting"
#define PARSER_ERROR_UKNOWN_ARGUMENT   "Unknown argument"




void
assign_unique_id (memif_connection_t * c, int idx_max)
{
  int idx_conn = idx_max;
  uint32_t impl_interface_id = 0;

  while (idx_conn)
    {
      memif_connection_t *c1 = &memif_connections[--idx_conn];

      if (c1 == c)
	continue;

      if (!c1->sock_name || !c->sock_name)
	{
	  if (c1->sock_name)
	    continue;

	  if (c->sock_name)
	    continue;
	}
      else if (strcmp (c1->sock_name, c->sock_name) != 0)
	continue;

      if (c1->args.interface_id == impl_interface_id)
	{
	  impl_interface_id++;
	  idx_conn = idx_max;
	  continue;
	}
    }

  c->args.interface_id = impl_interface_id;
}


int
bad_params (memif_connection_t * c, char **err_msg)
{
  int cp_cnt_conn = cnt_conn;
  while (cp_cnt_conn)
    {
      memif_connection_t *c1 = &memif_connections[--cp_cnt_conn];

      if (c1 == c)
	continue;

      if (!c1->sock_name || !c->sock_name)
	{
	  if (c1->sock_name)
	    continue;

	  if (c->sock_name)
	    continue;
	}
      else if (strcmp (c1->sock_name, c->sock_name) != 0)
	continue;

      if (c1->args.is_master != c->args.is_master)
	{
	  *err_msg = PARSER_ERROR_MODE;
	  return 1;
	}

      if (!c->id_is_expl)
	continue;

      if (c1->args.interface_id == c->args.interface_id)
	{
	  if (c1->id_is_expl)
	    {
	      *err_msg = PARSER_ERROR_USED_ID;
	      return 1;
	    }
	  else
	    {
	      assign_unique_id (c1, cnt_conn + 1);
	    }
	}
    }

  return 0;
}

int
parse_corelist (cpu_set_t * corelist, char *saveptr1, char **err_msg)
{
  char *str_parse = strtok_r (NULL, "=", &saveptr1);
  if (!str_parse)
    {
      *err_msg = PARSER_ERROR_AFFINITY;
      return -1;
    }

  int cpu;
  str_parse = strtok (str_parse, ",");
  CPU_ZERO (corelist);

  do
    {
      char *pEnd;
      cpu = strtol (str_parse, &pEnd, 10);

      if (*pEnd != '\0')
	{
	  *err_msg = PARSER_ERORR_AFFINITY_NUM;
	  return -1;
	}
      else
	CPU_SET (cpu, corelist);
    }
  while (str_parse = strtok (NULL, ","));

  return 0;
}

int
set_arg_conn (memif_connection_t * c, char *saveptr1, char **err_msg)
{
  char *saveptr2;
  char *str_parse;

  if (saveptr1[0] == ',' || !(str_parse = strtok_r (NULL, ",", &saveptr1)))
    {
      *err_msg = PARSER_ERROR_NAME_MISSING;
      return -1;
    }

  int pos_conn;
  for (pos_conn = 0; pos_conn < cnt_conn; pos_conn++)
    {
      if (strcmp (memif_connections[pos_conn].args.interface_name, str_parse)
	  == 0)
	{
	  *err_msg = PARSER_ERROR_NAME_EXIST;
	  return -1;
	}
    }

  strncpy (c->args.interface_name, str_parse, strlen (str_parse) < 32 ?
	   strlen (str_parse) : 32);

  while (str_parse = strtok_r (NULL, "=", &saveptr1))
    {
      char str_out[200];
      char *pEnd;
      char *value;

      if (str_parse[0] == ',')
	{
	  *err_msg = PARSER_ERROR_EMPTY_ARGUMENT;
	  return -1;
	}

      char cp_param[1 + strlen (str_parse)];
      strcpy (cp_param, str_parse);


      if (strcmp (cp_param, "lcores") == 0)
	{
	  if (saveptr1[0] == '[')
	    {
	      saveptr1++;
	      value = strtok_r (NULL, "]", &saveptr1);
	    }
	  else
	    {
	      value = strtok_r (NULL, ",", &saveptr1);
	    }

	  if (saveptr1[0] == ',')
	    saveptr1++;

	  if (parse_corelist (&c->q0_corelist, value, err_msg) < 0)
	    return -1;

	  continue;
	}

      value = strtok_r (NULL, ",", &saveptr1);
      if (!value)
	{
	  *err_msg = PARSER_ERROR_PARAMETER_MISSING;
	  return -1;
	}

      if (strcmp (cp_param, "id") == 0)
	{

	  c->args.interface_id = strtol (value, &pEnd, 10);
	  c->id_is_expl = 1;

	  if (*pEnd != '\0')
	    {
	      *err_msg = PARSER_ERROR_PARAMETER_ID;
	      return -1;
	    }
	}
      else if (strcmp (cp_param, "qpairs") == 0)
	{
	  int32_t q_cnt = strtol (value, &pEnd, 10);

	  if (*pEnd != '\0')
	    {
	      *err_msg = PARSER_ERROR_QUEUES_FORMAT;
	      return -1;
	    }

	  if (q_cnt < 1 || q_cnt > 255)
	    {
	      *err_msg = PARSER_ERROR_QUEUES_RANGE;
	      return -1;
	    }
	  c->args.num_s2m_rings = (uint8_t) q_cnt;
	  c->args.num_m2s_rings = (uint8_t) q_cnt;
	}
      else if (strcmp (cp_param, "rsize") == 0)
	{
	  int32_t log2_ring_size = strtol (value, &pEnd, 10);

	  if (*pEnd != '\0')
	    {
	      *err_msg = PARSER_ERROR_RSIZE_FORMAT;
	      return -1;
	    }

	  if (log2_ring_size > 14 || log2_ring_size < 1)
	    {
	      *err_msg = PARSER_ERROR_RSIZE_RANGE;
	      return -1;
	    }

	  c->args.log2_ring_size = (uint8_t) log2_ring_size;
	}
      else if (strcmp (cp_param, "bsize") == 0)
	{
	  uint16_t buffer_size = strtol (value, &pEnd, 10);

	  if (*pEnd != '\0')
	    {
	      *err_msg = PARSER_ERROR_BSIZE_FORMAT;
	      return -1;
	    }

	  c->args.buffer_size = buffer_size;
	}
      else if (strcmp (cp_param, "ip") == 0)
	{
	  if (inet_pton (AF_INET, value, (void *) c->ip_src) != 1)
	    {
	      *err_msg = PARSER_ERROR_IP_FORMAT;
	      return -1;
	    }
	}
      else if (strcmp (cp_param, "socket") == 0)
	{
	  c->sock_name = malloc (1 + strlen (value));
	  strcpy (c->sock_name, value);
	}
      else if (strcmp (cp_param, "role") == 0)
	{
	  if (strcmp (value, "master") == 0)
	    c->args.is_master = 1;
	  else if (strcmp (value, "slave") == 0)
	    c->args.is_master = 0;
	  else
	    {
	      *err_msg = PARSER_ERROR_ROLE_PARAMETER;
	      return -1;
	    }
	}
      else if (strcmp (cp_param, "q0-rxmode") == 0)
	{
	  if (strcmp (value, "poll") == 0)
	    c->set_q0_poll = 1;
	  else if (strcmp (value, "interrupt") == 0)
	    c->set_q0_poll = 0;
	  else
	    {
	      *err_msg = PARSER_ERROR_MOD_Q0_PARAMETER;
	      return -1;
	    }
	}
      else if (strcmp (cp_param, "domain") == 0)
	{
	  uint32_t id_domain = strtol (value, &pEnd, 10);

	  if (*pEnd != '\0')
	    {
	      *err_msg = PARSER_ERORR_DOMAIN_NUM;
	      return -1;
	    }

	  int idx_domain = itms_bridge.cnt_domain;

	  if (idx_domain >= MAX_ITM_BRIDGE)
	    {
	      *err_msg = PARSER_ERROR_MAX_DOMAIN;
	      return -1;
	    }

	  uint8_t domain_exist = 0;
	  struct _table *domain_itm;
	  while (idx_domain)
	    {
	      domain_itm = &itms_bridge.table[--idx_domain];

	      if (domain_itm->id_domain == id_domain)
		{
		  domain_exist = 1;

		  if (domain_itm->cnt_items >= MAX_ITM_BRIDGE)
		    {
		      *err_msg = PARSER_ERROR_MAX_DOMAIN;
		      return -1;
		    }
		  else
		    {
		      domain_itm->idx_conn[domain_itm->cnt_items] = cnt_conn;
		      domain_itm->cnt_items++;
		      c->idx_domain = idx_domain;
		      break;
		    }
		}
	    }

	  if (!domain_exist)
	    {
	      idx_domain = itms_bridge.cnt_domain;
	      c->idx_domain = idx_domain;
	      domain_itm = &itms_bridge.table[idx_domain];
	      domain_itm->id_domain = id_domain;
	      domain_itm->idx_conn[0] = cnt_conn;
	      domain_itm->cnt_items++;
	      itms_bridge.cnt_domain++;
	    }
	}
      else
	{
	  *err_msg = PARSER_ERROR_UKNOWN_ARGUMENT;
	  return -1;
	}
    }

  if (CPU_COUNT (&c->q0_corelist) > 0 && c->set_q0_poll == 0)
    {
      INFO ("in interface \"%s\" will be ignored setting of cpu affinity,",
	    c->args.interface_name);
      INFO ("because qid 0 isn't in polling mode.");
    }

  return 0;
}

int
rm_itm_domain (memif_connection_t * c, uint16_t idx_conn)
{
  int idx_domain = c->idx_domain;

  if (idx_domain < 0)
    return 0;

  if (itms_bridge.cnt_domain <= idx_domain)
    {
      INFO ("Unexpected error. Index into domain is beyond of valid number.");
      return -1;
    }

  struct _table *domain_itm = &itms_bridge.table[idx_domain];
  uint16_t idx_table = domain_itm->cnt_items - 1;

  if (idx_table < 0)
    {
      INFO
	("Unexpected error. In domain index %d isn't any item for remove.",
	 idx_domain);
      return -1;
    }

  if (domain_itm->idx_conn[domain_itm->cnt_items - 1] == idx_conn)
    {
      domain_itm->cnt_items--;
      DBG ("remove item from bridge");
      return 1;
    }

  INFO
    ("Unexpected error. Index of connection %d isn't find in domain index %d.",
     idx_conn, idx_domain);
  return -1;
}

int
parse_arg (char argv[], char **err_msg)
{
  // copy argument because strtok_r modified original string of argument
  char arg_cp[1 + strlen (argv)];
  strcpy (arg_cp, argv);

  char *saveptr1;
  char *str_parse = strtok_r (arg_cp, "=", &saveptr1);

  if (strcmp (str_parse, "--master-lcore") == 0)
    {
      if (!saveptr1 || saveptr1[0] == '\0')
	{
	  *err_msg = PARSER_ERROR_AFFINITY;
	  return -1;
	}

      char *pEnd;
      int cpu = strtol (saveptr1, &pEnd, 10);

      if (*pEnd != '\0')
	{
	  *err_msg = PARSER_ERORR_AFFINITY_NUM;
	  return -1;
	}

      cpu_set_t corelist;
      CPU_ZERO (&corelist);
      CPU_SET (cpu, &corelist);
      pid_t pid = getpid ();

      if (sched_setaffinity (pid, sizeof (corelist), &corelist) == -1)
	INFO ("setting of CPU affinity fail for --master-lcore setting");
    }
  else if (strcmp (str_parse, "--vdev") == 0)
    {
      if (cnt_conn >= MAX_CONNS)
	{
	  *err_msg = PARSER_ERROR_MAX_CONNECTION;
	  return -1;
	}

      memif_connection_t *c = &memif_connections[cnt_conn];
      memset (&c->args, 0, sizeof (memif_conn_args_t));
      c->args.is_master = 0;
      c->args.log2_ring_size = 10;
      c->args.num_s2m_rings = 1;
      c->args.num_m2s_rings = 1;
      c->args.buffer_size = 2048;
      c->idx_domain = -1;
      CPU_ZERO (&c->q0_corelist);
      c->set_q0_poll = 0;
      c->index = cnt_conn;
      c->ip_src[0] = 192;
      c->ip_src[1] = 168;
      c->ip_src[2] = cnt_conn + 1;
      c->ip_src[3] = 2;
      c->sock_name = NULL;
      c->id_is_expl = 0;

      if (set_arg_conn (c, saveptr1, err_msg) == 0)
	{
	  if (!c->id_is_expl)
	    assign_unique_id (c, cnt_conn);

	  if (bad_params (c, err_msg))
	    {
	      rm_itm_domain (c, cnt_conn);
	      return -1;
	    }

	  cnt_conn++;
	}
      else
	{
	  rm_itm_domain (c, cnt_conn);
	  return -1;
	}
    }
  else
    {
      *err_msg = PARSER_ERROR_UKNOWN_SETTING;
      return -1;
    }

  return 0;
}

int
valid_ping (char *arg, uint8_t ip_ping[4], int *ping_index, int *ping_qid)
{
  char *ip = strtok (arg, " ");

  if (!ip)
    {
      printf
	("Usage: ping destination [-q queue_id] [-i index_connection]\n");
      return 0;
    }

  if (inet_pton (AF_INET, ip, (void *) ip_ping) != 1)
    {
      printf ("ping: %s: Name or service not known\n", ip);
      return 0;
    }

  *ping_qid = 0;
  *ping_index = 0;
  char *next_par;
  char *pEnd;

  while (next_par = strtok (NULL, " "))
    {
      if (strcmp (next_par, "-q") == 0)
	{
	  next_par = strtok (NULL, " ");

	  if (!next_par)
	    {
	      printf ("missing argument for option -q\n");
	      return 0;
	    }

	  *ping_qid = strtol (next_par, &pEnd, 10);


	  if (*pEnd != '\0')
	    {
	      printf ("%s isn't numeric value for -q option\n", next_par);
	      return 0;
	    }
	}
      else if (strcmp (next_par, "-i") == 0)
	{
	  next_par = strtok (NULL, " ");

	  if (!next_par)
	    {
	      printf ("missing argument for option -i\n");
	      return 0;
	    }

	  uint32_t conn_index = strtol (next_par, &pEnd, 10);

	  if (*pEnd != '\0')
	    {
	      printf ("%s isn't valid numeric value for -i option\n",
		      next_par);
	      return 0;
	    }

	  if (cnt_conn <= conn_index)
	    {
	      printf
		("index %d isn't valid, option -i acept only number in range <0, %d>\n",
		 conn_index, cnt_conn - 1);
	      return 0;
	    }
	  else
	    *ping_index = conn_index;

	}
      else
	{
	  printf ("%s is unknown parameter\n", next_par);
	  return 0;
	}
    }


  memif_connection_t *c = &memif_connections[*ping_index];

  if (c->current_cnt_q <= 0)
    {
      printf
	("index of connection %d have non valid count of queue %d\n",
	 *ping_index, c->current_cnt_q);
      return 0;
    }

  if (*ping_qid >= c->current_cnt_q)
    {
      printf
	("index of connection %d accept -q number only in range <0, %d>\n",
	 *ping_index, c->current_cnt_q - 1);
      return 0;
    }

  return 1;
}
