#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <sched.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "parser.h"


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
bad_params (memif_connection_t * c)
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

      if (c1->args.is_master != c->args.is_master && c1->mode_is_expl)
	{
	  if (c->mode_is_expl)
	    {
	      printf ("%s mode not be used on socket \"%s\"\n",
		      c->args.is_master ? "master" : "slave",
		      c->sock_name ? c->sock_name : "(default socket)");
	      printf ("\t, because one or more %s",
		      c1->args.is_master ? "master" : "slave");
	      printf (" already are used on this socket\n");
	      return 1;
	    }
	  else
	    c->args.is_master = c1->args.is_master;
	}

      if (!c->id_is_expl)
	continue;

      if (c1->args.interface_id == c->args.interface_id)
	{
	  if (c1->id_is_expl)
	    {
	      printf ("interface_id %d is explicitly alredy used\n",
		      c->args.interface_id);
	      return 1;
	    }
	  else
	    {
	      assign_unique_id (c1, cnt_conn + 1);
	    }
	}
    }

/* all connection with implicitly setting of mode must be set into same mode
as connection with explicitly setting of mode */
  cp_cnt_conn = cnt_conn;
  while (c->mode_is_expl && cp_cnt_conn)
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

      if (!c1->mode_is_expl)
	c1->args.is_master = c->args.is_master;
    }

  return 0;
}

int
set_affinity_cpu (char *saveptr1)
{
  char *str_parse = strtok_r (NULL, "=", &saveptr1);
  if (!str_parse)
    {
      printf ("missing parameters for setting of cpu affinity\n");
      return -1;
    }

  int cpu;
  str_parse = strtok (str_parse, ",");
  cpu_set_t set;
  CPU_ZERO (&set);

  do
    {
      char *pEnd;
      cpu = strtol (str_parse, &pEnd, 10);

      if (*pEnd != '\0')
	{
	  printf ("%s isn't valid number for parameter number of cpu\n",
		  str_parse);
	  return -1;
	}
      else
	CPU_SET (cpu, &set);
    }
  while (str_parse = strtok (NULL, ","));

  pid_t pid = getpid ();

  if (sched_setaffinity (pid, sizeof (set), &set) == -1)
    INFO ("setting of CPU affinity fail");

  return 0;
}

int
set_arg_conn (memif_connection_t * c, char *saveptr1)
{
  char *saveptr2;
  char *str_parse;

  str_parse = strtok_r (NULL, "=,", &saveptr1);

  if (!str_parse)
    {
      printf ("missing name connection\n");
      return -1;
    }

  int pos_conn;
  for (pos_conn = 0; pos_conn < cnt_conn; pos_conn++)
    {
      if (strcmp (memif_connections[pos_conn].args.interface_name, str_parse)
	  == 0)
	{
	  printf ("name %s exist\n", str_parse);
	  return -1;
	}
    }

  strncpy (c->args.interface_name, str_parse, strlen (str_parse) < 32 ?
	   strlen (str_parse) : 32);

  while (str_parse = strtok_r (NULL, ",", &saveptr1))
    {
      char str_out[200];
      char *pEnd;

      if (str_parse[0] == '=')
	{
	  printf ("some parameter isn't set\n");
	  return -1;
	}

      str_parse = strtok_r (str_parse, " =", &saveptr2);
      char cp_param[1 + strlen (str_parse)];
      strcpy (cp_param, str_parse);
      char *value = strtok_r (NULL, " =", &saveptr2);

      if (!value)
	{
	  printf ("value for parameter \"%s\" isn't inserted\n", cp_param);
	  return -1;
	}

      if (strcmp (cp_param, "i") == 0)
	{

	  c->args.interface_id = strtol (value, &pEnd, 10);
	  c->id_is_expl = 1;

	  if (*pEnd != '\0')
	    {
	      printf ("%s isn't valid number for parameter 'i'\n", value);
	      return -1;
	    }
	}
      else if (strcmp (cp_param, "qn") == 0)
	{
	  uint8_t q_cnt;
	  q_cnt = atoi (value);
	  if (q_cnt < 1)
	    {
	      printf ("count of queue must be in range <1,255>\n");
	      return -1;
	    }
	  c->args.num_s2m_rings = q_cnt;
	  c->args.num_m2s_rings = q_cnt;
	}
      else if (strcmp (cp_param, "aff") == 0)
	{
	  int8_t af_cpu = strtol (value, &pEnd, 10);

	  if (*pEnd != '\0')
	    {
	      printf ("%s isn't numeric value for af option\n", value);
	      return -1;
	    }

	  c->set_q0_aff = af_cpu;
	}
      else if (strcmp (cp_param, "rs") == 0)
	{
	  uint8_t log2_ring_size = atoi (value);
	  if (log2_ring_size > 14)
	    {
	      printf ("ring size must be in range <1,14>\n");
	      return -1;
	    }

	  c->args.log2_ring_size = log2_ring_size;
	}
      else if (strcmp (cp_param, "bs") == 0)
	{
	  c->args.buffer_size = atoi (value);
	}
      else if (strcmp (cp_param, "ip") == 0)
	{
	  if (inet_pton (AF_INET, value, (void *) c->ip_src) != 1)
	    {
	      printf ("non valid ip address %s\n", value);
	      return -1;
	    }
	}
      else if (strcmp (cp_param, "s") == 0)
	{
	  c->sock_name = malloc (1 + strlen (value));
	  strcpy (c->sock_name, value);
	}
      else if (strcmp (cp_param, "r") == 0)
	{
	  if (strcmp (value, "master") == 0)
	    c->args.is_master = 1;
	  else if (strcmp (value, "slave") == 0)
	    c->args.is_master = 0;
	  else
	    {
	      printf ("\"%s\" is not supported\n", value);
	      return -1;
	    }
	  c->mode_is_expl = 1;
	}
      else if (strcmp (cp_param, "q0") == 0)
	{
	  if (strcmp (value, "poll") == 0)
	    c->set_q0_poll = 1;
	  else if (strcmp (value, "interrupt") == 0)
	    c->set_q0_poll = 0;
	  else
	    {
	      printf ("\"%s\" is not supported\n", value);
	      return -1;
	    }
	}
      else if (strcmp (cp_param, "domain") == 0)
	{
	  int id_domain;
	  int cnt_par = sscanf (value, "%d", &id_domain);

	  if (cnt_par != 1)
	    {
	      printf ("%s is bad value for id of domain\n", value);
	      return -1;
	    }

	  int idx_domain = itms_bridge.cnt_domain;

	  if (idx_domain >= MAX_ITM_BRIDGE)
	    {
	      printf ("ins't enught free domain items\n");
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
		      printf ("count of index in domain %d is more than %d\n",
			      id_domain, MAX_ITM_BRIDGE);
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
	  printf ("\"%s\" is unknown parameter\n", cp_param);
	  return -1;
	}
    }

  if (c->set_q0_aff >= 0 && c->set_q0_poll == 0)
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
      printf
	("Unexpected error. Index into domain is beyond of valid number.\n");
      return -1;
    }

  struct _table *domain_itm = &itms_bridge.table[idx_domain];
  uint16_t idx_table = domain_itm->cnt_items - 1;

  if (idx_table < 0)
    {
      printf
	("Unexpected error. In domain index %d isn't any item for remove\n",
	 idx_domain);
      return -1;
    }

  if (domain_itm->idx_conn[domain_itm->cnt_items - 1] == idx_conn)
    {
      domain_itm->cnt_items--;
      DBG ("remove item from bridge");
      return 1;
    }

  printf
    ("Unexpected error. Index of connection %d isn't find in domain index %d\n",
     idx_conn, idx_domain);
  return -1;
}

int
parse_arg (char argv[])
{
  // copy argument because strtok_r modified original string of argument
  char arg_cp[1 + strlen (argv)];
  strcpy (arg_cp, argv);

  char *saveptr1;
  char *str_parse = strtok_r (arg_cp, "=", &saveptr1);

  if (strcmp (str_parse, "--aff") == 0)
    {
      if (set_affinity_cpu (saveptr1) < 0)
	return -1;
    }
  else if (strcmp (str_parse, "--vdev") == 0)
    {
      if (cnt_conn >= MAX_CONNS)
	{
	  printf ("count of connections achieved maximum number %d\n",
		  MAX_CONNS);
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
      c->set_q0_aff = -1;
      c->set_q0_poll = 0;
      c->mode_is_expl = 0;
      c->index = cnt_conn;
      c->ip_src[0] = 192;
      c->ip_src[1] = 168;
      c->ip_src[2] = cnt_conn + 1;
      c->ip_src[3] = 2;
      c->sock_name = NULL;
      c->id_is_expl = 0;

      if (set_arg_conn (c, saveptr1) == 0)
	{
	  if (!c->id_is_expl)
	    assign_unique_id (c, cnt_conn);

	  if (bad_params (c))
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
      printf ("unknown setting \"%s\"\n", str_parse);
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
