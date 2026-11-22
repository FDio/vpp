/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <getopt.h>
#include <string.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <vlib/vlib.h>
#include <vlibapi/api_types.h>
#include <vlibapi/api_desc.h>
#include <vppinfra/hash.h>
#include <vppinfra/json.h>
#include <vppinfra/pool.h>

/* VPP API client includes */
#include <vpp-api/client/vppapiclient.h>
#include <vlibmemory/memclnt.api_types.h>

#include <limits.h>
#include "vat2.h"

bool vat2_debug;

/*
 * Filter these messages as they are used to manage the API connection to VPP
 */
char *filter_messages_strings[] = { "memclnt_create",
				    "memclnt_delete",
				    "sockclnt_create",
				    "sockclnt_delete",
				    "memclnt_rx_thread_suspend",
				    "memclnt_read_timeout",
				    "rx_thread_exit",
				    "trace_plugin_msg_ids",
				    0 };

static bool
filter_message (char *msgname)
{
  char **p = filter_messages_strings;

  while (*p)
    {
      if (strcmp (*p, msgname) == 0)
	return true;
      p++;
    }
  return false;
}

/* A message which can be sent, with what VPP answers. The messages and their
 * layout come from the .api.json of the files, from VPP or from a directory. */
typedef struct
{
  const vl_api_desc_file_t *f;
  const vl_api_desc_type_t *t;
} vat2_msg_t;

static vat2_msg_t *vat2_msgs;
static uword *vat2_msg_by_name;

void
vac_callback (unsigned char *data, int len)
{
  u16 result_msg_id = ntohs (*((u16 *) data));
  DBG ("Received something async: %d\n", result_msg_id);
}

static u8 *
vat2_read_file (char *filename)
{
  FILE *f = fopen (filename, "r");
  u8 *buf = 0;
  size_t n;
  u8 chunk[4096];

  if (!f)
    return 0;

  while ((n = fread (chunk, 1, sizeof (chunk), f)) > 0)
    vec_add (buf, chunk, n);

  fclose (f);
  return buf;
}

/* The descriptors of the file at value_index and its messages */
static void
vat2_add_file (clib_json_text_t *j, int value_index)
{
  const vl_api_desc_file_t *f;
  clib_error_t *err;

  err = vl_api_desc_file_from_json (j, value_index, &f);
  if (err)
    {
      if (vat2_debug)
	fformat (stderr, "Cannot use the API description: %U\n", format_clib_error, err);
      clib_error_free (err);
      return;
    }

  for (u32 i = 0; i < f->n_msgs; i++)
    {
      vat2_msg_t m = { .f = f, .t = &f->msgs[i] };

      if (hash_get_mem (vat2_msg_by_name, m.t->name))
	continue;

      vec_add1 (vat2_msgs, m);
      hash_set_mem (vat2_msg_by_name, m.t->name, vec_len (vat2_msgs) - 1);
    }
}

static vat2_msg_t *
vat2_find_msg (const char *name)
{
  uword *p = hash_get_mem (vat2_msg_by_name, name);

  return p ? &vat2_msgs[p[0]] : 0;
}

static u8 *
vat2_msg_key (const vl_api_desc_type_t *t)
{
  return format (0, "%s_%08x%c", t->name, t->crc, 0);
}

static int
vat2_msg_index (const vl_api_desc_type_t *t)
{
  u8 *key = vat2_msg_key (t);
  int id = vac_get_msg_index ((char *) key);

  vec_free (key);
  return id;
}

/* ---- where the API comes from */

static void
vat2_load_array (clib_json_text_t *j)
{
  int v;

  if (!clib_json_value_is_array (j, j->root_value))
    {
      vat2_add_file (j, j->root_value);
      return;
    }

  foreach_clib_json_array_value (j, j->root_value, v)
    vat2_add_file (j, v);
}

static void
vat2_load_dir (char *dir)
{
  DIR *d = opendir (dir);
  struct dirent *e;

  if (!d)
    return;

  while ((e = readdir (d)))
    {
      u8 *path;
      struct stat st;
      uword len = strlen (e->d_name);

      if (e->d_name[0] == '.')
	continue;

      path = format (0, "%s/%s%c", dir, e->d_name, 0);

      if (stat ((char *) path, &st) == 0 && S_ISDIR (st.st_mode))
	vat2_load_dir ((char *) path);
      else if (len > 9 && !strcmp (e->d_name + len - 9, ".api.json"))
	{
	  u8 *text = vat2_read_file ((char *) path);
	  clib_json_text_t j;

	  if (text && clib_json_init_from_string (&j, (char *) text, vec_len (text)) == 0)
	    {
	      vat2_add_file (&j, j.root_value);
	      clib_json_free (&j);
	    }
	  vec_free (text);
	}

      vec_free (path);
    }

  closedir (d);
}

static u8 *
vat2_find_api_dir (void)
{
  char *p, path[PATH_MAX];
  int rv;

  /* find executable path */
  if ((rv = readlink ("/proc/self/exe", path, PATH_MAX - 1)) == -1)
    return 0;

  /* readlink doesn't provide null termination */
  path[rv] = 0;

  /* strip filename and bin/ */
  if ((p = strrchr (path, '/')) == 0)
    return 0;
  *p = 0;
  if ((p = strrchr (path, '/')) == 0)
    return 0;
  *p = 0;

  return format (0, "%s/share/vpp/api%c", path, 0);
}

/* The API of the VPP which we are connected to: what it has is what it
 * understands */
static int
vat2_load_from_vpp (void)
{
  vl_api_get_api_json_t mp = { 0 };
  vl_api_get_api_json_reply_t *rmp;
  clib_json_text_t j;
  clib_error_t *err;
  int reply_id = vac_get_msg_index (VL_API_GET_API_JSON_REPLY_CRC);
  char *p;
  int l;
  u32 len;

  mp._vl_msg_id = htons (vac_get_msg_index (VL_API_GET_API_JSON_CRC));
  mp.context = htonl (1);
  vac_write ((char *) &mp, sizeof (mp));

  /* the reply can be preceded by events */
  while (1)
    {
      vac_read (&p, &l, 10);
      if (p == 0 || l == 0)
	{
	  fprintf (stderr, "No reply to get_api_json\n");
	  return -1;
	}
      if (ntohs (*((u16 *) p)) == reply_id)
	break;
    }

  rmp = (vl_api_get_api_json_reply_t *) p;
  if (l < sizeof (*rmp) || ntohl (rmp->retval))
    {
      fprintf (stderr, "get_api_json failed\n");
      return -1;
    }

  len = ntohl (rmp->json.length);
  if (len > l - sizeof (*rmp))
    {
      fprintf (stderr, "Truncated reply to get_api_json\n");
      return -1;
    }

  err = clib_json_init_from_string (&j, (char *) rmp->json.buf, len);
  if (err)
    {
      fprintf (stderr, "Cannot parse the API of VPP: %s\n",
	       (char *) format (0, "%U%c", format_clib_error, err, 0));
      clib_error_free (err);
      return -1;
    }

  vat2_load_array (&j);
  clib_json_free (&j);
  return 0;
}

/* ---- messages */

static void
vat2_print_json (clib_json_text_t *j)
{
  u8 *s = format (0, "%U", format_clib_json_text, j);

  if (s)
    printf ("%.*s\n", (int) vec_len (s), s);
  vec_free (s);
}

/* the reply read from VPP, in network byte order */
static int
vat2_read_reply (char **p, int *l)
{
  vac_read (p, l, 5); // XXX: Fix timeout
  return !(*p == 0 || *l == 0);
}

/* converts a reply to JSON, false if it is not what the message says */
static int
vat2_reply_to_json (const vl_api_desc_file_t *f, const vl_api_desc_type_t *t, char *p, int l,
		    clib_json_text_t *j)
{
  vl_api_desc_msg_t dm = { .file = f, .type = t };

  if ((u32) l < t->size || vl_api_desc_msg_calc_size (&dm, p) > (uword) l)
    return -1;

  vl_api_desc_msg_endian (&dm, p, 0);
  return vl_api_desc_msg_to_json (&dm, p, j);
}

static void
vat2_control_ping (u32 context)
{
  vl_api_control_ping_t mp = { 0 };

  mp._vl_msg_id = htons (vac_get_msg_index (VL_API_CONTROL_PING_CRC));
  mp.context = htonl (context);
  vac_write ((char *) &mp, sizeof (mp));
}

/* sends the message and reads what the service answers, the JSON of it is
 * left in *out, 0 if it did not work */
static int
vat2_call (vat2_msg_t *m, u8 *msg, clib_json_text_t *out)
{
  const vl_api_desc_type_t *t = m->t, *r = vl_api_desc_reply (m->f, t),
			   *d = vl_api_desc_details (m->f, t);
  int id = vat2_msg_index (t), reply_id, details_id = -1, ping_reply_id = -1;
  int is_stream = !!(t->flags & VL_API_DTF_STREAM);
  int is_dump = is_stream && !d;
  int rv = -1;
  char *p;
  int l;

  if (!r || id < 0 || (reply_id = vat2_msg_index (r)) < 0)
    {
      fprintf (stderr, "Message not known to VPP: %s\n", t->name);
      return -1;
    }

  if (d && (details_id = vat2_msg_index (d)) < 0)
    {
      fprintf (stderr, "Message not known to VPP: %s\n", d->name);
      return -1;
    }

  *(u16 *) msg = id;
  vl_api_desc_msg_endian (&(vl_api_desc_msg_t) { .file = m->f, .type = t }, msg, 1);
  vac_write ((char *) msg, vec_len (msg));

  if (!is_stream)
    {
      if (!vat2_read_reply (&p, &l))
	return -1;

      // XXX Will fail in case of event received. Do loop
      if (ntohs (*((u16 *) p)) != reply_id)
	{
	  fprintf (stderr, "Mismatched reply\n");
	  return -1;
	}

      return vat2_reply_to_json (m->f, r, p, l, out);
    }

  clib_json_init (out);
  clib_json_add_array (out, 0);

  if (is_dump)
    {
      vat2_control_ping (123); // FIX CONTEXT
      ping_reply_id = vac_get_msg_index (VL_API_CONTROL_PING_REPLY_CRC);
      /* the details of a dump are the reply of the service */
      details_id = reply_id;
    }

  while (vat2_read_reply (&p, &l))
    {
      const vl_api_desc_type_t *dt = 0;
      int mid = ntohs (*((u16 *) p));
      clib_json_text_t item;

      /* Message can be one of [details, the reply (control_ping_reply for
       * a dump) or an unrelated event] */
      if (mid == (is_dump ? ping_reply_id : reply_id))
	{
	  if (!is_dump && vat2_reply_to_json (m->f, r, p, l, &item) == 0)
	    {
	      clib_json_append (out, &item, 0);
	      clib_json_free (&item);
	    }
	  rv = 0;
	  break;
	}

      if (mid == details_id)
	dt = is_dump ? r : d;

      if (dt)
	{
	  if (vat2_reply_to_json (m->f, dt, p, l, &item))
	    break;

	  clib_json_append (out, &item, 0);
	  clib_json_free (&item);
	}
    }

  if (rv)
    clib_json_free (out);

  return rv;
}

static int
vat2_exec_command_by_name (char *msgname, clib_json_text_t *j, int o)
{
  vat2_msg_t *m;
  clib_json_text_t out;
  u32 crc = 0;
  u8 *msg;
  int c, rv;

  if (filter_message (msgname))
    return 0;

  c = clib_json_find_object_value_by_name (j, o, "_crc");
  if (c >= 0 && clib_json_value_is_string (j, c))
    {
      u8 *s = format (0, "%v%c", pool_elt_at_index (j->values, c)->string, 0);

      crc = (u32) strtol ((char *) s, NULL, 16);
      vec_free (s);
    }

  m = vat2_find_msg (msgname);
  if (!m || !(m->t->flags & VL_API_DTF_SERVICE))
    {
      fprintf (stderr, "No such command %s\n", msgname);
      return -1;
    }

  if (crc && crc != m->t->crc)
    fprintf (stderr, "API CRC does not match: %s!\n", msgname);

  msg = vl_api_desc_msg_from_json (&(vl_api_desc_msg_t) { .file = m->f, .type = m->t }, j, o);
  if (!msg)
    {
      fprintf (stderr, "Failed converting JSON to API\n");
      fprintf (stderr, "Call failed: %s\n", msgname);
      return -1;
    }

  rv = vat2_call (m, msg, &out);
  vec_free (msg);

  if (rv)
    {
      fprintf (stderr, "Call failed: %s\n", msgname);
      return -1;
    }

  vat2_print_json (&out);
  clib_json_free (&out);
  return 0;
}

static int
vat2_exec_command (clib_json_text_t *j, int o)
{
  int n = clib_json_find_object_value_by_name (j, o, "_msgname");
  char *name;
  int rv;

  if (n < 0 || !clib_json_value_is_string (j, n))
    {
      fprintf (stderr, "Missing '_msgname' element!\n");
      return -1;
    }

  name = (char *) format (0, "%v%c", pool_elt_at_index (j->values, n)->string, 0);
  rv = vat2_exec_command_by_name (name, j, o);
  vec_free (name);
  return rv;
}

static void
print_template (char *msgname)
{
  vat2_msg_t *m = vat2_find_msg (msgname);
  clib_json_text_t j;
  u8 *scratch;

  if (!m || !(m->t->flags & VL_API_DTF_SERVICE))
    goto error;

  scratch = 0;
  vec_validate (scratch, m->t->size - 1);
  clib_memset (scratch, 0, vec_len (scratch));
  if (vl_api_desc_msg_to_json (&(vl_api_desc_msg_t) { .file = m->f, .type = m->t }, scratch, &j))
    {
      vec_free (scratch);
      goto error;
    }

  vec_free (scratch);
  vat2_print_json (&j);
  clib_json_free (&j);
  return;

error:
  fprintf (stderr, "error printing template for: %s\n", msgname);
}

static void
dump_apis (void)
{
  vat2_msg_t *m;

  vec_foreach (m, vat2_msgs)
    if (m->t->flags & VL_API_DTF_SERVICE)
      printf ("%s\n", m->t->name);
}

static void
print_help (void)
{
  char *help_string =
    "Usage: vat2 [OPTION] <message-name> <JSON object>\n"
    "Send API message to VPP and print reply\n"
    "\n"
    "-a, --api-dir <directory>      Directory with the .api.json files, used when VPP\n"
    "                               is not asked for the API (--template, --dump-apis)\n"
    "-d, --debug                    Print additional information\n"
    "--dump-apis                    List all APIs available (from the .api.json files\n"
    "                               or, if there are none, from the running VPP)\n"
    "-f, --file <filename>          File containing a JSON object with the "
    "arguments for the message to send\n"
    "-p, --plugin-path              Not used any more\n"
    "-s, --socket <path>            Path of the API socket of the VPP instance "
    "to connect to, default /run/vpp/api.sock\n"
    "-t, --template <message-name>  Print a template JSON object for given API"
    " message\n";
  printf ("%s", help_string);
}

int
main (int argc, char **argv)
{
  /* Create a heap of 64MB */
  clib_mem_init (0, 64 << 20);
  char *filename = 0, *socket_path = 0, *template = 0, *apidir = 0;
  int index;
  int c;
  opterr = 0;
  clib_json_text_t j = {};
  int have_json = 0;
  int option_index = 0;
  bool dump_api = false;
  char *msgname = 0;
  static struct option long_options[] = {
    { "api-dir", required_argument, 0, 'a' },	  { "debug", no_argument, 0, 'd' },
    { "dump-apis", no_argument, 0, 0 },		  { "file", required_argument, 0, 'f' },
    { "plugin-path", required_argument, 0, 'p' }, { "socket", required_argument, 0, 's' },
    { "template", required_argument, 0, 't' },	  { 0, 0, 0, 0 }
  };

  while ((c = getopt_long (argc, argv, "a:df:p:s:t:", long_options, &option_index)) != -1)
    {
      switch (c)
	{
	case 0:
	  if (option_index == 2)
	    dump_api = true;
	  break;
	case 'a':
	  apidir = optarg;
	  break;
	case 'd':
	  vat2_debug = true;
	  break;
	case 'f':
	  filename = optarg;
	  break;
	case 'p':
	  DBG ("the plugin path is not used any more\n");
	  break;
	case 's':
	  socket_path = optarg;
	  break;
	case 't':
	  template = optarg;
	  break;
	case '?':
	  print_help ();
	  return 1;
	default:
	  abort ();
	}
    }
  DBG ("debug = %d, filename = %s, template = %s, api socket: %s\n", vat2_debug, filename, template,
       socket_path);

  for (index = optind; index < argc; index++)
    DBG ("Non-option argument %s\n", argv[index]);

  index = optind;

  if (argc > index + 2)
    {
      fprintf (stderr, "%s: Too many arguments\n", argv[0]);
      exit (-1);
    }

  vat2_msg_by_name = hash_create_string (0, sizeof (uword));

  /* The files are enough to print what is known of the API, a message is
   * sent with the API of the VPP which receives it */
  if (template || dump_api)
    {
      u8 *dir = apidir ? format (0, "%s%c", apidir, 0) : vat2_find_api_dir ();

      if (dir)
	vat2_load_dir ((char *) dir);
      vec_free (dir);

      if (vec_len (vat2_msgs) == 0)
	{
	  if (vac_connect ("vat2", socket_path, 0, 1024))
	    {
	      fprintf (stderr, "No .api.json files and failed connecting to VPP\n");
	      exit (-1);
	    }
	  vat2_load_from_vpp ();
	  vac_disconnect ();
	}

      if (template)
	{
	  print_template (template);
	  exit (0);
	}

      dump_apis ();
      exit (0);
    }

  /* Read message arguments from command line */
  if (argc >= (index + 1))
    {
      msgname = argv[index];
    }
  if (argc == (index + 2))
    {
      clib_error_t *err =
	clib_json_init_from_string (&j, argv[index + 1], strlen (argv[index + 1]));

      if (err)
	{
	  fprintf (stderr, "%s: Failed parsing JSON input: %s\n", argv[0],
		   (char *) format (0, "%U%c", format_clib_error, err, 0));
	  exit (-1);
	}
      have_json = 1;
    }

  if (!msgname && !filename)
    {
      print_help ();
      exit (-1);
    }

  /* Read message from file */
  if (filename)
    {
      u8 *buf;

      if (argc > index)
	{
	  fprintf (stderr, "%s: Superfluous arguments when filename given\n", argv[0]);
	  exit (-1);
	}

      buf = vat2_read_file (filename);
      if (!buf && access (filename, R_OK))
	{
	  fprintf (stderr, "%s: can't open file: %s\n", argv[0], filename);
	  exit (-1);
	}

      if (vec_len (buf))
	{
	  clib_error_t *err = clib_json_init_from_string (&j, (char *) buf, vec_len (buf));

	  if (err)
	    {
	      fprintf (stderr, "%s: Failed parsing JSON input: %s\n", argv[0],
		       (char *) format (0, "%U%c", format_clib_error, err, 0));
	      exit (-1);
	    }
	  have_json = 1;
	}
      vec_free (buf);
    }

  if (!have_json)
    {
      fprintf (stderr, "%s: Failed parsing JSON input\n", argv[0]);
      exit (-1);
    }

  if (vac_connect ("vat2", socket_path, 0, 1024))
    {
      fprintf (stderr, "Failed connecting to VPP\n");
      exit (-1);
    }

  if (vat2_load_from_vpp ())
    {
      vac_disconnect ();
      exit (-1);
    }

  if (msgname)
    {
      vat2_exec_command_by_name (msgname, &j, j.root_value);
    }
  else
    {
      if (clib_json_value_is_array (&j, j.root_value))
	{
	  int v;

	  foreach_clib_json_array_value (&j, j.root_value, v)
	    vat2_exec_command (&j, v);
	}
    }
  clib_json_free (&j);
  vac_disconnect ();
  exit (0);
}
