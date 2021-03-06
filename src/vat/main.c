/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include "vat.h"
#include "plugin.h"
#include <signal.h>
#include <limits.h>

vat_main_t vat_main;

#include <vlibapi/api_helper_macros.h>

void
vat_suspend (vlib_main_t * vm, f64 interval)
{
  /* do nothing in the standalone version, just return */
}

int
connect_to_vpe (char *name)
{
  vat_main_t *vam = &vat_main;
  api_main_t *am = vlibapi_get_main ();

  if (vl_client_connect_to_vlib ("/vpe-api", name, 32) < 0)
    return -1;

  vam->vl_input_queue = am->shmem_hdr->vl_input_queue;
  vam->my_client_index = am->my_client_index;

  return 0;
}

/* *INDENT-OFF* */

vlib_global_main_t vlib_global_main;
vlib_main_t **vlib_mains;

void
vlib_cli_output (struct vlib_main_t *vm, char *fmt, ...)
{
  clib_warning ("BUG");
}

static u8 *
format_api_error (u8 * s, va_list * args)
{
  vat_main_t *vam = va_arg (*args, vat_main_t *);
  i32 error = va_arg (*args, u32);
  uword *p;

  p = hash_get (vam->error_string_by_error_number, -error);

  if (p)
    s = format (s, "%s", p[0]);
  else
    s = format (s, "%d", error);
  return s;
}

void
do_one_file (vat_main_t * vam)
{
  int rv;
  int (*fp) (vat_main_t * vam);
  int arg_len;
  unformat_input_t _input;
  u8 *cmdp, *argsp;
  uword *p;
  u8 *this_cmd = 0;

  vam->input = &_input;

  /* Used by the "quit" command handler */
  if (setjmp (vam->jump_buf) != 0)
    return;

  vam->jump_buf_set = 1;

  while (1)
    {
      if (vam->ifp == stdin)
	{
	  if (vam->exec_mode == 0)
	    rv = write (1, "vat# ", 5);
	  else
	    rv = write (1, "exec# ", 6);
	}

      _vec_len (vam->inbuf) = 4096;

      if (vam->do_exit ||
	  fgets ((char *) vam->inbuf, vec_len (vam->inbuf), vam->ifp) == 0)
	break;

      vam->input_line_number++;

      vec_free (this_cmd);

      this_cmd =
	(u8 *) clib_macro_eval (&vam->macro_main, (i8 *) vam->inbuf,
				1 /* complain */ ,
				0 /* level */ ,
				8 /* max_level */ );

      if (vam->exec_mode == 0)
	{
	  /* Split input into cmd + args */
	  cmdp = this_cmd;

	  while (cmdp < (this_cmd + vec_len (this_cmd)))
	    {
	      if (*cmdp == ' ' || *cmdp == '\t' || *cmdp == '\n')
		{
		  cmdp++;
		}
	      else
		break;
	    }
	  argsp = cmdp;
	  while (argsp < (this_cmd + vec_len (this_cmd)))
	    {
	      if (*argsp != ' ' && *argsp != '\t' && *argsp != '\n')
		{
		  argsp++;
		}
	      else
		break;
	    }
	  *argsp++ = 0;
	  while (argsp < (this_cmd + vec_len (this_cmd)))
	    {
	      if (*argsp == ' ' || *argsp == '\t' || *argsp == '\n')
		{
		  argsp++;
		}
	      else
		break;
	    }


	  /* Blank input line? */
	  if (*cmdp == 0)
	    continue;

	  p = hash_get_mem (vam->function_by_name, cmdp);
	  if (p == 0)
	    {
	      errmsg ("'%s': function not found\n", cmdp);
	      continue;
	    }

	  arg_len = strlen ((char *) argsp);

	  unformat_init_string (vam->input, (char *) argsp, arg_len);
	  fp = (void *) p[0];
	}
      else
	{
	  unformat_init_string (vam->input, (char *) this_cmd,
				strlen ((char *) this_cmd));
	  cmdp = this_cmd;
	  fp = exec;
	}

      rv = (*fp) (vam);
      if (rv < 0)
	errmsg ("%s error: %U\n", cmdp, format_api_error, vam, rv);
      unformat_free (vam->input);

      if (vam->regenerate_interface_table)
	{
	  vam->regenerate_interface_table = 0;
	  api_sw_interface_dump (vam);
	}

      /* Hack to pick up new client index after memfd_segment_create pivot */
      if (vam->client_index_invalid)
	{
	  vat_main_t *vam = &vat_main;
	  api_main_t *am = vlibapi_get_main ();

	  vam->vl_input_queue = am->shmem_hdr->vl_input_queue;
	  vam->my_client_index = am->my_client_index;
	  vam->client_index_invalid = 0;
	}
    }
}

static void
init_error_string_table (vat_main_t * vam)
{

  vam->error_string_by_error_number = hash_create (0, sizeof (uword));

#define _(n,v,s) hash_set (vam->error_string_by_error_number, -v, s);
  foreach_vnet_api_error;
#undef _

  hash_set (vam->error_string_by_error_number, 99, "Misc");
}

static i8 *
eval_current_file (clib_macro_main_t * mm, i32 complain)
{
  vat_main_t *vam = &vat_main;
  return ((i8 *) format (0, "%s%c", vam->current_file, 0));
}

static i8 *
eval_current_line (clib_macro_main_t * mm, i32 complain)
{
  vat_main_t *vam = &vat_main;
  return ((i8 *) format (0, "%d%c", vam->input_line_number, 0));
}

static void
signal_handler (int signum, siginfo_t * si, ucontext_t * uc)
{
  vat_main_t *vam = &vat_main;

  switch (signum)
    {
      /* these (caught) signals cause the application to exit */
    case SIGINT:
    case SIGTERM:
      if (vam->jump_buf_set)
	{
	  vam->do_exit = 1;
	  return;
	}

      /* FALLTHROUGH on purpose */

    default:
      break;
    }

  _exit (1);
}

static void
setup_signal_handlers (void)
{
  uword i;
  struct sigaction sa;

  for (i = 1; i < 32; i++)
    {
      clib_memset (&sa, 0, sizeof (sa));
      sa.sa_sigaction = (void *) signal_handler;
      sa.sa_flags = SA_SIGINFO;

      switch (i)
	{
	  /* these signals take the default action */
	case SIGABRT:
	case SIGKILL:
	case SIGSTOP:
	case SIGUSR1:
	case SIGUSR2:
	case SIGPROF:
	  continue;

	  /* ignore SIGPIPE, SIGCHLD */
	case SIGPIPE:
	case SIGCHLD:
	case SIGWINCH:
	  sa.sa_sigaction = (void *) SIG_IGN;
	  break;

	  /* catch and handle all other signals */
	default:
	  break;
	}

      if (sigaction (i, &sa, 0) < 0)
	clib_unix_warning ("sigaction %U", format_signal, i);
    }
}

static void
vat_find_plugin_path ()
{
  char *p, path[PATH_MAX];
  int rv;
  u8 *s;

  /* find executable path */
  if ((rv = readlink ("/proc/self/exe", path, PATH_MAX - 1)) == -1)
    return;

  /* readlink doesn't provide null termination */
  path[rv] = 0;

  /* strip filename */
  if ((p = strrchr (path, '/')) == 0)
    return;
  *p = 0;

  /* strip bin/ */
  if ((p = strrchr (path, '/')) == 0)
    return;
  *p = 0;

  s = format (0, "%s/lib/" CLIB_TARGET_TRIPLET "/vpp_api_test_plugins:"
	      "%s/lib/vpp_api_test_plugins", path, path);
  vec_add1 (s, 0);
  vat_plugin_path = (char *) s;
}

static void
load_features (void)
{
  vat_registered_features_t *f;
  vat_main_t *vam = &vat_main;
  clib_error_t *error;

  f = vam->feature_function_registrations;

  while (f)
    {
      error = f->function (vam);
      if (error)
	{
	  clib_warning ("INIT FAILED");
	}
      f = f->next;
    }
}

static inline clib_error_t *
call_init_exit_functions_internal (vlib_main_t *vm,
				   _vlib_init_function_list_elt_t **headp,
				   int call_once, int do_sort, int is_global)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  clib_error_t *error = 0;
  _vlib_init_function_list_elt_t *i;

  ASSERT (is_global == 1);

#if 0
  /* Not worth copying the topological sort code */
  if (do_sort && (error = vlib_sort_init_exit_functions (headp)))
    return (error);
#endif

  i = *headp;
  while (i)
    {
      if (call_once && !hash_get (vgm->init_functions_called, i->f))
	{
	  if (call_once)
	    hash_set1 (vgm->init_functions_called, i->f);
	  error = i->f (vm);
	  if (error)
	    return error;
	}
      i = i->next_init_function;
    }
  return error;
}

clib_error_t *
vlib_call_init_exit_functions (vlib_main_t *vm,
			       _vlib_init_function_list_elt_t **headp,
			       int call_once, int is_global)
{
  return call_init_exit_functions_internal (vm, headp, call_once,
					    1 /* do_sort */, is_global);
}

int
main (int argc, char **argv)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  vat_main_t *vam = &vat_main;
  unformat_input_t _argv, *a = &_argv;
  u8 **input_files = 0;
  u8 *output_file = 0;
  u8 *chroot_prefix;
  u8 *this_input_file;
  u8 interactive = 1;
  u8 json_output = 0;
  int i;
  f64 timeout;
  clib_error_t *error;
  vlib_main_t *vm = vlib_mains[0];

  clib_mem_init_thread_safe (0, 128 << 20);

  clib_macro_init (&vam->macro_main);
  clib_macro_add_builtin (&vam->macro_main, "current_file",
			  eval_current_file);
  clib_macro_add_builtin (&vam->macro_main, "current_line",
			  eval_current_line);

  init_error_string_table (vam);
  vec_validate (vam->cmd_reply, 0);
  vec_reset_length (vam->cmd_reply);

  vat_find_plugin_path ();

  unformat_init_command_line (a, argv);

  while (unformat_check_input (a) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (a, "in %s", &this_input_file))
	vec_add1 (input_files, this_input_file);
      else if (unformat (a, "out %s", &output_file))
	;
      else if (unformat (a, "script"))
	interactive = 0;
      else if (unformat (a, "json"))
	json_output = 1;
      else if (unformat (a, "socket-name %s", &vam->socket_name))
	;
      else if (unformat (a, "default-socket"))
	{
	  vam->socket_name = format (0, "%s%c", API_SOCKET_FILE, 0);
	}
      else if (unformat (a, "plugin_path %s", (u8 *) & vat_plugin_path))
	vec_add1 (vat_plugin_path, 0);
      else if (unformat (a, "plugin_name_filter %s",
			 (u8 *) & vat_plugin_name_filter))
	vec_add1 (vat_plugin_name_filter, 0);
      else if (unformat (a, "chroot prefix %s", &chroot_prefix))
	{
	  vl_set_memory_root_path ((char *) chroot_prefix);
	}
      else
	{
	  fformat
	    (stderr,
	     "%s: usage [in <f1> ... in <fn>] [out <fn>] [script] [json]\n"
	     "[plugin_path <path>][default-socket][socket-name <name>]\n"
	     "[plugin_name_filter <filter>][chroot prefix <path>]\n",
	     argv[0]);
	  exit (1);
	}
    }

  if (output_file)
    vam->ofp = fopen ((char *) output_file, "w");
  else
    vam->ofp = stdout;

  if (vam->ofp == NULL)
    {
      fformat (stderr, "Couldn't open output file %s\n",
	       output_file ? (char *) output_file : "stdout");
      exit (1);
    }

  clib_time_init (&vam->clib_time);

  vat_api_hookup (vam);
  vat_plugin_api_reference ();

  setup_signal_handlers ();

  if (vam->socket_name && vat_socket_connect (vam))
    fformat (stderr, "WARNING: socket connection failed");

  if ((!vam->socket_client_main || vam->socket_client_main->socket_fd == 0)
      && connect_to_vpe ("vpp_api_test") < 0)
    {
      svm_region_exit ();
      fformat (stderr, "Couldn't connect to vpe, exiting...\n");
      exit (1);
    }

  vam->json_output = json_output;

  if (!json_output)
    api_sw_interface_dump (vam);

  vec_validate (vam->inbuf, 4096);

  load_features ();

  vam->current_file = (u8 *) "plugin-init";
  vat_plugin_init (vam);

  /* Set up the init function hash table */
  vgm->init_functions_called = hash_create (0, 0);

  /* Execute plugin init and api_init functions */
  error = vlib_call_init_exit_functions (vm, &vgm->init_function_registrations,
					 1 /* call once */, 1 /* is_global*/);

  if (error)
    clib_error_report (error);

  error =
    vlib_call_init_exit_functions (vm, &vgm->api_init_function_registrations,
				   1 /* call_once */, 1 /* is_global */);

  if (error)
    clib_error_report (error);

  for (i = 0; i < vec_len (input_files); i++)
    {
      vam->ifp = fopen ((char *) input_files[i], "r");
      if (vam->ifp == NULL)
	{
	  fformat (stderr, "Couldn't open input file %s\n", input_files[i]);
	  continue;
	}
      vam->current_file = input_files[i];
      vam->input_line_number = 0;
      do_one_file (vam);
      fclose (vam->ifp);
    }

  if (output_file)
    fclose (vam->ofp);

  if (interactive)
    {
      vam->ifp = stdin;
      vam->ofp = stdout;
      vam->current_file = (u8 *) "interactive";
      do_one_file (vam);
      fclose (vam->ifp);
    }

  /*
   * Particularly when running a script, don't be in a hurry to leave.
   * A reply message queued to this process will end up constipating
   * the allocation rings.
   */
  timeout = vat_time_now (vam) + 2.0;
  while (vam->result_ready == 0 && vat_time_now (vam) < timeout)
    ;

  if (vat_time_now (vam) > timeout)
    clib_warning ("BUG: message reply spin-wait timeout");

  vl_client_disconnect_from_vlib ();
  exit (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
