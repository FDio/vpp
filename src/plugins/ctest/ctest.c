/*
 * ctest.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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


#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ctest/ctest.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <ctest/ctest_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ctest/ctest_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ctest/ctest_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ctest/ctest_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ctest/ctest_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

#include <dirent.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>


#include "pty.h"

ctest_main_t ctest_main;

/* List of message types that this plugin understands */

#define foreach_ctest_plugin_api_msg                           \
_(CTEST_ENABLE_DISABLE, ctest_enable_disable)

/* Action function shared between message handler and debug CLI */

int
ctest_enable_disable (ctest_main_t * sm, u32 sw_if_index, int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "ctest",
			       sw_if_index, enable_disable, 0, 0);

  /* Send an event to enable/disable the periodic scanner process */
  vlib_process_signal_event (sm->vlib_main, ctest_periodic_node.index,
			     CTEST_EVENT_PERIODIC_ENABLE_DISABLE,
			     (uword) enable_disable);

  return rv;
}

#define foreach_test_file_type \
_(NONE, none) \
_(API_DUMP, api-dump) \
_(IN_PCAP, in-pcap) \
_(OUT_PCAP, out-pcap)

#define _(x,y) TEST_FILE_ ## x,
typedef enum
{
  foreach_test_file_type
} test_file_type_t;
#undef _

#define _(x,y) #y,
char *test_file_type_names[] = {
  foreach_test_file_type
};

#undef _

typedef struct
{
  test_file_type_t file_type;
  u8 *filename;
  u8 *dirname;
  u8 *file;
  u8 *intf_name;
  i64 sec;
  i64 nsec;
} filename_entry_t;

static int
file_time_compare (void *a1, void *a2)
{
  filename_entry_t *s1 = a1;
  filename_entry_t *s2 = a2;

  return (s1->sec > s2->sec) ? 1 : (s1->sec < s2->sec) ? -1 : (s1->nsec >
							       s2->nsec) ? 1
    : (s1->nsec < s2->nsec) ? -1 : 0;
}


static void
ctest_cli_output (uword arg, u8 * buffer, uword buffer_bytes)
{
  u8 **mem_vecp = (u8 **) arg;
  u8 *mem_vec = *mem_vecp;
  u32 offset = vec_len (mem_vec);

  vec_validate (mem_vec, offset + buffer_bytes - 1);
  clib_memcpy (mem_vec + offset, buffer, buffer_bytes);
  *mem_vecp = mem_vec;
}

u8 *
run_cli (u8 * cli)
{
  ctest_main_t *sm = &ctest_main;
  vlib_main_t *vm = sm->vlib_main;
  unformat_input_t input;
  u8 *out_vec = 0;

  unformat_init_string (&input, (void *) cli, vec_len (cli));
  vlib_cli_input (vm, &input, ctest_cli_output, (uword) & out_vec);
  return out_vec;
}

u8 *
do_pcap_activity (filename_entry_t * in_pcaps, filename_entry_t * out_pcaps)
{
  ctest_main_t *sm = &ctest_main;
  vlib_main_t *vm = sm->vlib_main;
/*
self.vapi.cli("clear trace")

"packet-generator new pcap %s source pg%u name %s" % ( self.in_path, self.pg_index, self.cap_name)

cls.logger.debug("Removing zombie capture %s" % cap_name)
cls.vapi.cli('packet-generator delete %s' % cap_name)
cls.vapi.cli("trace add pg-input 50")  # 50 is maximum
cls.vapi.cli('packet-generator enable')

intf.add_stream(pkts)
self.pg_enable_capture(self.pg_interfaces)
self.pg_start()
*/

  filename_entry_t *a_pcap;
  if (vec_len (in_pcaps) + vec_len (out_pcaps) == 0)
    {
      return 0;
    }

  u8 *out = 0;

  vec_foreach (a_pcap, in_pcaps)
  {
    u8 *cli = format (0, "packet-generator new pcap %s source %s name cap-%s",
		      a_pcap->filename, a_pcap->intf_name, a_pcap->intf_name);
    vlib_cli_output (vm, "RUN1: '%v'", cli);
    u8 *result = run_cli (cli);
    vlib_cli_output (vm, "RUN1r: '%v'", result);
    out = format (out, "%s", result);
    vec_free (cli);
    vec_free (result);
  }
  {
    u8 *cli = format (0, "trace add pg-input 50");
    vlib_cli_output (vm, "RUN2: '%v'", cli);
    u8 *result = run_cli (cli);
    vlib_cli_output (vm, "RUN2r: '%v'", result);
    out = format (out, "%s", result);
    vec_free (cli);
    vec_free (result);
  }
  {
    u8 *cli = format (0, "packet-generator enable");
    vlib_cli_output (vm, "RUN: '%v'", cli);
    u8 *result = run_cli (cli);
    vlib_cli_output (vm, "RUN3r: '%v'", result);
    out = format (out, "%s", result);
    vec_free (cli);
    vec_free (result);
  }
  {
    pg_main_t *pg = &pg_main;
    pg_stream_t *s;
    int running = 0;
    do
      {
	running = 0;
	pool_foreach (s, pg->streams, (
					{
					if (pg_stream_is_enabled (s))
					{
					running = 1;}
					if (running)
					{
					vlib_process_suspend (vm, 0.001);}
					}
		      ));
      }
    while (running);
  }
  vec_foreach (a_pcap, in_pcaps)
  {
    u8 *cli = format (0, "packet-generator delete cap-%v", a_pcap->intf_name);
    vlib_cli_output (vm, "RUN: '%v'", cli);
    u8 *result = run_cli (cli);
    out = format (out, "%s", result);
    vec_free (cli);
    vec_free (result);
  }
  out = format (out, "%c", 0);

  return out;
}


typedef u8 *(ctest_action_func_t) (filename_entry_t * files);

u8 *
replay_test_run (filename_entry_t * files)
{
  ctest_main_t *sm = &ctest_main;
  vlib_main_t *vm = sm->vlib_main;
  u8 *out = 0;

  typeof (files[0]) * afile, *in_pcaps = 0, *out_pcaps = 0;
  vec_foreach (afile, files)
  {
    vlib_cli_output (vm, "%s: %s\n", afile->file,
		     test_file_type_names[afile->file_type]);
    vlib_cli_output (vm, "    %s: mtime = %ld.%.9ld\n", afile->filename,
		     afile->sec, afile->nsec);
    switch (afile->file_type)
      {
      case TEST_FILE_API_DUMP:
	{
	  u8 *result = do_pcap_activity (in_pcaps, out_pcaps);
	  vec_free (in_pcaps);
	  vec_free (out_pcaps);
	  if (result)
	    {
	      vlib_cli_output (vm, "Result: %s", result);
	      out = result;
	      goto double_break;
	    }
	  else
	    {
	      u8 *cli =
		format (0, "api trace replay %s%c", afile->filename, 0);
	      u8 *res = run_cli (cli);
	      vec_free (cli);
	      vec_free (res);
	    }
	  break;
	}
      case TEST_FILE_IN_PCAP:
	vec_add1 (in_pcaps, *afile);
	break;
      case TEST_FILE_OUT_PCAP:
	vec_add1 (out_pcaps, *afile);
	break;
      default:
	clib_warning ("not a handled type: %d", afile->file_type);
      }
    continue;
  double_break:
    break;
  };

  return out;
}

int
suffix_with_intf (char *fullname, char *suffix, u8 ** ifname)
{
  char *suffix_start = strstr (fullname, suffix);
  char *intf_start = suffix_start;
  if (suffix_start == NULL)
    return 0;
  intf_start = suffix_start - 3;	/* pgX has at least three chars */
  while (intf_start > fullname)
    {
      if ((intf_start[0] == 'p') && (intf_start[1] == 'g')
	  && isdigit (intf_start[2]))
	{
	  vec_validate ((*ifname), suffix_start - intf_start);
	  _vec_len ((*ifname)) = 0;
	  while (intf_start < suffix_start)
	    {
	      vec_add1 ((*ifname), *intf_start++);
	    }
	  // vec_add1((*ifname), 0); // terminate the C-string
	  return 1;
	}
      intf_start--;
    }
  return 0;
}

void ctest_run_all (ctest_action_func_t * ctest_action_func);

void
ctest_run (u8 * dirname, ctest_action_func_t * ctest_action_func)
{
  ctest_main_t *sm = &ctest_main;
  vlib_main_t *vm = sm->vlib_main;
  DIR *d;
  struct dirent *dir;
  filename_entry_t *files = 0;
  if (0 == dirname)
    {
      ctest_run_all (ctest_action_func);
      return;
    }


  d = opendir ((char *) dirname);
  if (d)
    {
      while ((dir = readdir (d)) != NULL)
	{
	  struct stat st;
	  u8 *filename = format (0, "%s/%s%c", dirname, dir->d_name, 0);
	  u8 *intf_name = 0;
	  printf ("%s\n", dir->d_name);
	  if (stat ((void *) filename, &st))
	    {
	      clib_warning ("can not stat %s", filename);
	    }
	  else
	    {
	      // printf("%s: mtime = %lld.%.9ld\n", filename, (long long)st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
	      int file_type = TEST_FILE_NONE;
	      if (strstr (dir->d_name, "vpp_api_trace."))
		{
		  vec_free (intf_name);
		  file_type = TEST_FILE_API_DUMP;
		}
	      if (suffix_with_intf (dir->d_name, "_in.pcap", &intf_name))
		{
		  file_type = TEST_FILE_IN_PCAP;
		}
	      if (suffix_with_intf (dir->d_name, "_out.pcap", &intf_name))
		{
		  file_type = TEST_FILE_OUT_PCAP;
		}
	      if (file_type != TEST_FILE_NONE)
		{
		  u8 *dirname_copy = format (0, "%s%c", dirname, 0);
		  u8 *file = format (0, "%s%c", dir->d_name, 0);
		  filename_entry_t fe = {.filename = filename,.sec =
		      (i64) st.st_mtim.tv_sec,.nsec =
		      (i64) st.st_mtim.tv_nsec,.dirname = dirname_copy,.file =
		      file,.file_type = file_type,.intf_name =
		      vec_dup (intf_name)
		  };
		  vec_add1 (files, fe);
		}
	      else
		vec_free (filename);
	    }
	}
      closedir (d);
      vlib_cli_output (vm, "Total files: %d", vec_len (files));
      vec_sort_with_function (files, file_time_compare);
      if (ctest_action_func)
	{
	  u8 *out = ctest_action_func (files);
	  vec_free (out);
	}
      else
	{
	  typeof (files[0]) * afile;
	  vec_foreach (afile, files)
	  {
	    vlib_cli_output (vm, "%s: %s\n", afile->file,
			     test_file_type_names[afile->file_type]);
	    vlib_cli_output (vm, "    %s: mtime = %ld.%.9ld\n",
			     afile->filename, afile->sec, afile->nsec);
	  }
	}

    }
}

void
ctest_run_all (ctest_action_func_t * ctest_action_func)
{
  DIR *d;
  struct dirent *dir;
  char *dirname = "/tmp";
  d = opendir (dirname);
  if (d)
    {
      while ((dir = readdir (d)) != NULL)
	{
	  if (strstr (dir->d_name, "vpp-unittest-") == dir->d_name)
	    {
	      u8 *filename = format (0, "%s/%s", dirname, dir->d_name, 0);
	      ctest_run (filename, ctest_action_func);
	      vec_free (filename);
	    }
	}
      closedir (d);
    }
}


static clib_error_t *
ctest_run_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *dirname = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unformat (input, "%s", &dirname);
    }

  ctest_run (dirname, replay_test_run);

  return 0;
}

static clib_error_t *
ctest_show_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *dirname = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unformat (input, "%s", &dirname);
    }

  ctest_run (dirname, 0);

  return 0;
}

void unix_cli_output_redraw_prompt (u8 * out);

static clib_error_t *
pty_read_fd_read_ready (clib_file_t * uf)
{
  vlib_main_t *vm = (void *) uf->private_data;
  // vnet_main_t *vnm = vnet_get_main ();
  // u16 qid = uf->private_data & 0xFFFF;
  u8 buf[4096];
  u8 *out = 0;
  int size = 0;
  do
    {
      size = read (uf->file_descriptor, buf, sizeof (buf));
      int i;
      for (i = 0; i < size; i++)
	{
	  if (buf[i] == '\r')
	    {
	      u8 *out2 = format (0, "\routput: '%v'\n\r", out);
	      unix_cli_output_redraw_prompt (out2);
	      vec_free (out2);
	      if (out)
		_vec_len (out) = 0;
	    }
	  else
	    {
	      if (buf[i] != '\n')
		vec_add1 (out, buf[i]);
	    }
	}
      if (size < 0)
	{
	  clib_warning ("Failed to read form socket");
	  return 0;
	}
      return 0;
    }
  while (size == sizeof (buf));
  vlib_cli_output (vm, "output: '%v'", out);
  vec_free (out);
}

static clib_error_t *
pty_error_ready (clib_file_t * uf)
{
  clib_warning ("ERROR FUNCTION");
  close (uf->file_descriptor);
  return 0;
}

static int
run_in_pty (vlib_main_t * vm, u8 * command)
{
  clib_file_t template = { 0 };
  pid_t child_pid;
  int pty_fd = pty_run ((void *) command, &child_pid);
  vlib_cli_output (vm, "pty_fd: %d child_pid: %d", pty_fd, child_pid);
  if (child_pid > -1)
    {
      template.file_descriptor = pty_fd;
      template.read_function = pty_read_fd_read_ready;
      template.error_function = pty_error_ready;
      template.private_data = (uword) vm;
      template.description = format (0, "running '%s'", command);
      clib_file_add (&file_main, &template);
    }
  int status;
  pid_t pid = waitpid ((pid_t) - 1, &status, WNOHANG);
  clib_warning ("child process %ld exited: %d",
		(long) pid, WEXITSTATUS (status));
  return 0;
}

static clib_error_t *
ctest_shell_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int index = input->index;
  u8 *command = 0;
  u8 *ignored = 0;
  while (index < vec_len (input->buffer))
    {
      vec_add1 (command, input->buffer[index++]);
    }
  vec_add1 (command, 0);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unformat (input, "%s", &ignored);
    }

  if (command)
    {
      vlib_cli_output (vm, "RUN: '%s'", command);
/*
      int res = system ((void *) command);
      vlib_cli_output (vm, "Return code: %d", res);
*/
      run_in_pty (vm, command);
    }

  return 0;
}


static clib_error_t *
ctest_enable_disable_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  ctest_main_t *sm = &ctest_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 sm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = ctest_enable_disable (sm, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "ctest_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ctest_enable_disable_command, static) =
{
  .path = "ctest enable-disable",
  .short_help =
  "ctest enable-disable <interface-name> [disable]",
  .function = ctest_enable_disable_command_fn,
};

VLIB_CLI_COMMAND (ctest_run_command, static) =
{
  .path = "ctest run",
  .short_help =
  "ctest run",
  .function = ctest_run_command_fn,
};
VLIB_CLI_COMMAND (ctest_show_command, static) =
{
  .path = "ctest show",
  .short_help =
  "ctest show",
  .function = ctest_show_command_fn,
};
VLIB_CLI_COMMAND (ctest_shell_command, static) =
{
  .path = "ctest shell",
  .short_help =
  "ctest shell",
  .function = ctest_shell_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_ctest_enable_disable_t_handler
  (vl_api_ctest_enable_disable_t * mp)
{
  vl_api_ctest_enable_disable_reply_t *rmp;
  ctest_main_t *sm = &ctest_main;
  int rv;

  rv = ctest_enable_disable (sm, ntohl (mp->sw_if_index),
			     (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_CTEST_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
ctest_plugin_api_hookup (vlib_main_t * vm)
{
  ctest_main_t *sm = &ctest_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_ctest_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <ctest/ctest_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (ctest_main_t * sm, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n  #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_ctest;
#undef _
}

static clib_error_t *
ctest_init (vlib_main_t * vm)
{
  ctest_main_t *sm = &ctest_main;
  clib_error_t *error = 0;
  u8 *name;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  name = format (0, "ctest_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = ctest_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (ctest_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ctest, static) =
{
  .arc_name = "device-input",
  .node_name = "ctest",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "An experimental unit test plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
