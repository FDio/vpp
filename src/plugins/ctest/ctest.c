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

ctest_main_t ctest_main;

/* List of message types that this plugin understands */

#define foreach_ctest_plugin_api_msg                           \
_(CTEST_ENABLE_DISABLE, ctest_enable_disable)

/* Action function shared between message handler and debug CLI */

int ctest_enable_disable (ctest_main_t * sm, u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
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
                            (uword)enable_disable);

  return rv;
}

#define foreach_test_file_type \
_(NONE, none) \
_(API_DUMP, api-dump) \
_(IN_PCAP, in-pcap) \
_(OUT_PCAP, out-pcap)

#define _(x,y) TEST_FILE_ ## x,
typedef enum {
  foreach_test_file_type
} test_file_type_t;
#undef _

#define _(x,y) #y,
char *test_file_type_names[] = {
foreach_test_file_type
};
#undef _

typedef struct {
  test_file_type_t file_type;
  u8 *filename;
  u8 *dirname;
  u8 *file;
  i64 sec;
  i64 nsec;
} filename_entry_t;

static int
file_time_compare(void *a1, void *a2)
{
  filename_entry_t *s1 = a1;
  filename_entry_t *s2 = a2;

  return (s1->sec > s2->sec) ? 1 : (s1->sec < s2->sec) ? -1 : (s1->nsec > s2->nsec) ? 1 : (s1->nsec < s2->nsec) ? -1 : 0;
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

u8 *run_cli(u8 *cli)
{
  ctest_main_t * sm = &ctest_main;
  vlib_main_t *vm = sm->vlib_main;
  unformat_input_t input;
  u8 *out_vec = 0;

  unformat_init_string (&input, (void *)cli, vec_len(cli));
  vlib_cli_input (vm, &input, ctest_cli_output, (uword) & out_vec);
  return out_vec;
}

void ctest_run(u8 *dirname)
{
  ctest_main_t * sm = &ctest_main;
  vlib_main_t *vm = sm->vlib_main;
  DIR *d;
  struct dirent *dir;
  filename_entry_t *files = 0;
  d = opendir((char*)dirname);
  if (d) {
    while ((dir = readdir(d)) != NULL) {
      struct stat st;
      u8 *filename = format(0, "%s/%s%c", dirname, dir->d_name, 0);
      printf("%s\n", dir->d_name);
      if (stat((void *)filename, &st)) {
        clib_warning("can not stat %s", filename);
      } else {
        // printf("%s: mtime = %lld.%.9ld\n", filename, (long long)st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
        int file_type = TEST_FILE_NONE;
        if (strstr(dir->d_name, "vpp_api_trace.")) { file_type = TEST_FILE_API_DUMP; }
        if (strstr(dir->d_name, "_in.pcap")) { file_type = TEST_FILE_IN_PCAP; }
        if (strstr(dir->d_name, "_out.pcap")) { file_type = TEST_FILE_OUT_PCAP; }
        if (file_type != TEST_FILE_NONE)
          {
            u8 *dirname_copy = format(0, "%s%c", dirname, 0);
            u8 *file = format(0, "%s%c", dir->d_name, 0);
            filename_entry_t fe = { .filename = filename, .sec = (i64)st.st_mtim.tv_sec, .nsec = (i64)st.st_mtim.tv_nsec, .dirname = dirname_copy, .file = file, .file_type = file_type};
            vec_add1(files, fe);
          }
        else
          vec_free(filename);
      }
    }
    closedir(d);
    vlib_cli_output(vm, "Total files: %d", vec_len(files));
    vec_sort_with_function(files, file_time_compare);
    typeof(files[0]) *afile;
    vec_foreach (afile, files) {
      vlib_cli_output(vm, "%s: %s\n", afile->file, test_file_type_names[afile->file_type]);
      vlib_cli_output(vm, "    %s: mtime = %ld.%.9ld\n", afile->filename, afile->sec, afile->nsec);
      switch (afile->file_type) {
        case TEST_FILE_API_DUMP: 
          {
          u8 *cli = format(0, "api trace replay %s", afile->filename);
          u8 *res = run_cli(cli);
          vec_free(cli);
          vec_free(res);
          break;
          }
        case TEST_FILE_IN_PCAP:
        case TEST_FILE_OUT_PCAP:
        default:
          clib_warning("not a handled type: %d", afile->file_type);
      }
    }
    
  }
}

void ctest_run_all(void)
{
  DIR *d;
  struct dirent *dir;
  char *dirname = "/tmp";
  d = opendir(dirname);
  if (d) {
    while ((dir = readdir(d)) != NULL) {
      if (strstr(dir->d_name, "vpp-unittest-") == dir->d_name) {
        u8 *filename = format(0, "%s/%s%c", dirname, dir->d_name, 0);
        ctest_run(filename);
        vec_free(filename);
      }
    }
    closedir(d);
  }
}

static clib_error_t *
ctest_run_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  u8 *dirname = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      unformat (input, "%s", &dirname);
    }
 
  if (dirname)
    ctest_run(dirname);
  else
    ctest_run_all();

  return 0;
}

static clib_error_t *
ctest_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  ctest_main_t * sm = &ctest_main;
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

  switch(rv) 
    {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "ctest_enable_disable returned %d",
                              rv);
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

VLIB_CLI_COMMAND (ctest_list_command, static) = 
{
  .path = "ctest run",
  .short_help =
  "ctest run",
  .function = ctest_run_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_ctest_enable_disable_t_handler
(vl_api_ctest_enable_disable_t * mp)
{
  vl_api_ctest_enable_disable_reply_t * rmp;
  ctest_main_t * sm = &ctest_main;
  int rv;

  rv = ctest_enable_disable (sm, ntohl(mp->sw_if_index),
                                      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_CTEST_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
ctest_plugin_api_hookup (vlib_main_t *vm)
{
  ctest_main_t * sm = &ctest_main;
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
  foreach_vl_msg_name_crc_ctest ;
#undef _
}

static clib_error_t * ctest_init (vlib_main_t * vm)
{
  ctest_main_t * sm = &ctest_main;
  clib_error_t * error = 0;
  u8 * name;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main();

  name = format (0, "ctest_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = ctest_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

  vec_free(name);

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
