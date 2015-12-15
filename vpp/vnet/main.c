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
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ethernet/ethernet.h>

#include <api/vpe_msg_enum.h>

/** \mainpage Virtual Packet Edge Documentation
 * \section intro_sec Introduction
 * 
 * VPE is a specific vector packet processing application,
 * designed to steer packets to/from tenant virtual machines.
 *
 */

static clib_error_t *
vpe_main_init (vlib_main_t * vm)
{
    clib_error_t * error = 0;
    void vnet_library_plugin_reference(void);

    if (CLIB_DEBUG > 0)
        vlib_unix_cli_set_prompt ("DBGvpp# ");
    else
        vlib_unix_cli_set_prompt ("vpp# ");

    vnet_library_plugin_reference();

    if ((error = vlib_call_init_function (vm, pg_init)))
	return error;
    if ((error = vlib_call_init_function (vm, ip_main_init)))
	return error;
    if ((error = vlib_call_init_function (vm, osi_init)))
	return error;
    if ((error = vlib_call_init_function (vm, l2_init)))
	return error;
    if ((error = vlib_call_init_function (vm, ethernet_init)))
	return error;
    if ((error = vlib_call_init_function (vm, ethernet_arp_init)))
	return error;
    if ((error = vlib_call_init_function (vm, sr_init)))
	return error;
    if ((error = vlib_call_init_function (vm, map_init)))
	return error;
    if ((error = vlib_call_init_function (vm, sixrd_init)))
	return error;
    if ((error = vlib_call_init_function (vm, nsh_gre_init)))
	return error;
    if ((error = vlib_call_init_function (vm, nsh_vxlan_gpe_init)))
	return error;
    if ((error = vlib_call_init_function (vm, lisp_gpe_init)))
	return error;

#if DPDK == 1
    if ((error = vlib_call_init_function (vm, dpdk_init)))
        return error;
    if ((error = vlib_call_init_function (vm, dpdk_thread_init)))
        return error;
    if ((error = vlib_call_init_function (vm, vhost_user_init)))
	return error;
    if ((error = vlib_call_init_function (vm, ipsec_init)))
        return error;
#endif    
    if ((error = vlib_call_init_function (vm, vlibmemory_init)))
	return error;
    if ((error = vlib_call_init_function (vm, l2tp_init)))
       return error;
    if ((error = vlib_call_init_function (vm, gre_init)))
        return error;
    if ((error = vlib_call_init_function (vm, gre_interface_init)))
        return error;
    if ((error = vlib_call_init_function (vm, mpls_init)))
        return error;
    if ((error = vlib_call_init_function (vm, mpls_interface_init)))
        return error;
    if ((error = vlib_call_init_function (vm, dhcp_proxy_init)))
        return error;
    if ((error = vlib_call_init_function (vm, dhcpv6_proxy_init)))
        return error;
    if ((error = vlib_call_init_function (vm, tapcli_init)))
        return error;
    if ((error = vlib_call_init_function (vm, tuntap_init)))
	return error;
    if ((error = vlib_call_init_function (vm, gdb_func_init)))
        return error;
    if ((error = unix_physmem_init
	 (vm, 0 /* fail_if_physical_memory_not_present */)))
        return error;
    if ((error = vlib_call_init_function (vm, tuntap_init)))
	return error;
    if ((error = vlib_call_init_function (vm, sr_init)))
        return error;
    if ((error = vlib_call_init_function (vm, l2_classify_init)))
        return error;
    if ((error = vlib_call_init_function (vm, policer_init)))
        return error;
    if ((error = vlib_call_init_function (vm, vxlan_init)))
        return error;
    if ((error = vlib_call_init_function (vm, vcgn_init)))
        return error;
    if ((error = vlib_call_init_function (vm, li_init)))
        return error;

    return error;
}

VLIB_INIT_FUNCTION (vpe_main_init);

/* 
 * Load plugins from /usr/lib/vpp_plugins by default
 */
char *vlib_plugin_path = "/usr/lib/vpp_plugins";
                                                
void *vnet_get_handoff_structure (void)
{
    static vnet_plugin_handoff_t _rv, *rv = &_rv;

    rv->vnet_main = vnet_get_main();
    rv->ethernet_main = &ethernet_main;
    return (void *)rv;
}

int main (int argc, char * argv[])
{
    int i;
    void vl_msg_api_set_first_available_msg_id (u16);
    uword main_heap_size = (1ULL << 30);
    u8 * sizep;
    u32 size;
    void vlib_set_get_handoff_structure_cb (void *cb);

    /*
     * Load startup config from file.
     * usage: vpe -c /etc/vpp/startup.conf
     */
    if ((argc == 3) && !strncmp(argv[1], "-c", 2))
      {
        FILE * fp;
        char inbuf[4096];
        int argc_ = 1;
        char ** argv_ = NULL;
        char * arg = NULL;
        char * p;

        fp = fopen (argv[2], "r");
        if (fp == NULL)
          {
            fprintf(stderr, "open configuration file '%s' failed\n", argv[2]);
            return 1;
          }
        argv_ = calloc(1, sizeof(char *));
        if (argv_ == NULL)
          return 1;
        arg = strndup(argv[0], 1024);
        if (arg == NULL)
          return 1;
        argv_[0] = arg;

        while (1) {
          if (fgets(inbuf, 4096, fp) == 0)
            break;
          p = strtok(inbuf, " \t\n");
          while (p != NULL) {
            if (*p == '#')
              break;
            argc_++;
            char ** tmp = realloc(argv_, argc_ * sizeof(char *));
            if (tmp == NULL)
              return 1;
            argv_ = tmp;
            arg = strndup(p, 1024);
            if (arg == NULL)
              return 1;
            argv_[argc_ - 1] = arg;
            p = strtok(NULL, " \t\n");
          }
        }

        fclose(fp);

        char ** tmp = realloc(argv_, (argc_ + 1) * sizeof(char *));
        if (tmp == NULL)
           return 1;
        argv_ = tmp;
        argv_[argc_] = NULL;

        argc = argc_;
        argv = argv_;
      }

    /* 
     * Look for and parse the "heapsize" config parameter.
     * Manual since none of the clib infra has been bootstrapped yet.
     *
     * Format: heapsize <nn>[mM][gG] 
     */

    for (i = 1; i < (argc-1); i++) {
        if (!strncmp (argv[i], "plugin_path", 11)) {
            if (i < (argc-1))
                vlib_plugin_path = argv[++i];
        } else if (!strncmp (argv[i], "heapsize", 8)) {
            sizep = (u8 *) argv[i+1];
            size = 0;
            while (*sizep >= '0' && *sizep <= '9') {
                size *= 10;
                size += *sizep++ - '0';
            }
            if (size == 0) {
                fprintf
                    (stderr, 
                     "warning: heapsize parse error '%s', use default %lld\n",
                     argv[i], (long long int) main_heap_size);
                goto defaulted;
            }

            main_heap_size = size;
            
            if (*sizep == 'g' || *sizep == 'G')
                main_heap_size <<= 30;
            else if (*sizep == 'm' || *sizep == 'M')
                main_heap_size <<= 20;
        }
    }
            
defaulted:

    /* Set up the plugin message ID allocator right now... */
    vl_msg_api_set_first_available_msg_id (VL_MSG_FIRST_AVAILABLE);

    /* Allocate main heap */
    if (clib_mem_init (0, main_heap_size)) {
        vlib_set_get_handoff_structure_cb (&vnet_get_handoff_structure);
        return vlib_unix_main (argc, argv);
    } else {
      {
	int rv __attribute__((unused)) =
	  write (2, "Main heap allocation failure!\r\n", 31);
      }
        return 1;
    }
}

static clib_error_t *
heapsize_config (vlib_main_t * vm, unformat_input_t * input)
{
    u32 junk;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "%dm", &junk)
            || unformat (input, "%dM", &junk)
            || unformat (input, "%dg", &junk)
            || unformat (input, "%dG", &junk))
            return 0;
        else
            return clib_error_return (0, "unknown input '%U'",
                                      format_unformat_error, input);
    }
    return 0;
}

VLIB_CONFIG_FUNCTION (heapsize_config, "heapsize");

static clib_error_t *
plugin_path_config (vlib_main_t * vm, unformat_input_t * input)
{
    u8 * junk;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
        if (unformat (input, "%s", &junk)) {
            vec_free(junk);
            return 0;
        }
        else
            return clib_error_return (0, "unknown input '%U'",
                                      format_unformat_error, input);
        }
    return 0;
}

VLIB_CONFIG_FUNCTION (plugin_path_config, "plugin_path");

void vl_msg_api_post_mortem_dump(void);

void os_panic (void) 
{ 
    vl_msg_api_post_mortem_dump();
    abort (); 
}

void vhost_user_unmap_all (void) __attribute__((weak));
void vhost_user_unmap_all (void) { }

void os_exit (int code)
{ 
    static int recursion_block;

    if (code)
      {
        if (recursion_block)
            abort();

        recursion_block = 1;

        vl_msg_api_post_mortem_dump();
        vhost_user_unmap_all();
        abort();
      }
    exit (code);
}

void vl_msg_api_barrier_sync(void) 
{ 
  vlib_worker_thread_barrier_sync (vlib_get_main());
}

void vl_msg_api_barrier_release(void) 
{ 
  vlib_worker_thread_barrier_release (vlib_get_main());
}

/* This application needs 1 thread stack for the stats pthread */
u32 vlib_app_num_thread_stacks_needed (void) 
{
  return 1;
}

#if CLIB_DEBUG > 0

static clib_error_t *
test_crash_command_fn (vlib_main_t * vm,
                       unformat_input_t * input,
                       vlib_cli_command_t * cmd)
{
  u64 * p = (u64 *)0xdefec8ed;

  *p = 0xdeadbeef;

  /* Not so much... */
  return 0;
}

VLIB_CLI_COMMAND (test_crash_command, static) = {
    .path = "test crash",
    .short_help = "crash the bus!",
    .function = test_crash_command_fn,
};

#endif

