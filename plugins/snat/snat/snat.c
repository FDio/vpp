/*
 * snat.c - simple nat plugin
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <snat/snat.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

snat_main_t snat_main;

/* define message IDs */
#include <snat/snat_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <snat/snat_all_api_h.h> 
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <snat/snat_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <snat/snat_all_api_h.h> 
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <snat/snat_all_api_h.h>
#undef vl_api_version

/* 
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+sm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);


/* List of message types that this plugin understands */

#define foreach_snat_plugin_api_msg 


/* Hook up input features */
VNET_IP4_UNICAST_FEATURE_INIT (ip4_snat_in2out, static) = {
  .node_name = "snat-in2out",
  .runs_before = {"snat-out2in", 0},
  .feature_index = &snat_main.rx_feature_in2out,
};
VNET_IP4_UNICAST_FEATURE_INIT (ip4_snat_out2in, static) = {
  .node_name = "snat-out2in",
  .runs_before = {"ip4-lookup", 0},
  .feature_index = &snat_main.rx_feature_out2in,
};

/* 
 * This routine exists to convince the vlib plugin framework that
 * we haven't accidentally copied a random .dll into the plugin directory.
 *
 * Also collects global variable pointers passed from the vpp engine
 */

clib_error_t * 
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
                      int from_early_init)
{
  snat_main_t * sm = &snat_main;
  clib_error_t * error = 0;

  sm->vlib_main = vm;
  sm->vnet_main = h->vnet_main;
  sm->ethernet_main = h->ethernet_main;

  return error;
}

/* Set up the API message handling tables */
static clib_error_t *
snat_plugin_api_hookup (vlib_main_t *vm)
{
   snat_main_t * sm __attribute__ ((unused)) = &snat_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_snat_plugin_api_msg;
#undef _

    return 0;
}

static clib_error_t * snat_init (vlib_main_t * vm)
{
  snat_main_t * sm = &snat_main;
  clib_error_t * error = 0;
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  u8 * name;

  name = format (0, "snat_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids 
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = snat_plugin_api_hookup (vm);

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main();
  sm->ip4_main = im;
  sm->ip4_lookup_main = lm;

  vec_free(name);

  return error;
}

VLIB_INIT_FUNCTION (snat_init);

void snat_free_outside_address_and_port (snat_main_t * sm, 
                                         snat_session_key_t * k, 
                                         u32 address_index)
{
  snat_address_t *a;
  u16 port_host_byte_order = clib_net_to_host_u16 (k->port);
  
  ASSERT (address_index < vec_len (sm->addresses));

  a = sm->addresses + address_index;

  ASSERT (clib_bitmap_get (a->busy_port_bitmap, port_host_byte_order) == 1);

  a->busy_port_bitmap = clib_bitmap_set (a->busy_port_bitmap, 
                                         port_host_byte_order, 0);
  a->busy_ports--;
}  

int snat_alloc_outside_address_and_port (snat_main_t * sm, 
                                         snat_session_key_t * k,
                                         u32 * address_indexp)
{
  int i;
  snat_address_t *a;
  u32 portnum;

  for (i = 0; i < vec_len (sm->addresses); i++)
    {
      if (sm->addresses[i].busy_ports < (65535-1024))
        {
          a = sm->addresses + i;

          while (1)
            {
              portnum = random_u32 (&sm->random_seed);
              portnum &= 0xFFFF;
              if (portnum < 1024)
                continue;
              if (clib_bitmap_get (a->busy_port_bitmap, portnum))
                continue;
              a->busy_port_bitmap = clib_bitmap_set (a->busy_port_bitmap,
                                                     portnum, 1);
              a->busy_ports++;
              /* Caller sets protocol and fib index */
              k->addr = a->addr;
              k->port = clib_host_to_net_u16(portnum);
              *address_indexp = i;
              return 0;
            }
        }
    }
  /* Totally out of translations to use... */
  return 1;
}

void snat_add_address (snat_main_t *sm, ip4_address_t *addr)
{
  snat_address_t * ap;

  vec_add2 (sm->addresses, ap, 1);
  ap->addr = *addr;

}

static void increment_v4_address (ip4_address_t * a)
{
  u32 v;
  
  v = clib_net_to_host_u32(a->as_u32) + 1;
  a->as_u32 = clib_host_to_net_u32(v);
}


static clib_error_t *
add_address_command_fn (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
{
  snat_main_t * sm = &snat_main;
  ip4_address_t start_addr, end_addr, this_addr;
  u32 start_host_order, end_host_order;
  int i, count;

  if (unformat (input, "%U - %U", 
                unformat_ip4_address, &start_addr,
                unformat_ip4_address, &end_addr))
    ;
  else if (unformat (input, "%U", unformat_ip4_address, &start_addr))
    end_addr = start_addr;

  start_host_order = clib_host_to_net_u32 (start_addr.as_u32);
  end_host_order = clib_host_to_net_u32 (end_addr.as_u32);
  
  if (end_host_order < start_host_order)
    return clib_error_return (0, "end address less than start address");

  count = (end_host_order - start_host_order) + 1;

  if (count > 1024)
    clib_warning ("%U - %U, %d addresses...",
                  format_ip4_address, &start_addr,
                  format_ip4_address, &end_addr,
                  count);
  
  this_addr = start_addr;

  for (i = 0; i < count; i++)
    {
      snat_add_address (sm, &this_addr);
      increment_v4_address (&this_addr);
    }

  return 0;
}

VLIB_CLI_COMMAND (add_address_command, static) = {
  .path = "snat add address",
  .short_help = "snat add addresses <ip4-range-start> [- <ip4-range-end>]",
  .function = add_address_command_fn,
};

static clib_error_t *
snat_feature_command_fn (vlib_main_t * vm,
                          unformat_input_t * input,
                          vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  snat_main_t * sm = &snat_main;
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_config_main_t * rx_cm = &lm->rx_config_mains[VNET_UNICAST];
  clib_error_t * error = 0;
  u32 sw_if_index, ci;
  u32 feature_index;
  u32 * inside_sw_if_indices = 0;
  u32 * outside_sw_if_indices = 0;
  int is_del = 0;
  int i;

  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "in %U", unformat_vnet_sw_interface, 
                    vnm, &sw_if_index))
        vec_add1 (inside_sw_if_indices, sw_if_index);
      else if (unformat (input, "out %U", unformat_vnet_sw_interface, 
                         vnm, &sw_if_index))
        vec_add1 (outside_sw_if_indices, sw_if_index);
      else if (unformat (input, "del"))
        is_del = 1;
      else
        break;
    }

  if (vec_len (inside_sw_if_indices))
    {
      feature_index = sm->rx_feature_in2out;

      for (i = 0; i < vec_len(inside_sw_if_indices); i++)
        {
          sw_if_index = inside_sw_if_indices[i];
          ci = rx_cm->config_index_by_sw_if_index[sw_if_index];
          ci = (is_del
                ? vnet_config_del_feature
                : vnet_config_add_feature)
            (vm, &rx_cm->config_main,
             ci,
             feature_index,
             0 /* config struct */, 
             0 /* sizeof config struct*/);
          rx_cm->config_index_by_sw_if_index[sw_if_index] = ci;
        }
    }

  if (vec_len (outside_sw_if_indices))
    {
      feature_index = sm->rx_feature_out2in;

      for (i = 0; i < vec_len(outside_sw_if_indices); i++)
        {
          sw_if_index = outside_sw_if_indices[i];
          ci = rx_cm->config_index_by_sw_if_index[sw_if_index];
          ci = (is_del
                ? vnet_config_del_feature
                : vnet_config_add_feature)
            (vm, &rx_cm->config_main,
             ci,
             feature_index,
             0 /* config struct */, 
             0 /* sizeof config struct*/);
          rx_cm->config_index_by_sw_if_index[sw_if_index] = ci;
        }
    }

  vec_free (inside_sw_if_indices);
  vec_free (outside_sw_if_indices);

  return error;
}

VLIB_CLI_COMMAND (set_interface_snat_command, static) = {
  .path = "set interface snat",
  .function = snat_feature_command_fn,
  .short_help = "set interface snat in <intfc> out <intfc> [del]",
};

static clib_error_t *
snat_config (vlib_main_t * vm, unformat_input_t * input)
{
  snat_main_t * sm = &snat_main;
  u32 translation_buckets = 1024;
  u32 translation_memory_size = 128<<20;
  u32 user_buckets = 128;
  u32 user_memory_size = 64<<20;
  u32 max_translations_per_user = 100;
  u32 outside_vrf_id = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "translation hash buckets %d", &translation_buckets))
        ;
      else if (unformat (input, "translation hash memory %d",
                         &translation_memory_size));
      else if (unformat (input, "user hash buckets %d", &user_buckets))
        ;
      else if (unformat (input, "user hash memory %d",
                         &user_memory_size))
        ;
      else if (unformat (input, "max translations per user %d",
                         &max_translations_per_user))
        ;
      else if (unformat (input, "outside VRF id %d",
                         &outside_vrf_id))
        ;
      else 
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  /* for show commands, etc. */
  sm->translation_buckets = translation_buckets;
  sm->translation_memory_size = translation_memory_size;
  sm->user_buckets = user_buckets;
  sm->user_memory_size = user_memory_size;
  sm->max_translations_per_user = max_translations_per_user;
  sm->outside_vrf_id = outside_vrf_id;

  clib_bihash_init_8_8 (&sm->in2out, "in2out", translation_buckets,
                        translation_memory_size);
  
  clib_bihash_init_8_8 (&sm->out2in, "out2in", translation_buckets,
                        translation_memory_size);

  clib_bihash_init_8_8 (&sm->user_hash, "users", user_buckets,
                        user_memory_size);
  return 0;
}

VLIB_CONFIG_FUNCTION (snat_config, "snat");

u8 * format_snat_key (u8 * s, va_list * args)
{
  snat_session_key_t * key = va_arg (*args, snat_session_key_t *);
  char * protocol_string = "unknown";
  static char *protocol_strings[] = {
      "UDP",
      "TCP",
      "ICMP",
  };

  if (key->protocol < ARRAY_LEN(protocol_strings))
      protocol_string = protocol_strings[key->protocol];

  s = format (s, "%U proto %s port %d fib %d",
              format_ip4_address, &key->addr, protocol_string,
              key->port, key->fib_index);
  return s;
}

u8 * format_snat_session (u8 * s, va_list * args)
{
  snat_main_t * sm __attribute__((unused)) = va_arg (*args, snat_main_t *);
  snat_session_t * sess = va_arg (*args, snat_session_t *);

  s = format (s, "  i2o %U\n", format_snat_key, &sess->in2out);
  s = format (s, "    o2i %U\n", format_snat_key, &sess->out2in);
  s = format (s, "       last heard %.2f\n", sess->last_heard);
  s = format (s, "       total pkts %d, total bytes %lld\n",
              sess->total_pkts, sess->total_bytes);

  return s;
}

u8 * format_snat_user (u8 * s, va_list * args)
{
  snat_main_t * sm = va_arg (*args, snat_main_t *);
  snat_user_t * u = va_arg (*args, snat_user_t *);
  int verbose = va_arg (*args, int);
  dlist_elt_t * head, * elt;
  u32 elt_index, head_index;
  u32 session_index;
  snat_session_t * sess;

  s = format (s, "%U: %d translations\n",
              format_ip4_address, &u->addr, u->nsessions);

  if (verbose == 0)
    return s;

  head_index = u->sessions_per_user_list_head_index;
  head = pool_elt_at_index (sm->list_pool, head_index);

  elt_index = head->next;
  elt = pool_elt_at_index (sm->list_pool, elt_index);
  session_index = elt->value;

  while (session_index != ~0)
    {
      sess = pool_elt_at_index (sm->sessions, session_index);

      s = format (s, "  %U\n", format_snat_session, sm, sess);

      elt_index = elt->next;
      elt = pool_elt_at_index (sm->list_pool, elt_index);
      session_index = elt->value;
    }

  return s;
}

static clib_error_t *
show_snat_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
  int verbose = 0;
  snat_main_t * sm = &snat_main;
  snat_user_t * u;

  if (unformat (input, "detail"))
    verbose = 1;
  else if (unformat (input, "verbose"))
    verbose = 2;

  vlib_cli_output (vm, "%d users, %d outside addresses, %d active sessions",
                   pool_elts (sm->users),
                   vec_len (sm->addresses),
                   pool_elts (sm->sessions));
  
  if (verbose > 0)
    {
      vlib_cli_output (vm, "%U", format_bihash_8_8, &sm->in2out,
                       verbose - 1);
      vlib_cli_output (vm, "%U", format_bihash_8_8, &sm->out2in,
                       verbose - 1);
      vlib_cli_output (vm, "%d list pool elements",
                       pool_elts (sm->list_pool));

      pool_foreach (u, sm->users,
      ({
        vlib_cli_output (vm, "%U", format_snat_user, sm, u, verbose - 1);
      }));
    }

  return 0;
}

VLIB_CLI_COMMAND (show_snat_command, static) = {
    .path = "show snat",
    .short_help = "show snat",
    .function = show_snat_command_fn,
};
