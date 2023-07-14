/*
 * nsh.c - nsh mapping
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
#include <nsh/nsh.h>
#include <gre/gre.h>
#include <vxlan/vxlan.h>
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/l2/l2_classify.h>
#include <vnet/adj/adj.h>
#include <vpp/app/version.h>

nsh_main_t nsh_main;

/* Uses network order's class and type to register */
int
nsh_md2_register_option (u16 class,
			 u8 type,
			 u8 option_size,
			 int add_options (u8 * opt,
					  u8 * opt_size),
			 int options (vlib_buffer_t * b,
				      nsh_tlv_header_t * opt),
			 int swap_options (vlib_buffer_t * b,
					   nsh_tlv_header_t * old_opt,
					   nsh_tlv_header_t * new_opt),
			 int pop_options (vlib_buffer_t * b,
					  nsh_tlv_header_t * opt),
			 u8 * trace (u8 * s, nsh_tlv_header_t * opt))
{
  nsh_main_t *nm = &nsh_main;
  nsh_option_map_by_key_t key, *key_copy;
  uword *p;
  nsh_option_map_t *nsh_option;

  key.class = class;
  key.type = type;
  key.pad = 0;

  p = hash_get_mem (nm->nsh_option_map_by_key, &key);
  /* Already registered */
  if (p != 0)
    {
      return (-1);
    }

  pool_get_aligned (nm->nsh_option_mappings, nsh_option,
		    CLIB_CACHE_LINE_BYTES);
  clib_memset (nsh_option, 0, sizeof (*nsh_option));
  nsh_option->option_id = nsh_option - nm->nsh_option_mappings;

  key_copy = clib_mem_alloc (sizeof (*key_copy));
  clib_memcpy (key_copy, &key, sizeof (*key_copy));
  hash_set_mem (nm->nsh_option_map_by_key, key_copy,
		nsh_option - nm->nsh_option_mappings);

  if (option_size > (MAX_NSH_OPTION_LEN + sizeof (nsh_tlv_header_t)))
    {
      return (-1);
    }
  nm->options_size[nsh_option->option_id] = option_size;
  nm->add_options[nsh_option->option_id] = add_options;
  nm->options[nsh_option->option_id] = options;
  nm->swap_options[nsh_option->option_id] = swap_options;
  nm->pop_options[nsh_option->option_id] = pop_options;
  nm->trace[nsh_option->option_id] = trace;

  return (0);
}

/* Uses network order's class and type to lookup */
nsh_option_map_t *
nsh_md2_lookup_option (u16 class, u8 type)
{
  nsh_main_t *nm = &nsh_main;
  nsh_option_map_by_key_t key;
  uword *p;

  key.class = class;
  key.type = type;
  key.pad = 0;

  p = hash_get_mem (nm->nsh_option_map_by_key, &key);
  /* not registered */
  if (p == 0)
    {
      return NULL;
    }

  return pool_elt_at_index (nm->nsh_option_mappings, p[0]);

}

/* Uses network order's class and type to unregister */
int
nsh_md2_unregister_option (u16 class,
			   u8 type,
			   int options (vlib_buffer_t * b,
					nsh_tlv_header_t * opt),
			   u8 * trace (u8 * s, nsh_tlv_header_t * opt))
{
  nsh_main_t *nm = &nsh_main;
  nsh_option_map_by_key_t key, *key_copy;
  uword *p;
  hash_pair_t *hp;
  nsh_option_map_t *nsh_option;

  key.class = class;
  key.type = type;
  key.pad = 0;

  p = hash_get_mem (nm->nsh_option_map_by_key, &key);
  /* not registered */
  if (p == 0)
    {
      return (-1);
    }

  nsh_option = pool_elt_at_index (nm->nsh_option_mappings, p[0]);
  nm->options[nsh_option->option_id] = NULL;
  nm->add_options[nsh_option->option_id] = NULL;
  nm->pop_options[nsh_option->option_id] = NULL;
  nm->trace[nsh_option->option_id] = NULL;

  hp = hash_get_pair (nm->nsh_option_map_by_key, &key);
  key_copy = (void *) (hp->key);
  hash_unset_mem (nm->nsh_option_map_by_key, &key_copy);
  clib_mem_free (key_copy);

  pool_put (nm->nsh_option_mappings, nsh_option);

  return (0);
}

/**
 * @brief Formatting function for tracing VXLAN GPE with length
 *
 * @param *s
 * @param *args
 *
 * @return *s
 *
 */
static u8 *
format_nsh_tunnel_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (nsh_hw_class) = {
  .name = "NSH",
  .format_header = format_nsh_tunnel_with_length,
  .build_rewrite = default_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

void
nsh_md2_set_next_ioam_export_override (uword next)
{
  nsh_main_t *hm = &nsh_main;
  hm->decap_v4_next_override = next;
  return;
}

clib_error_t *
nsh_init (vlib_main_t * vm)
{
  vlib_node_t *node;
  nsh_main_t *nm = &nsh_main;
  clib_error_t *error = 0;
  uword next_node;
  vlib_node_registration_t *vxlan4_input, *vxlan6_input;
  vlib_node_registration_t *gre4_input, *gre6_input;

  /* Init the main structures from VPP */
  nm->vlib_main = vm;
  nm->vnet_main = vnet_get_main ();

  /* Various state maintenance mappings */
  nm->nsh_mapping_by_key = hash_create_mem (0, sizeof (u32), sizeof (uword));

  nm->nsh_mapping_by_mapped_key
    = hash_create_mem (0, sizeof (u32), sizeof (uword));

  nm->nsh_entry_by_key = hash_create_mem (0, sizeof (u32), sizeof (uword));

  nm->nsh_proxy_session_by_key
    =
    hash_create_mem (0, sizeof (nsh_proxy_session_by_key_t), sizeof (uword));

  nm->nsh_option_map_by_key
    = hash_create_mem (0, sizeof (nsh_option_map_by_key_t), sizeof (uword));

  error = nsh_api_init (vm, nm);
  if (error)
    return error;

  node = vlib_get_node_by_name (vm, (u8 *) "nsh-input");
  nm->nsh_input_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nsh-proxy");
  nm->nsh_proxy_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nsh-classifier");
  nm->nsh_classifier_node_index = node->index;

  /* Add dispositions to nodes that feed nsh-input */
  //alagalah - validate we don't really need to use the node value
  next_node =
    vlib_node_add_next (vm, vxlan4_gpe_input_node.index,
			nm->nsh_input_node_index);
  vlib_node_add_next (vm, vxlan4_gpe_input_node.index,
		      nm->nsh_proxy_node_index);
  vlib_node_add_next (vm, vxlan4_gpe_input_node.index,
		      nsh_aware_vnf_proxy_node.index);
  vxlan_gpe_register_decap_protocol (VXLAN_GPE_PROTOCOL_NSH, next_node);

  vlib_node_add_next (vm, vxlan6_gpe_input_node.index,
		      nm->nsh_input_node_index);
  vlib_node_add_next (vm, vxlan6_gpe_input_node.index,
		      nm->nsh_proxy_node_index);
  vlib_node_add_next (vm, vxlan6_gpe_input_node.index,
		      nsh_aware_vnf_proxy_node.index);

  gre4_input =
    vlib_get_plugin_symbol ("gre_plugin.so", "gre4_input_node");
  gre6_input =
    vlib_get_plugin_symbol ("gre_plugin.so", "gre6_input_node");

  vlib_node_add_next (vm, gre4_input->index, nm->nsh_input_node_index);
  vlib_node_add_next (vm, gre4_input->index, nm->nsh_proxy_node_index);
  vlib_node_add_next (vm, gre4_input->index,
		      nsh_aware_vnf_proxy_node.index);

  vlib_node_add_next (vm, gre6_input->index, nm->nsh_input_node_index);
  vlib_node_add_next (vm, gre6_input->index, nm->nsh_proxy_node_index);
  vlib_node_add_next (vm, gre6_input->index,
		      nsh_aware_vnf_proxy_node.index);

  /* Add NSH-Proxy support */
  vxlan4_input =
    vlib_get_plugin_symbol ("vxlan_plugin.so", "vxlan4_input_node");
  vxlan6_input =
    vlib_get_plugin_symbol ("vxlan_plugin.so", "vxlan6_input_node");
  if (vxlan4_input == 0 || vxlan6_input == 0)
    {
      error = clib_error_return (0, "vxlan_plugin.so is not loaded");
      return error;
    }
  vlib_node_add_next (vm, vxlan4_input->index, nm->nsh_proxy_node_index);
  vlib_node_add_next (vm, vxlan6_input->index, nm->nsh_proxy_node_index);

  /* Add NSH-Classifier support */
  vlib_node_add_next (vm, ip4_classify_node.index,
		      nm->nsh_classifier_node_index);
  vlib_node_add_next (vm, ip6_classify_node.index,
		      nm->nsh_classifier_node_index);
  vlib_node_add_next (vm, l2_input_classify_node.index,
		      nm->nsh_classifier_node_index);

  /* Add Ethernet+NSH support */
  ethernet_register_input_type (vm, ETHERNET_TYPE_NSH,
				nm->nsh_input_node_index);

  return error;
}

VLIB_INIT_FUNCTION (nsh_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Network Service Header (NSH)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
