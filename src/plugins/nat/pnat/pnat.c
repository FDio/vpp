/*
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
 */
#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include "pnat.h"
#include <vnet/ip/format.h>
#include <arpa/inet.h>
#include <vnet/ip/ip4.h>
#include <vnet/fib/fib_table.h>
#include <vnet/plugin/plugin.h>

/*
 * This is the main control plane part of the PNAT (Policy 1:1 NAT) feature.
 */


pnat_main_t pnat_main;

/*
 * Do a lookup in the interface vector (interface_by_sw_if_index)
 * and return pool entry.
 */
pnat_interface_t *
pnat_interface_by_sw_if_index (u32 sw_if_index)
{
  pnat_main_t *pm = &pnat_main;
  if (!pm->interface_by_sw_if_index ||
      sw_if_index > (vec_len(pm->interface_by_sw_if_index) - 1)) return 0;
  u32 index = pm->interface_by_sw_if_index[sw_if_index];
  if (index == ~0) return 0;
  if (pool_is_free_index(pm->interfaces, index)) return 0;
  return pool_elt_at_index(pm->interfaces, index);
}

/*
 * Create new PNAT interface object and register the pnat feature in the
 * corresponding feature chain.
 * Also enable shallow virtual reassembly, to ensure that we have
 * L4 ports available for all packets we receive.
 */
static clib_error_t *
pnat_enable_interface(u32 sw_if_index, bool input, pnat_mask_t mask)
{
  pnat_main_t *pm = &pnat_main;
  pnat_interface_t *interface = pnat_interface_by_sw_if_index(sw_if_index);

  if (!interface) {
    pool_get_zero(pm->interfaces, interface);
    interface->sw_if_index = sw_if_index;
    vec_validate_init_empty(pm->interface_by_sw_if_index, sw_if_index, ~0);
    pm->interface_by_sw_if_index[sw_if_index] = interface - pm->interfaces;
  }

  bool enabled = input ? interface->input_enabled : interface->output_enabled;
  if (!enabled) {
    char *nodename = input ? "pnat-input" : "pnat-output";
    char *arcname = input ? "ip4-unicast" : "ip4-output";
    if (vnet_feature_enable_disable (arcname, nodename, sw_if_index, 1, 0, 0) != 0)
      return clib_error_return(0, "PNAT feature enable failed on %u", sw_if_index);

    if (input) {
      /* TODO: Make shallow virtual reassembly configurable */
      ip4_sv_reass_enable_disable_with_refcnt(sw_if_index, 1);
      interface->input_enabled = true;
      interface->input_lookup_mask = mask;
    } else {
      ip4_sv_reass_output_enable_disable_with_refcnt(sw_if_index, 1);
      interface->output_enabled = true;
      interface->output_lookup_mask = mask;
    }
  } else {
    pnat_mask_t current_mask = input ? interface->input_lookup_mask : interface->output_lookup_mask;
    if (current_mask != mask) {
      return clib_error_return(0, "PNAT lookup mask must be consistent per interface/direction %u", sw_if_index);
    }
  }

  return 0;
}

/*
 * From a 5-tuple (with mask) calculate the key used in the flow cache lookup.
 */
static inline void
pnat_calc_key_from_5tuple (u32 sw_if_index, bool input, pnat_5tuple_t *match, pnat_key_t *k)
{
  k->as_u64[0] = k->as_u64[1] = 0;
  if (match->mask & PNAT_SA)
    clib_memcpy_fast(&k->sa, &match->src, 4);
  if (match->mask & PNAT_DA)
    clib_memcpy_fast(&k->da, &match->dst, 4);
  k->proto = match->proto;
  k->sw_if_index = sw_if_index;
  k->input = input;
  if (match->mask & PNAT_SPORT)
    k->sp = match->sport;
  if (match->mask & PNAT_DPORT)
    k->dp = match->dport;
}

/*
 * Map between the 5-tuple mask and the instruction set of the rewrite node.
 */
pnat_instructions_t
pnat_instructions_from_mask (pnat_mask_t m)
{
  pnat_instructions_t i = 0;

  if (m & PNAT_SA) i |= PNAT_INSTR_SOURCE_ADDRESS;
  if (m & PNAT_DA) i |= PNAT_INSTR_DESTINATION_ADDRESS;
  if (m & PNAT_SPORT) i |= PNAT_INSTR_SOURCE_PORT;
  if (m & PNAT_DPORT) i |= PNAT_INSTR_DESTINATION_PORT;
  return i;
}

/*
 * "Init" the PNAT datastructures. Called upon first creation of a PNAT rule.
 * Note there is no disable.
 * TODO: Make number of buckets configurable.
 */
static void
pnat_enable(void)
{
  pnat_main_t *pm = &pnat_main;
  if (pm->enabled) return;

  /* Create new flow cache table */
  clib_bihash_init_16_8 (&pm->flowhash, "flow hash", 100, 0);

  pm->enabled = true;
}

/*
 * Creates a translation (match/rewrite rule).
 * The translation is bound to interface and (direction in/out)
  */
int
pnat_add_translation (u32 sw_if_index, pnat_5tuple_t *match,
                      pnat_5tuple_t *rewrite, bool input, u32 *index)
{
  pnat_main_t *pm = &pnat_main;

  *index = -1;

  /* If we aren't matching or rewriting, why are we here? */
  if (match->mask == 0 || rewrite->mask == 0) return -1;

  /* Check if protocol is set if ports are set */
  if ((match->dport || match->sport) && (match->proto != 17 && match->proto != 6)) return -2;
  if ((rewrite->dport || rewrite->sport) && (rewrite->proto != 17 && rewrite->proto != 6)) return -2;

  pnat_enable();

  /* Verify non-duplicate */
  clib_bihash_kv_16_8_t kv, value;
  pnat_key_t *k = (pnat_key_t *)&kv.key;
  pnat_calc_key_from_5tuple(sw_if_index, input, match, k);
  if (clib_bihash_search_16_8(&pm->flowhash, &kv, &value) == 0) return -3;

  /* Create pool entry */
  pnat_translation_t *t;
  pool_get_zero(pm->translations, t);
  memcpy(&t->post_da, &rewrite->dst, 4);
  memcpy(&t->post_sa, &rewrite->src, 4);
  t->post_sp = rewrite->sport;
  t->post_dp = rewrite->dport;
  t->instructions = pnat_instructions_from_mask(rewrite->mask);

  /* Create flow cache */
  kv.value = t - pm->translations;
  if (clib_bihash_add_del_16_8(&pm->flowhash, &kv, 1)) {
    pool_put(pm->translations, t);
    return -4;
  }

  /* These are only used for show commands and trace */
  t->match = *match;
  t->rewrite = *rewrite;
  t->key = *k;

  /* Register interface */
  pnat_enable_interface(sw_if_index, input, match->mask);

  *index = t - pm->translations;

  return 0;
}

/*
 * Delete a translation using the index returned from pnat_add_translation.
 */
int
pnat_del_translation (u32 index)
{
  pnat_main_t *pm = &pnat_main;

  if (pool_is_free_index(pm->translations, index)) {
    clib_warning ("Binding delete: translation does not exist: %d", index);
    return -1;
  }

  pnat_translation_t *t = pool_elt_at_index(pm->translations, index);
  if (!t) return -2;

  if (clib_bihash_add_del_16_8(&pm->flowhash, (clib_bihash_kv_16_8_t *)&t->key, 0)) {
    pool_put(pm->translations, t);
    return -3;
  }
  pool_put(pm->translations, t);

  return 0;
}

/*
 * Register the plugin and hook up the API
 */
VLIB_PLUGIN_REGISTER() = {
  .version = "0.0.1",
  .description = "Policy 1:1 NAT",
};

clib_error_t *pnat_plugin_api_hookup (vlib_main_t * vm);

clib_error_t *
pnat_init (vlib_main_t * vm)
{
  pnat_main_t *pm = &pnat_main;
  memset (pm, 0, sizeof(*pm));

  return pnat_plugin_api_hookup(vm);
}

VLIB_INIT_FUNCTION (pnat_init);
