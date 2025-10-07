/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>
#include <selog/selog.h>

#define SELOG_DEFAULT_SSVM_NAME "selog_ssvm"

static clib_error_t *
selog_init (vlib_main_t *vm)
{
  selog_main_t *sm = &selog_main;
  ssvm_private_t *ssvm = &sm->ssvm;
  elog_event_t *new_ring;
  elog_main_t *old_em = vlib_get_elog_main ();
  uword n_entries = old_em->event_ring_size;
  int rv;

  if (sm->config.ssvm_name == 0)
    sm->config.ssvm_name =
      (u8 *) format (0, "%s%c", SELOG_DEFAULT_SSVM_NAME, 0);

  ssvm->name = sm->config.ssvm_name;
  ssvm->ssvm_size =
    clib_mem_get_page_size () + 2 * n_entries * sizeof (elog_event_t);

  if ((rv = ssvm_server_init_memfd (ssvm)) != 0)
    return clib_error_return (0, "ssvm_server_init_memfd failed: %d", rv);

  sm->shr =
    clib_mem_heap_alloc (ssvm->sh->heap, sizeof (selog_shared_header_t));
  clib_memset (sm->shr, 0, sizeof (selog_shared_header_t));
  sm->em = &sm->shr->em;
  /* Copy existing elog_main as is in shared memory */
  clib_memcpy (sm->em, old_em, sizeof (elog_main_t));

  /* Create a ring buffer in the shared heap */
  new_ring =
    vec_new_heap (elog_event_t, vec_len (sm->em->event_ring), ssvm->sh->heap);

  /* Copy existing events */
  clib_memcpy (new_ring, sm->em->event_ring,
	       vec_len (sm->em->event_ring) * sizeof (elog_event_t));

  vec_free (sm->em->event_ring);
  sm->em->event_ring = new_ring;
  /* opaque[0] contains the offset to reach the selog_shared_header */
  ssvm->sh->opaque[0] = (void *) ((void *) sm->shr - (void *) ssvm->sh);
  vlib_update_elog_main (sm->em);
  clib_mem_free (old_em);
  clib_atomic_store_rel_n (&ssvm->sh->ready, 1);
  return 0;
}
VLIB_INIT_FUNCTION (selog_init);

static clib_error_t *
selog_config (vlib_main_t *vm, unformat_input_t *input)
{
  selog_main_t *sm = &selog_main;
  selog_config_t *config = &sm->config;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ssvm-name %s", &config->ssvm_name))
	;
      else
	{
	  return clib_error_return (0, "Invalid selog config");
	}
    }
  return 0;
}
VLIB_CONFIG_FUNCTION (selog_config, "selog");

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "sFlow random packet sampling",
};
selog_main_t selog_main;