/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 DriveNets Ltd.
 */

/**
 * @file
 * @brief Seamless BFD (RFC 7880, RFC 7881) reflector
 */

#include <vnet/bfd/bfd_api.h>
#include <vnet/bfd/bfd_main.h>

vnet_api_error_t
bfd_sbfd_reflector_add (u32 discriminator, u8 admin_up, u32 required_min_rx_usec)
{
  bfd_main_t *bm = &bfd_main;
  u32 disc = clib_host_to_net_u32 (discriminator);
  bfd_sbfd_reflector_t *r;

  if (0 == discriminator)
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator must be non-zero");
      return VNET_API_ERROR_INVALID_VALUE;
    }
  if (0 == required_min_rx_usec)
    {
      vlib_log_err (bm->log_class, "S-BFD required min rx interval must be non-zero");
      return VNET_API_ERROR_INVALID_VALUE;
    }
  if (hash_get (bm->sbfd_reflector_by_disc, disc))
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator %u already exists", discriminator);
      return VNET_API_ERROR_BFD_EEXIST;
    }

  pool_get_zero (bm->sbfd_reflectors, r);
  r->discriminator = disc;
  r->admin_up = admin_up;
  r->required_min_rx_usec = required_min_rx_usec;
  hash_set (bm->sbfd_reflector_by_disc, disc, r - bm->sbfd_reflectors);
  vlib_log_info (bm->log_class, "add S-BFD reflector discriminator %u", discriminator);
  return 0;
}

vnet_api_error_t
bfd_sbfd_reflector_mod (u32 discriminator, u8 admin_up, u32 required_min_rx_usec)
{
  bfd_main_t *bm = &bfd_main;
  uword *p = hash_get (bm->sbfd_reflector_by_disc, clib_host_to_net_u32 (discriminator));
  bfd_sbfd_reflector_t *r;

  if (!p)
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator %u not found", discriminator);
      return VNET_API_ERROR_BFD_ENOENT;
    }
  if (0 == required_min_rx_usec)
    {
      vlib_log_err (bm->log_class, "S-BFD required min rx interval must be non-zero");
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* in place, without removing the discriminator */
  r = pool_elt_at_index (bm->sbfd_reflectors, p[0]);
  r->admin_up = admin_up;
  r->required_min_rx_usec = required_min_rx_usec;
  vlib_log_info (bm->log_class, "modify S-BFD reflector discriminator %u", discriminator);
  return 0;
}

vnet_api_error_t
bfd_sbfd_reflector_del (u32 discriminator)
{
  bfd_main_t *bm = &bfd_main;
  u32 disc = clib_host_to_net_u32 (discriminator);
  uword *p = hash_get (bm->sbfd_reflector_by_disc, disc);
  u32 idx;

  if (!p)
    {
      vlib_log_err (bm->log_class, "S-BFD discriminator %u not found", discriminator);
      return VNET_API_ERROR_BFD_ENOENT;
    }
  idx = p[0];
  hash_unset (bm->sbfd_reflector_by_disc, disc);
  pool_put_index (bm->sbfd_reflectors, idx);
  vlib_log_info (bm->log_class, "delete S-BFD reflector discriminator %u", discriminator);
  return 0;
}
