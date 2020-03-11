#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include "pool.h"
#include "nat_slowpath.h"

/*
 * Generic prefix pool
 *
 * Create a new pool (prefix)
 * Lookup in a prefix in a pool
 * Get address from pool (adj load balancing algorithm)
 * (ip4_compute_flow_hash (ip0, lb0->lb_hash_config);)
 * Support just a single pool at the moment.
 */

extern nat_slowpath_main_t nat_slowpath_main;

static int
pool_add_del_ext_addr_pool (ip4_address_t * prefix, u8 prefixlen,
			    u32 vrf_id, bool is_add)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main; // register and make modular

  /* ignore delete */

  nsm->pool.vrf_id = vrf_id;
  ip4_address_normalize (prefix, prefixlen);
  nsm->pool.prefix = *prefix;
  nsm->pool.prefixlen = prefixlen;
  nsm->pool.count = 0x1 << (32 - prefixlen);

  return 0;
}

ip4_address_t
nat_slowpath_pool_get_address(u32 vrf_id, ip4_address_t *ip)
{
  nat_slowpath_main_t *nsm = &nat_slowpath_main; // register and make modular
  return nsm->pool.prefix;
}

static clib_error_t *
pool_command_fn (vlib_main_t * vm,
		     unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t prefix;
  u32 prefix_len, vrf_id;
  bool is_add = true;
  int rv = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
          (line_input, "%U/%d", unformat_ip4_address, &prefix, &prefix_len))
        ;
      else if (unformat (line_input, "vrf %u", &vrf_id))
        ;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  rv = pool_add_del_ext_addr_pool (&prefix, (u8) prefix_len, vrf_id, is_add);
  switch (rv)
    {
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "NAT address already in use.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "NAT address not exist.");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (pool_add_ext_addr_pool_command, static) = {
  .path = "nat prefix-pool add",
  .short_help =
      "nat prefix-pool add <ip4-pfx> [vrf-id <id>] [del]",
  .function = pool_command_fn,
};
