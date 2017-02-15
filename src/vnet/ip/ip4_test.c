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
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

/**
 * @file
 * @brief IPv4 FIB Tester.
 *
 * Not compiled in by default. IPv4 FIB tester. Add, probe, delete a bunch of
 * random routes / masks and make sure that the mtrie agrees with
 * the hash-table FIB.
 *
 * Manipulate the FIB by means of the debug CLI commands, to minimize
 * the chances of doing something idiotic.
 */

/*
 * These routines need to be redeclared non-static elsewhere.
 *
 * Also: rename ip_route() -> vnet_ip_route_cmd() and add the usual
 * test_route_init() call to main.c
 */
clib_error_t *vnet_ip_route_cmd (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd_arg);

int ip4_lookup_validate (ip4_address_t * a, u32 fib_index0);

ip4_fib_t *find_fib_by_table_index_or_id (ip4_main_t * im,
					  u32 table_index_or_id, u32 flags);

/* Routes to insert/delete/probe in FIB */
typedef struct
{
  ip4_address_t address;
  u32 mask_width;
  u32 interface_id;		/* not an xx_if_index */
} test_route_t;

typedef struct
{
  /* Test routes in use */
  test_route_t *route_pool;

  /* Number of fake ethernets created */
  u32 test_interfaces_created;
} test_main_t;

test_main_t test_main;

/* fake ethernet device class, distinct from "fake-ethX" */
static u8 *
format_test_interface_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "test-eth%d", dev_instance);
}

static uword
dummy_interface_tx (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (test_interface_device_class,static) = {
  .name = "Test interface",
  .format_device_name = format_test_interface_name,
  .tx_function = dummy_interface_tx,
};
/* *INDENT-ON* */

static clib_error_t *
thrash (vlib_main_t * vm,
	unformat_input_t * main_input, vlib_cli_command_t * cmd_arg)
{
  u32 seed = 0xdeaddabe;
  u32 niter = 10;
  u32 nroutes = 10;
  u32 ninterfaces = 4;
  f64 min_mask_bits = 7.0;
  f64 max_mask_bits = 32.0;
  u32 table_id = 11;		/* my amp goes to 11 (use fib 11) */
  u32 table_index;
  int iter, i;
  u8 *cmd;
  test_route_t *tr;
  test_main_t *tm = &test_main;
  ip4_main_t *im = &ip4_main;
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t cmd_input;
  f64 rf;
  u32 *masks = 0;
  u32 tmp;
  u32 hw_if_index;
  clib_error_t *error = 0;
  uword *p;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 hw_address[6];
  ip4_fib_t *fib;
  int verbose = 0;

  /* Precompute mask width -> mask vector */
  tmp = (u32) ~ 0;
  vec_validate (masks, 32);
  for (i = 32; i > 0; i--)
    {
      masks[i] = tmp;
      tmp <<= 1;
    }

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "seed %d", &seed))
	    ;
	  else if (unformat (line_input, "niter %d", &niter))
	    ;
	  else if (unformat (line_input, "nroutes %d", &nroutes))
	    ;
	  else if (unformat (line_input, "ninterfaces %d", &ninterfaces))
	    ;
	  else if (unformat (line_input, "min-mask-bits %d", &tmp))
	    min_mask_bits = (f64) tmp;
	  else if (unformat (line_input, "max-mask-bits %d", &tmp))
	    max_mask_bits = (f64) tmp;
	  else if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, line_input);
	      goto done;
	    }
	}
    }

  /* Find or create FIB table 11 */
  fib = ip4_fib_find_or_create_fib_by_table_id (table_id);

  for (i = tm->test_interfaces_created; i < ninterfaces; i++)
    {
      vnet_hw_interface_t *hw;
      memset (hw_address, 0, sizeof (hw_address));
      hw_address[0] = 0xd0;
      hw_address[1] = 0x0f;
      hw_address[5] = i;

      error = ethernet_register_interface
	(vnm, test_interface_device_class.index, i /* instance */ ,
	 hw_address, &hw_if_index,
	 /* flag change */ 0);

      /* Fake interfaces use FIB table 11 */
      hw = vnet_get_hw_interface (vnm, hw_if_index);
      vec_validate (im->fib_index_by_sw_if_index, hw->sw_if_index);
      im->fib_index_by_sw_if_index[hw->sw_if_index] = fib->index;
      ip4_sw_interface_enable_disable (sw_if_index, 1);
    }

  tm->test_interfaces_created = ninterfaces;

  /* Find fib index corresponding to FIB id 11 */
  p = hash_get (im->fib_index_by_table_id, table_id);
  if (p == 0)
    {
      vlib_cli_output (vm, "Couldn't map fib id %d to fib index\n", table_id);
      goto done;
    }
  table_index = p[0];

  for (iter = 0; iter < niter; iter++)
    {
      /* Pick random routes to install */
      for (i = 0; i < nroutes; i++)
	{
	  int j;

	  pool_get (tm->route_pool, tr);
	  memset (tr, 0, sizeof (*tr));

	again:
	  rf = random_f64 (&seed);
	  tr->mask_width = (u32) (min_mask_bits
				  + rf * (max_mask_bits - min_mask_bits));
	  tmp = random_u32 (&seed);
	  tmp &= masks[tr->mask_width];
	  tr->address.as_u32 = clib_host_to_net_u32 (tmp);

	  /* We can't add the same address/mask twice... */
	  for (j = 0; j < i; j++)
	    {
	      test_route_t *prev;
	      prev = pool_elt_at_index (tm->route_pool, j);
	      if ((prev->address.as_u32 == tr->address.as_u32)
		  && (prev->mask_width == tr->mask_width))
		goto again;
	    }

	  rf = random_f64 (&seed);
	  tr->interface_id = (u32) (rf * ninterfaces);
	}

      /* Add them */
      for (i = 0; i < nroutes; i++)
	{
	  tr = pool_elt_at_index (tm->route_pool, i);
	  cmd = format (0, "add table %d %U/%d via test-eth%d",
			table_id,
			format_ip4_address, &tr->address,
			tr->mask_width, tr->interface_id);
	  vec_add1 (cmd, 0);
	  if (verbose)
	    fformat (stderr, "ip route %s\n", cmd);
	  unformat_init_string (&cmd_input, (char *) cmd, vec_len (cmd) - 1);
	  error = vnet_ip_route_cmd (vm, &cmd_input, cmd_arg);
	  if (error)
	    clib_error_report (error);
	  unformat_free (&cmd_input);
	  vec_free (cmd);
	}
      /* Probe them */
      for (i = 0; i < nroutes; i++)
	{
	  tr = pool_elt_at_index (tm->route_pool, i);
	  if (!ip4_lookup_validate (&tr->address, table_index))
	    {
	      if (verbose)
		fformat (stderr, "test lookup table %d %U\n",
			 table_index, format_ip4_address, &tr->address);

	      fformat (stderr, "FAIL-after-insert: %U/%d\n",
		       format_ip4_address, &tr->address, tr->mask_width);
	    }
	}

      /* Delete them */
      for (i = 0; i < nroutes; i++)
	{
	  int j;
	  tr = pool_elt_at_index (tm->route_pool, i);
	  if (0)
	    cmd = format (0, "del table %d %U/%d via test-eth%d",
			  table_id,
			  format_ip4_address, &tr->address,
			  tr->mask_width, tr->interface_id);
	  else
	    cmd = format (0, "del table %d %U/%d",
			  table_id,
			  format_ip4_address, &tr->address, tr->mask_width);
	  vec_add1 (cmd, 0);
	  if (verbose)
	    fformat (stderr, "ip route %s\n", cmd);
	  unformat_init_string (&cmd_input, (char *) cmd, vec_len (cmd) - 1);
	  error = vnet_ip_route_cmd (vm, &cmd_input, cmd_arg);
	  if (error)
	    clib_error_report (error);
	  unformat_free (&cmd_input);
	  vec_free (cmd);

	  /* Make sure all undeleted routes still work */
	  for (j = i + 1; j < nroutes; j++)
	    {
	      test_route_t *rr;	/* remaining route */
	      rr = pool_elt_at_index (tm->route_pool, j);
	      if (!ip4_lookup_validate (&rr->address, table_index))
		{
		  if (verbose)
		    fformat (stderr, "test lookup table %d %U\n",
			     table_index, format_ip4_address, &rr->address);

		  fformat (stderr, "FAIL: %U/%d AWOL\n",
			   format_ip4_address, &rr->address, rr->mask_width);
		  fformat (stderr, " iter %d after %d of %d deletes\n",
			   iter, i, nroutes);
		  fformat (stderr, " last route deleted %U/%d\n",
			   format_ip4_address, &tr->address, tr->mask_width);
		}
	    }
	}

      pool_free (tm->route_pool);
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command in not in the build by default. It is an internal
 * command used to test the route functonality.
 *
 * Create test routes on IPv4 FIB table 11. Table will be created if it
 * does not exist.
 *
 * There are several optional attributes:
 * - If not provided, <seed> defaults to 0xdeaddabe.
 * - If not provided, <num-iter> defaults to 10.
 * - If not provided, <num-iface> defaults to 4.
 * - If not provided, <min-mask> defaults to 7.0.
 * - If not provided, <max-mask> defaults to 32.0.
 *
 * @cliexpar
 * Example of how to run:
 * @cliexcmd{test route}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_route_command, static) = {
    .path = "test route",
    .short_help = "test route [seed <seed-num>] [niter <num-iter>] [ninterfaces <num-iface>] [min-mask-bits <min-mask>] [max-mask-bits <max-mask>] [verbose]",    .function = thrash,
    .function = thrash,
};
/* *INDENT-ON* */

clib_error_t *
test_route_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (test_route_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
