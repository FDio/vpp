#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/flow/flow.h>
#include <vnet/ip/ip.h>
#include <vpp/app/version.h>

static clib_error_t *
insert_flow (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_flow_t templ;
  vnet_flow_range_t range;
  u32 hw_if_index = ~0;
  u32 template_index;
  u32 flow_indices[10];
  int rv;
  const u32 n_flows = 10;

  // 1. Parse interface from CLI
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  if (hw_if_index == ~0)
    return clib_error_return (0, "please specify interface name");

  // 2. Create flow template
  clib_memset (&templ, 0, sizeof (templ));
  templ.type = VNET_FLOW_TYPE_IP4_N_TUPLE;
  templ.actions = VNET_FLOW_ACTION_MARK | VNET_FLOW_ACTION_DROP;
  templ.mark_flow_id = 1;

  // Template pattern: match TCP traffic (wildcards will be set per-flow)
  templ.ip4_n_tuple.src_addr.addr.as_u32 = 0;
  templ.ip4_n_tuple.src_addr.mask.as_u32 = ~0;
  templ.ip4_n_tuple.dst_addr.addr.as_u32 = 0;
  templ.ip4_n_tuple.dst_addr.mask.as_u32 = ~0;
  templ.ip4_n_tuple.protocol.prot = IP_PROTOCOL_TCP;
  templ.ip4_n_tuple.protocol.mask = 0xff;
  templ.ip4_n_tuple.src_port.port = 0;
  templ.ip4_n_tuple.src_port.mask = ~0;
  templ.ip4_n_tuple.dst_port.port = 0;
  templ.ip4_n_tuple.dst_port.mask = ~0;

  // 3. Add template to template pool
  rv = vnet_flow_add_async_template (vnm, &templ, &template_index);
  if (rv)
    return clib_error_return (0, "vnet_flow_add_async_template failed: %d", rv);

  vlib_cli_output (vm, "Template index: %u", template_index);

  // 4. Enable template on interface
  rv = vnet_flow_async_template_enable (vnm, template_index, hw_if_index, n_flows);
  if (rv)
    return clib_error_return (0, "vnet_flow_async_template_enable failed: %d", rv);

  vlib_cli_output (vm, "Template enabled on interface");

  // 5. Add individual flows to the pool
  for (u32 i = 0; i < n_flows; i++)
    {
      vnet_flow_t f;
      clib_memset (&f, 0, sizeof (f));
      f.type = VNET_FLOW_TYPE_IP4_N_TUPLE;
      f.actions = VNET_FLOW_ACTION_MARK | VNET_FLOW_ACTION_DROP;
      f.mark_flow_id = 1000 + i;

      // Set specific match criteria for each flow
      f.ip4_n_tuple.src_addr.addr.as_u32 = 0;
      f.ip4_n_tuple.src_addr.mask.as_u32 = 0;
      f.ip4_n_tuple.dst_addr.addr.as_u32 = 0;
      f.ip4_n_tuple.dst_addr.mask.as_u32 = 0;
      f.ip4_n_tuple.protocol.prot = IP_PROTOCOL_TCP;
      f.ip4_n_tuple.protocol.mask = 0xff;
      f.ip4_n_tuple.src_port.port = 0;
      f.ip4_n_tuple.src_port.mask = 0;
      // Each flow matches a different destination port
      f.ip4_n_tuple.dst_port.port = clib_host_to_net_u16 (80 + i);
      f.ip4_n_tuple.dst_port.mask = 0xffff;

      rv = vnet_flow_add (vnm, &f, &flow_indices[i]);
      if (rv)
	return clib_error_return (0, "vnet_flow_add failed for flow %u: %d", i, rv);
    }

  vlib_cli_output (vm, "Added %u flows (indices %u-%u)", n_flows, flow_indices[0],
		   flow_indices[n_flows - 1]);

  // 6. Construct range structure
  // Note: This assumes flow indices are contiguous (true for fresh pool)
  range.start = flow_indices[0];
  range.count = n_flows;
  range.owner = (u8 *) "flow_test";

  // 7. Enable flows asynchronously
  rv = vnet_flow_async_enable (vnm, &range, template_index, hw_if_index);
  if (rv)
    return clib_error_return (0, "vnet_flow_async_enable failed: %d", rv);

  vlib_cli_output (vm, "Successfully enabled %u async flows", n_flows);

  return 0;
}

VLIB_CLI_COMMAND (insert_flow_cmd, static) = {
  .path = "test flow",
  .short_help = "test flow <interface>",
  .function = insert_flow,
};
