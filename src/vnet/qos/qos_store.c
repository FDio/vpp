/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/qos/qos_store.h>
#include <vnet/ip/ip.h>
#include <vnet/feature/feature.h>

/**
 * QoS Store configuration
 */
typedef struct qos_store_t_
{
  u8 qst_n_cfgs;
  qos_bits_t qst_value;
} qos_store_t;

/**
 * Per-interface, per-protocol vector of feature on/off configurations
 */
qos_store_t *qos_store_configs[QOS_N_SOURCES];

static void
qos_store_feature_config (u32 sw_if_index,
			  qos_source_t input_source,
			  u8 enable, qos_bits_t value)
{
  switch (input_source)
    {
    case QOS_SOURCE_IP:
      vnet_feature_enable_disable ("ip6-unicast", "ip6-qos-store",
				   sw_if_index, enable, &value,
				   sizeof (value));
      vnet_feature_enable_disable ("ip6-multicast", "ip6-qos-store",
				   sw_if_index, enable, &value,
				   sizeof (value));
      vnet_feature_enable_disable ("ip4-unicast", "ip4-qos-store",
				   sw_if_index, enable, &value,
				   sizeof (value));
      vnet_feature_enable_disable ("ip4-multicast", "ip4-qos-store",
				   sw_if_index, enable, &value,
				   sizeof (value));
      break;
    case QOS_SOURCE_MPLS:
    case QOS_SOURCE_VLAN:
    case QOS_SOURCE_EXT:
      /* not a valid option for storeing */
      break;
    }
}

int
qos_store_enable (u32 sw_if_index,
		  qos_source_t input_source, qos_bits_t value)
{
  qos_store_t *qst;

  if (QOS_SOURCE_IP != input_source)
    return VNET_API_ERROR_UNIMPLEMENTED;

  vec_validate (qos_store_configs[input_source], sw_if_index);

  qst = &qos_store_configs[input_source][sw_if_index];

  if (0 == qst->qst_n_cfgs)
    {
      qst->qst_value = value;
      qos_store_feature_config (sw_if_index, input_source, 1, value);
    }

  qst->qst_n_cfgs++;

  return (0);
}

int
qos_store_disable (u32 sw_if_index, qos_source_t input_source)
{
  qos_store_t *qst;

  if (vec_len (qos_store_configs[input_source]) <= sw_if_index)
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;

  qst = &qos_store_configs[input_source][sw_if_index];

  if (0 == qst->qst_n_cfgs)
    return VNET_API_ERROR_VALUE_EXIST;

  qst->qst_n_cfgs--;

  if (0 == qst->qst_n_cfgs)
    {
      qos_store_feature_config (sw_if_index, input_source, 0, qst->qst_value);
    }

  return (0);
}

void
qos_store_walk (qos_store_walk_cb_t fn, void *c)
{
  qos_source_t qs;

  FOR_EACH_QOS_SOURCE (qs)
  {
    qos_store_t *qst;
    u32 sw_if_index;

    vec_foreach_index (sw_if_index, qos_store_configs[qs])
    {
      qst = &qos_store_configs[qs][sw_if_index];
      if (0 != qst->qst_n_cfgs)
	fn (sw_if_index, qs, qst->qst_value, c);
    }
  }
}

/*
 * Disable storeing feature for all protocols when the interface
 * is deleted
 */
static clib_error_t *
qos_store_ip_interface_add_del (vnet_main_t * vnm,
				u32 sw_if_index, u32 is_add)
{
  if (!is_add)
    {
      qos_source_t qs;

      FOR_EACH_QOS_SOURCE (qs)
      {
	while (qos_store_disable (sw_if_index, qs) == 0);
      }
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (qos_store_ip_interface_add_del);

clib_error_t *
qos_store_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (qos_store_init);

static clib_error_t *
qos_store_cli (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index, qs, value;
  u8 enable;

  qs = 0xff;
  enable = 1;
  sw_if_index = ~0;
  value = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "%U", unformat_qos_source, &qs))
	;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "value &d", &value))
	;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");
  if (~0 == value)
    return clib_error_return (0, "value to be stored must be specified");
  if (0xff == qs)
    return clib_error_return (0, "input location must be specified");

  if (enable)
    qos_store_enable (sw_if_index, qs, value);
  else
    qos_store_disable (sw_if_index, qs);

  return (NULL);
}

/*?
 * Enable QoS bit storeing on an interface using the packet's input DSCP bits
 * Which input QoS bits to use are either; IP, MPLS or VLAN. If more than
 * one protocol is chosen (which is foolish) the higher layers override the
 * lower.
 *
 * @cliexpar
 * @cliexcmd{qos store ip GigEthernet0/1/0}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_store_command, static) = {
  .path = "qos store",
  .short_help = "qos store <store-source> <INTERFACE> [disable]",
  .function = qos_store_cli,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static void
qos_store_show_one_interface (vlib_main_t * vm, u32 sw_if_index)
{
  u8 n_cfgs[QOS_N_SOURCES] = { };
  qos_source_t qs;
  bool set;

  set = false;

  FOR_EACH_QOS_SOURCE (qs)
  {
    if (vec_len (qos_store_configs[qs]) <= sw_if_index)
      continue;
    if (0 != (n_cfgs[qs] = qos_store_configs[qs][sw_if_index].qst_n_cfgs))
      set = true;
  }

  if (set)
    {
      vlib_cli_output (vm, " %U:", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);

      FOR_EACH_QOS_SOURCE (qs)
      {
	if (n_cfgs[qs] != 0)
	  vlib_cli_output (vm, "  %U -> %d",
			   format_qos_source, qs,
			   qos_store_configs[qs][sw_if_index].qst_value);
      }
    }
}

static clib_error_t *
qos_store_show (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  qos_source_t qs;
  u32 sw_if_index;

  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
    }

  if (~0 == sw_if_index)
    {
      u32 ii, n_ints = 0;

      FOR_EACH_QOS_SOURCE (qs)
      {
	n_ints = clib_max (n_ints, vec_len (qos_store_configs[qs]));
      }

      for (ii = 0; ii < n_ints; ii++)
	{
	  qos_store_show_one_interface (vm, ii);
	}
    }
  else
    qos_store_show_one_interface (vm, sw_if_index);

  return (NULL);
}

/*?
 * Show Egress Qos Maps
 *
 * @cliexpar
 * @cliexcmd{show qos egress map}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_store_show_command, static) = {
  .path = "show qos store",
  .short_help = "show qos store [interface]",
  .function = qos_store_show,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
