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
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>
#include <vnet/flow/flow.h>
#include <Python.h>

#define PF_DEFAULT_STRING_LEN 1024

uword
packetforge_parser (char *pattern, u8 *ret_spec, u8 *ret_mask, int profile_use)
{
  PyObject *pModule, *pFunc;
  PyObject *pArgs, *pValue;
  u8 *spec, *mask;

  Py_Initialize ();

  PyRun_SimpleString ("import sys");
  PyRun_SimpleString ("import os");
  PyRun_SimpleString (
    "sys.path.append(os.getcwd() + '/src/plugins/packetforge/base')");

  pModule = PyImport_Import (PyUnicode_FromString ("packetforge"));

  if (pModule != NULL)
    {
      pFunc = PyObject_GetAttrString (pModule, "Forge");
      if (pFunc && PyCallable_Check (pFunc))
	{
	  pArgs = PyTuple_New (2);
	  PyTuple_SetItem (pArgs, 0, Py_BuildValue ("s", pattern));
	  PyTuple_SetItem (pArgs, 1, Py_BuildValue ("i", profile_use));

	  pValue = PyObject_CallObject (pFunc, pArgs);
	  Py_DECREF (pArgs);
	  if (pValue == NULL)
	    {
	      PyErr_Print ();
	      Py_DECREF (pFunc);
	      Py_DECREF (pModule);
	      return -1;
	    }

	  PyArg_ParseTuple (pValue, "ss", &spec, &mask);
	  if (*spec == 0 || *mask == 0)
	    {
	      PyErr_Print ();
	      Py_DECREF (pFunc);
	      Py_DECREF (pModule);
	      return -1;
	    }
	  memcpy (ret_spec, spec, PF_DEFAULT_STRING_LEN);
	  memcpy (ret_mask, mask, PF_DEFAULT_STRING_LEN);
	}
      else
	{
	  PyErr_Print ();
	}
      Py_DECREF (pFunc);
      Py_DECREF (pModule);
    }
  else
    {
      PyErr_Print ();
      return -1;
    }

  Py_Finalize ();
  return 0;
}

static clib_error_t *
packetforge_flow_add (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd_arg)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_flow_t flow;
  char *json_profile = NULL;
  char *pattern = NULL;
  u32 queue_start = 0, queue_end = 0;
  u32 flow_index;
  u8 spec[PF_DEFAULT_STRING_LEN] = {};
  u8 mask[PF_DEFAULT_STRING_LEN] = {};
  int profile_use = 0;
  int rv;

  clib_memset (&flow, 0, sizeof (vnet_flow_t));

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "profile %s", &json_profile))
	profile_use = 1;
      else if (unformat (line_input, "pattern %s", &pattern))
	;
      else if (unformat (line_input, "index %u", &flow_index))
	;
      else if (unformat (line_input, "next-node %U", unformat_vlib_node, vm,
			 &flow.redirect_node_index))
	flow.actions |= VNET_FLOW_ACTION_REDIRECT_TO_NODE;
      else if (unformat (line_input, "mark %d", &flow.mark_flow_id))
	flow.actions |= VNET_FLOW_ACTION_MARK;
      else if (unformat (line_input, "buffer-advance %d",
			 &flow.buffer_advance))
	flow.actions |= VNET_FLOW_ACTION_BUFFER_ADVANCE;
      else if (unformat (line_input, "redirect-to-queue %d",
			 &flow.redirect_queue))
	flow.actions |= VNET_FLOW_ACTION_REDIRECT_TO_QUEUE;
      else if (unformat (line_input, "drop"))
	flow.actions |= VNET_FLOW_ACTION_DROP;
      else if (unformat (line_input, "rss function"))
	{
	  if (0)
	    ;
#undef _
#define _(f, s)                                                               \
  else if (unformat (line_input, s)) flow.rss_fun = VNET_RSS_FUNC_##f;

	  foreach_rss_function
#undef _
	    else
	  {
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, line_input);
	  }

	  flow.actions |= VNET_FLOW_ACTION_RSS;
	}
      else if (unformat (line_input, "rss queues"))
	{
	  if (unformat (line_input, "%d to %d", &queue_start, &queue_end))
	    ;
	  else
	    {
	      return clib_error_return (0, "unknown input `%U'",
					format_unformat_error, line_input);
	    }
	  flow.queue_index = queue_start;
	  flow.queue_num = queue_end - queue_start + 1;

	  flow.actions |= VNET_FLOW_ACTION_RSS;
	}
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  /**
   * Parse json profile or pattern and get corresponding spec and mask
   * via packetforge.
   */
  if (!json_profile && !pattern)
    return clib_error_return (0, "Please specify json profile or pattern");

  if (profile_use)
    {
      if (packetforge_parser (json_profile, spec, mask, profile_use))
	return clib_error_return (0, "Read json profile failed");
    }
  else
    {
      if (packetforge_parser (pattern, spec, mask, profile_use))
	return clib_error_return (0, "Parse pattern failed");
    }

  clib_memcpy (flow.generic.pattern.spec, spec,
	       sizeof (flow.generic.pattern.spec));
  clib_memcpy (flow.generic.pattern.mask, mask,
	       sizeof (flow.generic.pattern.mask));

  flow.type = VNET_FLOW_TYPE_GENERIC;
  rv = vnet_flow_add (vnm, &flow, &flow_index);
  if (!rv)
    vlib_cli_output (vm, "flow %u added", flow_index);
  if (rv < 0)
    return clib_error_return (0, "flow add failed");

  return 0;
}

/**
 * @brief CLI command to use paccketforge to add flow.
 */
VLIB_CLI_COMMAND (packetforge_flow_add_command, static) = {
  .path = "packetforge flow add",
  .short_help = "packetforge flow add [profile <json_profile_name>]"
		"[pattern <packet_pattern>]"
		"[next-node <node>] [mark <id>] [buffer-advance <len>] "
		"[redirect-to-queue <queue>] [drop] "
		"[rss function <name>]"
		"[rss queues <queue_start> to <queue_end>]",
  .function = packetforge_flow_add,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Packetforge (packetforge)",
};
