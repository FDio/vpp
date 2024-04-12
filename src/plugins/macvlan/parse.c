/* Copyright (c) 2024 Cisco and/or its affiliates.
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
 * limitations under the License. */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include "macvlan.h"

clib_error_t *
macvlan_parse_add_del (unformat_input_t *input, u32 *parent_sw_if_index,
		       u32 *child_sw_if_index, bool *is_add)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *err = 0;

  *parent_sw_if_index = ~0;
  *child_sw_if_index = ~0;
  *is_add = true;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing input");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	*is_add = true;
      else if (unformat (line_input, "del"))
	*is_add = false;
      else if (unformat (line_input, "parent %U", unformat_vnet_sw_interface,
			 vnm, parent_sw_if_index))
	;
      else if (unformat (line_input, "child %U", unformat_vnet_sw_interface,
			 vnm, child_sw_if_index))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, line_input);
	  break;
	}
    }

  unformat_free (line_input);
  return err;
}
