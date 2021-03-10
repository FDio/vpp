/*
 * Copyright (c) 2020 Intel and/or its affiliates.
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
/*
 * node_init.c: node march variant startup initialization
 *
 * Copyright (c) 2020 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <sys/types.h>
#include <fcntl.h>
#include <vlib/vlib.h>

static clib_error_t *
vlib_node_config (vlib_main_t *vm, unformat_input_t *input)
{
  clib_error_t *error = 0;
  unformat_input_t sub_input;
  u32 *march_variant_by_node = 0;
  clib_march_variant_type_t march_variant;
  u32 node_index;
  int i;

  /* specify prioritization defaults for all graph nodes */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "default %U", unformat_vlib_cli_sub_input,
		    &sub_input))
	{
	  while (unformat_check_input (&sub_input) != UNFORMAT_END_OF_INPUT)
	    {
	      if (!unformat (&sub_input, "variant %U",
			     unformat_vlib_node_variant, &march_variant))
		return clib_error_return (0,
					  "please specify a valid node variant");

	      vec_validate_init_empty (march_variant_by_node,
				       vec_len (vm->node_main.nodes) - 1, ~0);
	      vec_foreach_index (i, march_variant_by_node)
		march_variant_by_node[i] = march_variant;
	      vm->node_main.node_fn_default_march_variant = march_variant;
	      unformat_free (&sub_input);
	    }
	}
      else /* specify prioritization for an individual graph node */
	if (unformat (input, "%U", unformat_vlib_node, vm, &node_index))
	{
	  if (unformat (input, "%U", unformat_vlib_cli_sub_input, &sub_input))
	    {
	      while (unformat_check_input (&sub_input) !=
		     UNFORMAT_END_OF_INPUT)
		{
		  if (!unformat (&sub_input, "variant %U",
				 unformat_vlib_node_variant, &march_variant))
		    return clib_error_return (0,
					      "please specify a valid node variant");
		  vec_validate_init_empty (march_variant_by_node, node_index,
					   ~0);
		  march_variant_by_node[node_index] = march_variant;
		  unformat_free (&sub_input);
		}
	    }
	}
      else
	{
	  break;
	}
    }

  if (march_variant_by_node)
    {
      vec_foreach_index (i, march_variant_by_node)
	if (march_variant_by_node[i] != ~0)
	  vlib_node_set_march_variant (vm, i, march_variant_by_node[i]);
      vec_free (march_variant_by_node);
    }
  unformat_free (input);

  return error;
}

VLIB_CONFIG_FUNCTION (vlib_node_config, "node");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
