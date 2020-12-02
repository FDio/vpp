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
#include <vnet/vnet.h>

typedef struct _vlib_node_march_variant
{
  struct _vlib_node_march_variant *next_variant;
  char *name;
} vlib_node_march_variant_t;

#define VLIB_VARIANT_REGISTER()			\
  static vlib_node_march_variant_t			\
  CLIB_MARCH_VARIANT##variant;				\
							\
  static void __clib_constructor			\
  CLIB_MARCH_VARIANT##_register (void)			\
  {							\
    extern vlib_node_march_variant_t *variants;	\
    vlib_node_march_variant_t *v;			\
    v = & CLIB_MARCH_VARIANT##variant;			\
    v->name = CLIB_MARCH_VARIANT_STR;			\
    v->next_variant = variants;			\
    variants = v;					\
  }							\

VLIB_VARIANT_REGISTER ();

#ifndef CLIB_MARCH_VARIANT

vlib_node_march_variant_t *variants = 0;

uword
unformat_vlib_node_variant (unformat_input_t * input, va_list * args)
{
  u8 **variant = va_arg (*args, u8 **);
  vlib_node_march_variant_t *v = variants;

  if (!unformat (input, "%v", variant))
    return 0;

  while (v)
    {
      if (!strncmp (v->name, (char *) *variant, vec_len (*variant)))
	return 1;

      v = v->next_variant;
    }

  return 0;
}

static_always_inline void
vlib_update_nr_variant_default (vlib_node_fn_registration_t * fnr,
				u8 * variant)
{
  vlib_node_fn_registration_t *p_reg = 0;
  vlib_node_fn_registration_t *v_reg = 0;
  u32 tmp;

  while (fnr)
    {
      /* which is the highest priority registration */
      if (!p_reg || fnr->priority > p_reg->priority)
	p_reg = fnr;

      /* which is the variant we want to prioritize */
      if (!strncmp (fnr->name, (char *) variant, vec_len (variant) - 1))
	v_reg = fnr;

      fnr = fnr->next_registration;
    }

  /* node doesn't have the variants */
  if (!v_reg)
    return;

  ASSERT (p_reg != 0 && v_reg != 0);

  /* swap priorities */
  tmp = p_reg->priority;
  p_reg->priority = v_reg->priority;
  v_reg->priority = tmp;

}

static clib_error_t *
vlib_early_node_config (vlib_main_t * vm, unformat_input_t * input)
{
  clib_error_t *error = 0;
  vlib_node_registration_t *nr, **all;
  vnet_device_class_t *c;
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t sub_input;
  uword *hash = 0, *p;
  u8 *variant = 0;
  u8 *s = 0;

  all = 0;
  hash = hash_create_string (0, sizeof (uword));

  nr = vm->node_main.node_registrations;
  while (nr)
    {
      hash_set_mem (hash, nr->name, vec_len (all));
      vec_add1 (all, nr);

      nr = nr->next_registration;
    }

  /* specify prioritization defaults for all graph nodes */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "default %U", unformat_vlib_cli_sub_input,
		    &sub_input))
	{
	  while (unformat_check_input (&sub_input) != UNFORMAT_END_OF_INPUT)
	    {
	      if (!unformat (&sub_input, "variant %U",
			     unformat_vlib_node_variant, &variant))
		return clib_error_return (0,
					  "please specify a valid node variant");
	      vec_add1 (variant, 0);

	      nr = vm->node_main.node_registrations;
	      while (nr)
		{
		  vlib_update_nr_variant_default (nr->node_fn_registrations,
						  variant);
		  nr = nr->next_registration;
		}

	      /* also apply it to interfaces */
	      c = vnm->device_class_registrations;
	      while (c)
		{
		  vlib_update_nr_variant_default (c->tx_fn_registrations,
						  variant);
		  c = c->next_class_registration;
		}

	      vec_free (variant);
	    }
	}
      else /* specify prioritization for an individual graph node */
      if (unformat (input, "%s", &s))
	{
	  if (!(p = hash_get_mem (hash, s)))
	    {
	      error = clib_error_return (0,
					 "node variants: unknown graph node '%s'",
					 s);
	      break;
	    }

	  nr = vec_elt (all, p[0]);

	  if (unformat (input, "%U", unformat_vlib_cli_sub_input, &sub_input))
	    {
	      while (unformat_check_input (&sub_input) !=
		     UNFORMAT_END_OF_INPUT)
		{
		  if (!unformat (&sub_input, "variant %U",
				 unformat_vlib_node_variant, &variant))
		    return clib_error_return (0,
					      "please specify a valid node variant");
		  vec_add1 (variant, 0);

		  vlib_update_nr_variant_default (nr->node_fn_registrations,
						  variant);

		  vec_free (variant);
		}
	    }
	}
      else
	{
	  break;
	}
    }

  hash_free (hash);
  vec_free (all);
  unformat_free (input);

  return error;
}

VLIB_EARLY_CONFIG_FUNCTION (vlib_early_node_config, "node");

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
