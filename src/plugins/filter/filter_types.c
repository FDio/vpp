/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <filter/filter_types.h>


u8 *
format_filter_hook_type (u8 * s, va_list * args)
{
  filter_hook_type_t fct = va_arg (*args, filter_hook_type_t);

  switch (fct)
    {
#define _(a, b) case FILTER_HOOK_##a:           \
    return (format (s, "%s", b));
      foreach_filter_hook_type
#undef _
    }

  return (format (s, "unknown"));
}

uword
unformat_filter_hook_type (unformat_input_t * input, va_list * args)
{
  filter_hook_type_t *fct = va_arg (*args, filter_hook_type_t *);

  if (0)
    {
    }
#define _(a,b) else if (unformat (input, b)) {           \
    *fct = FILTER_HOOK_##a;                              \
    return (1);                                          \
  }
  foreach_filter_hook_type
#undef _
    return (0);
}

u8 *
format_filter_chain_policy (u8 * s, va_list * args)
{
  filter_chain_policy_t fct = va_arg (*args, filter_chain_policy_t);

  switch (fct)
    {
#define _(a, b) case FILTER_CHAIN_POLICY_##a:           \
    return (format (s, "%s", b));
      foreach_filter_chain_policy
#undef _
    }

  return (format (s, "unknown"));
}

uword
unformat_filter_chain_policy (unformat_input_t * input, va_list * args)
{
  filter_chain_policy_t *fct = va_arg (*args, filter_chain_policy_t *);

  if (0)
    {
    }
#define _(a,b) else if (unformat (input, b)) {           \
    *fct = FILTER_CHAIN_POLICY_##a;                              \
    return (1);                                          \
  }
  foreach_filter_chain_policy
#undef _
    return (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
