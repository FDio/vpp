/*
 * tunnel.h: shared definitions for tunnels.
 *
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

#include <vnet/tunnel/tunnel.h>

u8 *
format_tunnel_mode (u8 * s, va_list * args)
{
  tunnel_mode_t mode = va_arg (*args, int);

  switch (mode)
    {
#define _(n, v) case TUNNEL_MODE_##n:       \
        s = format (s, "%s", v);            \
        break;
      foreach_tunnel_mode
#undef _
    }

  return (s);
}

u8 *
format_tunnel_encap_decap_flags (u8 * s, va_list * args)
{
  tunnel_encap_decap_flags_t f = va_arg (*args, int);

  if (f == TUNNEL_ENCAP_DECAP_FLAG_NONE)
    return (format (s, "none"));

#define _(a,b,c) if (f & TUNNEL_ENCAP_DECAP_FLAG_##a) s = format(s, "%s ", b);
  forech_tunnel_encap_decap_flag
#undef _
    return (s);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
