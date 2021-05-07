/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef included_vppinfra_netns_h
#define included_vppinfra_netns_h

#include <vppinfra/format.h>

#include <fcntl.h>

__clib_export int
clib_netns_open (char *netns)
{
  u8 *s = 0;
  int fd;

  if (strncmp (netns, "pid:", 4) == 0)
    s = format (0, "/proc/%u/ns/net%c", atoi (netns + 4), 0);
  else if (netns[0] == '/')
    s = format (0, "%s%c", netns, 0);
  else
    s = format (0, "/var/run/netns/%s%c", netns, 0);

  fd = open ((char *) s, O_RDONLY);
  vec_free (s);
  return fd;
}

#endif /* included_vppinfra_netns_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
