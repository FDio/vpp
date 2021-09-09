/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <sched.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <net/if.h>

#include <plugins/linux-cp/lcp.h>
#include <plugins/linux-cp/lcp_interface.h>

lcp_main_t lcp_main;

u8 *
lcp_get_default_ns (void)
{
  lcp_main_t *lcpm = &lcp_main;

  if (!lcpm->default_namespace || lcpm->default_namespace[0] == 0)
    return NULL;

  return lcpm->default_namespace;
}

int
lcp_get_default_ns_fd (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->default_ns_fd;
}

/*
 * ns is expected to be or look like a NUL-terminated C string.
 */
int
lcp_set_default_ns (u8 *ns)
{
  lcp_main_t *lcpm = &lcp_main;
  char *p;
  int len;
  u8 *s;

  p = (char *) ns;
  len = clib_strnlen (p, LCP_NS_LEN);
  if (len >= LCP_NS_LEN)
    return -1;

  if (!p || *p == 0)
    {
      lcpm->default_namespace = NULL;
      if (lcpm->default_ns_fd > 0)
	close (lcpm->default_ns_fd);
      lcpm->default_ns_fd = 0;
      return 0;
    }

  vec_validate_init_c_string (lcpm->default_namespace, p,
			      clib_strnlen (p, LCP_NS_LEN));
  s = format (0, "/var/run/netns/%s%c", (char *) lcpm->default_namespace, 0);
  lcpm->default_ns_fd = open ((char *) s, O_RDONLY);
  vec_free (s);

  return 0;
}

void
lcp_set_sync (u8 is_auto)
{
  lcp_main_t *lcpm = &lcp_main;

  lcpm->lcp_sync = (is_auto != 0);

  // If we set to 'on', do a one-off sync of LCP interfaces
  if (is_auto)
    lcp_itf_pair_sync_state_all ();
}

int
lcp_sync (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->lcp_sync;
}

void
lcp_set_auto_subint (u8 is_auto)
{
  lcp_main_t *lcpm = &lcp_main;

  lcpm->lcp_auto_subint = (is_auto != 0);
}

int
lcp_auto_subint (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->lcp_auto_subint;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
