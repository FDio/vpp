/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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
#include <selog/selog_client/selog_client.h>
#include <stdio.h>
#include <time.h>

int
main (int argc, char *argv[])
{
  selog_client_ctx_t *ctx = selog_client_ctx_alloc ();
  int32_t rv;
  ctx->sock_name = "/run/vpp/api.sock";
  ctx->client_name = "selog_client_example";
  rv = selog_client_connect_to_vpp (ctx);
  if (rv)
    {
      printf ("selog_client_connect_to_vpp failed: %d %s\n", rv,
	      selog_client_error_strings[-rv]);
      return rv;
    }
  while (1)
    {
      selog_event_t event;
      int rv = selog_client_poll_event (ctx, &event, 1);
      if (rv == 1)
	{
	  char *s;
	  selog_client_format_events (ctx, &event, 1, &s);
	  printf ("%s\n", s);
	  selog_client_free_formatted_events (&s, 1);
	}
      else
	{
	  /* Sleep 100ms */
	  struct timespec req = { 0 }, rem = { 0 };
	  req.tv_sec = 0;
	  req.tv_nsec = 100 * 1000000L;
	  nanosleep (&req, &rem);
	}
    }
  selog_client_disconnect_from_vpp (ctx);
  return 0;
}