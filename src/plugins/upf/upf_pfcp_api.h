/*
 * Copyright(c) 2018 Travelping GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _UPF_PFCP_ERL_H
#define _UPF_PFCP_ERL_H

#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include "pfcp.h"
#include "upf.h"
#include "upf_pfcp_server.h"

#define PRIsMAC "%02x:%02x:%02x:%02x:%02x:%02x"
#define ARGsMAC(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

int upf_pfcp_handle_msg (pfcp_msg_t * msg);

u8 *format_ipfilter (u8 * s, va_list * args);

typedef struct
{
  pfcp_reporting_triggers_t triggers;
  f64 now;
} upf_usage_report_ev_t;

typedef struct
{
  upf_usage_report_ev_t *events;
  uword *liusa_bitmap;
} upf_usage_report_t;

static inline void
upf_usage_report_init (upf_usage_report_t * report, int n_urrs)
{
  ASSERT (report);

  report->events = vec_new (typeof (report->events[0]), n_urrs);
  clib_bitmap_alloc (report->liusa_bitmap, n_urrs);
};

static inline void
upf_usage_report_set (upf_usage_report_t * report,
		      pfcp_reporting_triggers_t triggers, f64 now)
{
  ASSERT (report);

  vec_set (report->events, ((upf_usage_report_ev_t)
			    {
			    .triggers = triggers,.now = now}));
};

static inline void
upf_usage_report_free (upf_usage_report_t * report)
{
  ASSERT (report);

  vec_free (report->events);
  clib_bitmap_free (report->liusa_bitmap);
};

static inline void
upf_usage_report_trigger (upf_usage_report_t * report, u32 idx,
			  pfcp_reporting_triggers_t triggers,
			  uword * liusa_bitmap, f64 now)
{
  ASSERT (report);

  vec_elt (report->events, idx).triggers = triggers;
  vec_elt (report->events, idx).now = now;

  if (liusa_bitmap)
    report->liusa_bitmap =
      clib_bitmap_or (report->liusa_bitmap, liusa_bitmap);
};

void
upf_usage_report_build (upf_session_t * sx,
			ip46_address_t * ue,
			upf_urr_t * urr, f64 now,
			upf_usage_report_t * report,
			pfcp_usage_report_t ** usage_report);

#endif /* _UPF_PFCP_ERL_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
