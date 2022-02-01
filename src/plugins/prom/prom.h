/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#ifndef SRC_PLUGINS_PROM_PROM_H_
#define SRC_PLUGINS_PROM_PROM_H_

#include <vnet/session/session.h>
#include <http_static/http_static.h>

typedef struct prom_main_
{
  u8 *stats;
  f64 latest_scrape;
  hss_register_url_fn register_url;
  hss_session_send_fn send_data;
  u32 scraper_node_index;
  u8 is_enabled;

  vlib_main_t *vm;
} prom_main_t;

typedef enum prom_process_evt_codes_
{
  PROM_SCRAPER_EVT_RUN,
} prom_process_evt_codes_t;

#endif /* SRC_PLUGINS_PROM_PROM_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
