/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_PROM_PROM_H_
#define SRC_PLUGINS_PROM_PROM_H_

#include <vnet/session/session.h>
#include <http_static/http_static.h>

typedef struct prom_main_
{
  u8 *stats;
  f64 last_scrape;
  hss_register_url_fn register_url;
  hss_session_send_fn send_data;
  u32 scraper_node_index;
  u8 is_enabled;
  u8 *name_scratch_pad;
  vlib_main_t *vm;

  /*
   * Configs
   */
  u8 **stats_patterns;
  u8 *stat_name_prefix;
  f64 min_scrape_interval;
  u8 used_only;
} prom_main_t;

typedef enum prom_process_evt_codes_
{
  PROM_SCRAPER_EVT_RUN,
} prom_process_evt_codes_t;

clib_error_t *prom_enable (vlib_main_t *vm);
prom_main_t *prom_get_main (void);

void prom_stat_patterns_set (u8 **patterns);
void prom_stat_patterns_add (u8 **patterns);
u8 **prom_stat_patterns_get (void);
void prom_stat_patterns_free (void);

void prom_stat_name_prefix_set (u8 *prefix);
void prom_report_used_only (u8 used_only);

#endif /* SRC_PLUGINS_PROM_PROM_H_ */
