/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef __CNAT_LOG_H__
#define __CNAT_LOG_H__

#include "cnat_session.h"

typedef struct
{
  ip46_address_t ip;
  int enabled;
} cnat_log_main_t;

extern cnat_log_main_t cnat_log_main;

void cnat_log_session_create__ (const cnat_session_t *s);
void cnat_log_session_free__ (const cnat_session_t *s);
void cnat_log_session_overwrite__ (const cnat_session_t *s);
void cnat_log_session_expire__ (const cnat_session_t *s);
void cnat_log_scanner_start (int i);
void cnat_log_scanner_stop (int i);
void cnat_log_enable_disable (const ip46_address_t *ip, int enable);

static_always_inline int
cnat_log_session_is_logged (const cnat_session_t *s)
{
  const cnat_log_main_t *clm = &cnat_log_main;
  if (PREDICT_TRUE (!clm->enabled))
    return 0;
  if (!ip46_address_is_zero (&clm->ip) &&
      !ip46_address_is_equal (&clm->ip, &s->key.cs_5tuple.ip[VLIB_RX]) &&
      !ip46_address_is_equal (&clm->ip, &s->key.cs_5tuple.ip[VLIB_TX]))
    return 0;
  return 1;
}

static_always_inline void
cnat_log_session_create (const cnat_session_t *s)
{
  if (PREDICT_FALSE (cnat_log_session_is_logged (s)))
    cnat_log_session_create__ (s);
}

static_always_inline void
cnat_log_session_free (const cnat_session_t *s)
{
  if (PREDICT_FALSE (cnat_log_session_is_logged (s)))
    cnat_log_session_free__ (s);
}

static_always_inline void
cnat_log_session_overwrite (const cnat_session_t *s)
{
  if (PREDICT_FALSE (cnat_log_session_is_logged (s)))
    cnat_log_session_overwrite__ (s);
}

static_always_inline void
cnat_log_session_expire (const cnat_session_t *s)
{
  if (PREDICT_FALSE (cnat_log_session_is_logged (s)))
    cnat_log_session_expire__ (s);
}

#endif /* __CNAT_LOG_H__ */
