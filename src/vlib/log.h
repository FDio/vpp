/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_vlib_log_h
#define included_vlib_log_h

#include <vppinfra/types.h>

typedef u32 vlib_log_class_t;

#define foreach_vlib_log_level \
  _(0, EMERG, emerg) \
  _(1, ALERT, alert) \
  _(2, CRIT, crit) \
  _(3, ERR, err) \
  _(4, WARNING, warn) \
  _(5, NOTICE, notice) \
  _(6, INFO, info) \
  _(7, DEBUG, debug) \
  _(8, DISABLED, disabled)

typedef enum
{
#define _(n,uc,lc) VLIB_LOG_LEVEL_##uc = n,
  foreach_vlib_log_level
#undef _
} vlib_log_level_t;


vlib_log_class_t vlib_log_register_class (char *vlass, char *subclass);
u32 vlib_log_get_indent ();
void vlib_log (vlib_log_level_t level, vlib_log_class_t class, char *fmt,
	       ...);

#define vlib_log_emerg(...) vlib_log(VLIB_LOG_LEVEL_EMERG, __VA_ARGS__)
#define vlib_log_alert(...) vlib_log(VLIB_LOG_LEVEL_ALERT, __VA_ARGS__)
#define vlib_log_crit(...) vlib_log(VLIB_LOG_LEVEL_CRIT, __VA_ARGS__)
#define vlib_log_err(...) vlib_log(VLIB_LOG_LEVEL_ERR, __VA_ARGS__)
#define vlib_log_warn(...) vlib_log(VLIB_LOG_LEVEL_WARNING, __VA_ARGS__)
#define vlib_log_notice(...) vlib_log(VLIB_LOG_LEVEL_NOTICE, __VA_ARGS__)
#define vlib_log_info(...) vlib_log(VLIB_LOG_LEVEL_INFO, __VA_ARGS__)
#define vlib_log_debug(...) vlib_log(VLIB_LOG_LEVEL_DEBUG, __VA_ARGS__)

#endif /* included_vlib_log_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
