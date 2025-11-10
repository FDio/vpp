/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#pragma once

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vlib/log.h>

#include <vlua/vlua.h>

extern vlib_log_class_registration_t lua_main_log;
extern u8 *vlua_config_stub_path;
extern u8 **vlua_config_scripts;

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (lua_main_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (lua_main_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
#define log_err(fmt, ...)                                                     \
  vlib_log_err (lua_main_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
