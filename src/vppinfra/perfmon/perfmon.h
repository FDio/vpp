/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#ifndef included_perfmon_perfmon_h
#define included_perfmon_perfmon_h

#include <vppinfra/cpu.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#endif

#define CLIB_PERFMON_MAX_EVENTS 7
typedef struct
{
  char *name;
  char *desc;
  u64 config[CLIB_PERFMON_MAX_EVENTS];
  u32 type;
  u8 n_events;
  format_function_t *format_fn;
  char **column_headers;
} clib_perfmon_bundle_t;

typedef struct
{
  u64 time_enabled;
  u64 time_running;
  u64 data[CLIB_PERFMON_MAX_EVENTS];
  u8 *desc;
  u32 n_ops;
  u32 group;
} clib_perfmon_capture_t;

typedef struct
{
  u8 *name;
  u32 start;
} clib_perfmon_capture_group_t;

typedef struct
{
  int group_fd;
  int *fds;
  clib_perfmon_bundle_t *bundle;
  u64 *data;
  u8 debug : 1;
  u32 n_captures;
  clib_perfmon_capture_t *captures;
  clib_perfmon_capture_group_t *capture_groups;
  f64 ref_clock;
} clib_perfmon_ctx_t;

typedef struct clib_perfmon_bundle_reg
{
  clib_perfmon_bundle_t *bundle;
  struct clib_perfmon_bundle_reg *next;
} clib_perfmon_bundle_reg_t;

typedef struct
{
  clib_perfmon_bundle_reg_t *bundle_regs;
} clib_perfmon_main_t;

extern clib_perfmon_main_t clib_perfmon_main;

static_always_inline void
clib_perfmon_ioctl (int fd, u32 req)
{
#ifdef __linux__
#ifdef __x86_64__
  asm volatile("syscall"
	       :
	       : "D"(fd), "S"(req), "a"(__NR_ioctl), "d"(PERF_IOC_FLAG_GROUP)
	       : "rcx", "r11" /* registers modified by kernel */);
#else
  ioctl (fd, req, PERF_IOC_FLAG_GROUP);
#endif
#endif /* linux */
}

clib_error_t *clib_perfmon_init_by_bundle_name (clib_perfmon_ctx_t *ctx,
						char *fmt, ...);
void clib_perfmon_free (clib_perfmon_ctx_t *ctx);
void clib_perfmon_warmup (clib_perfmon_ctx_t *ctx);
void clib_perfmon_clear (clib_perfmon_ctx_t *ctx);
u64 *clib_perfmon_capture (clib_perfmon_ctx_t *ctx, u32 n_ops, char *fmt, ...);
void clib_perfmon_capture_group (clib_perfmon_ctx_t *ctx, char *fmt, ...);
format_function_t format_perfmon_bundle;

#ifdef __linux__
static_always_inline void
clib_perfmon_reset (clib_perfmon_ctx_t *ctx)
{
  clib_perfmon_ioctl (ctx->group_fd, PERF_EVENT_IOC_RESET);
}
static_always_inline void
clib_perfmon_enable (clib_perfmon_ctx_t *ctx)
{
  clib_perfmon_ioctl (ctx->group_fd, PERF_EVENT_IOC_ENABLE);
}
static_always_inline void
clib_perfmon_disable (clib_perfmon_ctx_t *ctx)
{
  clib_perfmon_ioctl (ctx->group_fd, PERF_EVENT_IOC_DISABLE);
}
#elif __FreeBSD__
static_always_inline void
clib_perfmon_reset (clib_perfmon_ctx_t *ctx)
{
  /* TODO: Implement for FreeBSD */
}
static_always_inline void
clib_perfmon_enable (clib_perfmon_ctx_t *ctx)
{
  /* TODO: Implement for FreeBSD */
}
static_always_inline void
clib_perfmon_disable (clib_perfmon_ctx_t *ctx)
{
  /* TODO: Implement for FreeBSD */
}
#endif /* linux */

#define CLIB_PERFMON_BUNDLE(x)                                                \
  static clib_perfmon_bundle_reg_t clib_perfmon_bundle_reg_##x;               \
  static clib_perfmon_bundle_t clib_perfmon_bundle_##x;                       \
  static void __clib_constructor clib_perfmon_bundle_reg_fn_##x (void)        \
  {                                                                           \
    clib_perfmon_bundle_reg_##x.bundle = &clib_perfmon_bundle_##x;            \
    clib_perfmon_bundle_reg_##x.next = clib_perfmon_main.bundle_regs;         \
    clib_perfmon_main.bundle_regs = &clib_perfmon_bundle_reg_##x;             \
  }                                                                           \
  static clib_perfmon_bundle_t clib_perfmon_bundle_##x

#endif
