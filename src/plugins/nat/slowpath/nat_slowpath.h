#ifndef included_nat_slowpath_h
#define included_nat_slowpath_h

#include "../flowrouter/flowrouter.h"

typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  flowrouter_session_t in2out;
  flowrouter_session_t out2in;
  u32 timer;
  u32 timer_handle;
} nat_sp_session_t;

typedef struct {
  bool enabled;
  nat_slowpath_pool_t pool;
  nat_sp_session_t *sessions;
  clib_bihash_16_8_t in2out_hash;
  clib_bihash_16_8_t out2in_hash;

  u32 max_sessions;

  u32 default_timeout;
  u32 icmp_timeout;
  u32 udp_timeout;
  u32 tcp_transitory_timeout;
  u32 tcp_established_timeout;

  TWT (tw_timer_wheel) *timers;
  clib_spinlock_t tw_lock;
  clib_rwlock_t sessions_lock;

} nat_slowpath_main_t;

#endif
