#ifndef __included_profile_h__
#define __included_profile_h__

#include <float.h>

#define PROFILE_DECL(P, desc, _snapshot_secs)          \
  static int P (iterations) = 0;                       \
  static const char *P (name) = desc;                  \
  static const int P (snapshot_secs) = _snapshot_secs; \
  static u64 P (ticks_min)[_snapshot_secs] = {~0};     \
  static u64 P (ticks_max)[_snapshot_secs] = {0};      \
  static u64 P (ticks)[_snapshot_secs] = {0};          \
  static u64 P (events)[_snapshot_secs] = {0};         \
  static int P (last_index) = 0;                       \
  static u64 P (last_ticks) = 0;                       \
  static u64 P (ticks_per_second) = 0;                 \
  static u64 P (global_events) = 0;                    \
  static u64 P (global_ticks) = 0;                     \
  static u64 P (global_ticks_min) = ~0;                \
  static u64 P (global_ticks_max) = 0;                 \
  static f64 P (global_ticks_min_avg) = FLT_MAX;       \
  static f64 P (global_ticks_max_avg) = FLT_MIN;

#define PROFILE_START(P) u64 P (ticks_start) = clib_cpu_time_now ();

#define SEC_IN_USEC (1.00 / 1000000)
#define PROFILE_END(P)                                                      \
  u64 P (ticks_now) = clib_cpu_time_now ();                                 \
  u64 P (ticks_taken) = P (ticks_now) - P (ticks_start);                    \
  int P (index) = (u64)now % P (snapshot_secs);                             \
  if (P (index) != P (last_index))                                          \
    {                                                                       \
      P (ticks_per_second) = P (ticks_now) - P (last_ticks);                \
      static u8 *P (s) = NULL;                                              \
      int P (secs) = P (snapshot_secs);                                     \
      P (s) =                                                               \
          format (P (s), "%s stats @%llu ticks per sec. iterations: %d\n",  \
                  P (name), P (ticks_per_second), P (iterations));          \
      P (s) = format (                                                      \
          P (s),                                                            \
          "[---] events: %10llu ticks total: %10llu(%08.2fus), "            \
          "min: %10llu(%08.4fus), max: %10llu(%08.4fus), min avg: "         \
          "%.2f(%08.4fus), max avg: %.2f(%08.4f)\n",                        \
          P (global_events), P (global_ticks),                              \
          P (global_ticks) / (SEC_IN_USEC * P (ticks_per_second)),          \
          P (global_ticks_min),                                             \
          P (global_ticks_min) / (SEC_IN_USEC * P (ticks_per_second)),      \
          P (global_ticks_max),                                             \
          P (global_ticks_max) / (SEC_IN_USEC * P (ticks_per_second)),      \
          P (global_ticks_min_avg),                                         \
          P (global_ticks_min_avg) / (SEC_IN_USEC * P (ticks_per_second)),  \
          P (global_ticks_max_avg),                                         \
          P (global_ticks_max_avg) / (SEC_IN_USEC * P (ticks_per_second))); \
      for (int i = P (last_index) + 1; i < P (snapshot_secs); ++i)          \
        {                                                                   \
          if (P (events)[i])                                                \
            {                                                               \
              P (s) = format (                                              \
                  P (s),                                                    \
                  "[-%02d] events: %10llu ticks total: %10llu(%08.2fus), "  \
                  "min: %10llu(%08.4fus), max: %10llu(%08.4fus), avg: "     \
                  "%10llu(%08.4fus), max/min: %.2f\n",                      \
                  P (secs), P (events)[i], P (ticks)[i],                    \
                  P (ticks)[i] / (SEC_IN_USEC * P (ticks_per_second)),      \
                  P (ticks_min)[i],                                         \
                  P (ticks_min)[i] / (SEC_IN_USEC * P (ticks_per_second)),  \
                  P (ticks_max)[i],                                         \
                  P (ticks_max)[i] / (SEC_IN_USEC * P (ticks_per_second)),  \
                  P (ticks)[i] / P (events)[i],                             \
                  (P (ticks)[i] / P (events)[i]) /                          \
                      (SEC_IN_USEC * P (ticks_per_second)),                 \
                  (f64)P (ticks_max)[i] / P (ticks_min)[i]);                \
            }                                                               \
          --P (secs);                                                       \
        }                                                                   \
      for (int i = 0; i <= P (last_index); ++i)                             \
        {                                                                   \
          if (P (events)[i])                                                \
            {                                                               \
              P (s) = format (                                              \
                  P (s),                                                    \
                  "[-%02d] events: %10llu ticks total: %10llu(%08.2fus), "  \
                  "min: %10llu(%08.4fus), max: %10llu(%08.4fus), avg: "     \
                  "%10llu(%08.4fus), max/min: %.2f\n",                      \
                  P (secs), P (events)[i], P (ticks)[i],                    \
                  P (ticks)[i] / (SEC_IN_USEC * P (ticks_per_second)),      \
                  P (ticks_min)[i],                                         \
                  P (ticks_min)[i] / (SEC_IN_USEC * P (ticks_per_second)),  \
                  P (ticks_max)[i],                                         \
                  P (ticks_max)[i] / (SEC_IN_USEC * P (ticks_per_second)),  \
                  P (ticks)[i] / P (events)[i],                             \
                  (P (ticks)[i] / P (events)[i]) /                          \
                      (SEC_IN_USEC * P (ticks_per_second)),                 \
                  (f64)P (ticks_max)[i] / P (ticks_min)[i]);                \
            }                                                               \
          --P (secs);                                                       \
        }                                                                   \
      clib_warning ("%v", P (s));                                           \
      _vec_len (P (s)) = 0;                                                 \
      P (global_events) += P (events)[P (index)];                           \
      P (global_ticks) += P (ticks)[P (index)];                             \
      if (P (ticks_min)[P (index)])                                         \
        {                                                                   \
          P (global_ticks_min) =                                            \
              clib_min (P (global_ticks_min), P (ticks_min)[P (index)]);    \
        }                                                                   \
      P (global_ticks_max) =                                                \
          clib_max (P (global_ticks_max), P (ticks_max)[P (index)]);        \
      if (P (events)[P (index)])                                            \
        {                                                                   \
          P (global_ticks_min_avg) =                                        \
              clib_min (P (global_ticks_min_avg),                           \
                        (P (ticks)[P (index)] / P (events)[P (index)]));    \
          P (global_ticks_max_avg) =                                        \
              clib_max (P (global_ticks_max_avg),                           \
                        (P (ticks)[P (index)] / P (events)[P (index)]));    \
        }                                                                   \
      P (ticks_min)[P (index)] = ~0;                                        \
      P (ticks_max)[P (index)] = 0;                                         \
      P (ticks)[P (index)] = 0;                                             \
      P (events)[P (index)] = 0;                                            \
      P (last_ticks) = P (ticks_now);                                       \
      ++P (iterations);                                                     \
    }                                                                       \
  P (ticks_min)                                                             \
  [P (index)] = clib_min (P (ticks_taken), P (ticks_min)[P (index)]);       \
  P (ticks_max)                                                             \
  [P (index)] = clib_max (P (ticks_taken), P (ticks_max)[P (index)]);       \
  P (ticks)[P (index)] += P (ticks_taken);                                  \
  ++P (events)[P (index)];                                                  \
  P (last_index) = P (index);

#endif /* __included_profile_h__ */
