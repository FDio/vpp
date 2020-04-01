#ifndef __included_benchmark_h__
#define __included_benchmark_h__

#define BENCHMARK_DECL(B, desc, _snapshot_secs)        \
  static const char *B (name) = desc;                  \
  static const int B (snapshot_secs) = _snapshot_secs; \
  static u64 B (ticks_min)[_snapshot_secs] = {~0};     \
  static u64 B (ticks_max)[_snapshot_secs] = {0};      \
  static u64 B (ticks)[_snapshot_secs] = {0};          \
  static u64 B (events)[_snapshot_secs] = {0};         \
  static int B (last_index) = 0;                       \
  static u64 B (last_ticks) = 0;                       \
  static u64 B (ticks_per_second) = 0;

#define BENCHMARK_START(B) u64 B (ticks_start) = clib_cpu_time_now ();

#define SEC_IN_USEC (1.00 / 1000000)
#define BENCHMARK_END(B)                                                   \
  u64 B (ticks_now) = clib_cpu_time_now ();                                \
  u64 B (ticks_taken) = B (ticks_now) - B (ticks_start);                   \
  int B (index) = (u64)now % B (snapshot_secs);                            \
  B (ticks_min)                                                            \
  [B (index)] = clib_min (B (ticks_taken), B (ticks_min)[B (index)]);      \
  B (ticks_max)                                                            \
  [B (index)] = clib_max (B (ticks_taken), B (ticks_max)[B (index)]);      \
  B (ticks)[B (index)] += B (ticks_taken);                                 \
  ++B (events)[B (index)];                                                 \
  if (B (index) != B (last_index))                                         \
    {                                                                      \
      B (ticks_per_second) = B (ticks_now) - B (last_ticks);               \
      static u8 *B (s) = NULL;                                             \
      int B (secs) = B (snapshot_secs);                                    \
      B (s) = format (B (s), "%s stats @%llu ticks per sec\n", B (name),   \
                      B (ticks_per_second));                               \
      for (int i = B (last_index) + 1; i < B (snapshot_secs); ++i)         \
        {                                                                  \
          if (B (events)[i])                                               \
            {                                                              \
              B (s) = format (                                             \
                  B (s),                                                   \
                  "[-%02d] %10llu events total: %10llu ticks(%08.2fus), "  \
                  "min: "                                                  \
                  "%10llu(%08.4fus), max: %10llu(%08.4fus), avg: "         \
                  "%10llu(%08.4fus), max/min: %.2f\n",                     \
                  B (secs), B (events)[i], B (ticks)[i],                   \
                  B (ticks)[i] / (SEC_IN_USEC * B (ticks_per_second)),     \
                  B (ticks_min)[i],                                        \
                  B (ticks_min)[i] / (SEC_IN_USEC * B (ticks_per_second)), \
                  B (ticks_max)[i],                                        \
                  B (ticks_max)[i] / (SEC_IN_USEC * B (ticks_per_second)), \
                  B (ticks)[i] / B (events)[i],                            \
                  (B (ticks)[i] / B (events)[i]) /                         \
                      (SEC_IN_USEC * B (ticks_per_second)),                \
                  (f64)B (ticks_max)[i] / B (ticks_min)[i]);               \
            }                                                              \
          --B (secs);                                                      \
        }                                                                  \
      for (int i = 0; i <= B (last_index); ++i)                            \
        {                                                                  \
          if (B (events)[i])                                               \
            {                                                              \
              B (s) = format (                                             \
                  B (s),                                                   \
                  "[-%02d] %10llu events total: %10llu ticks(%08.2fus), "  \
                  "min: "                                                  \
                  "%10llu(%08.4fus), max: %10llu(%08.4fus), avg: "         \
                  "%10llu(%08.4fus), max/min: %.2f\n",                     \
                  B (secs), B (events)[i], B (ticks)[i],                   \
                  B (ticks)[i] / (SEC_IN_USEC * B (ticks_per_second)),     \
                  B (ticks_min)[i],                                        \
                  B (ticks_min)[i] / (SEC_IN_USEC * B (ticks_per_second)), \
                  B (ticks_max)[i],                                        \
                  B (ticks_max)[i] / (SEC_IN_USEC * B (ticks_per_second)), \
                  B (ticks)[i] / B (events)[i],                            \
                  (B (ticks)[i] / B (events)[i]) /                         \
                      (SEC_IN_USEC * B (ticks_per_second)),                \
                  (f64)B (ticks_max)[i] / B (ticks_min)[i]);               \
            }                                                              \
          --B (secs);                                                      \
        }                                                                  \
      clib_warning ("%v", B (s));                                          \
      _vec_len (B (s)) = 0;                                                \
      B (ticks_min)[B (index)] = ~0;                                       \
      B (ticks_max)[B (index)] = 0;                                        \
      B (ticks)[B (index)] = 0;                                            \
      B (events)[B (index)] = 0;                                           \
      B (last_ticks) = B (ticks_now);                                      \
    }                                                                      \
  B (last_index) = B (index);

#endif /* __included_benchmark_h__ */
