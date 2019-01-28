
#include <perfmon/perfmon_intel.h>

static perfmon_intel_pmc_cpu_model_t cpu_model_table[] = {
  {0x5C, 0x00, 0},
  {0x5F, 0x00, 0},

};

static perfmon_intel_pmc_event_t event_table[] = {
  {
   .event_name = 0,
   },
};

PERFMON_REGISTER_INTEL_PMC (cpu_model_table, event_table);

