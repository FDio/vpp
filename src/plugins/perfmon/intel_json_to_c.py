#!/usr/bin/env python3

import json, argparse

p = argparse.ArgumentParser()

p.add_argument('-i', '--input', action="store",
               help="input JSON file name", required = True)

p.add_argument('-o', '--output', action="store",
               help="output C file name", required = True)

p.add_argument('-m', '--model', action="append",
               help="CPU model in format: model[,stepping0]",
               required = True)

r = p.parse_args()

with open(r.input, 'r') as fp:
    objects = json.load(fp)

c = open(r.output, 'w')

c.write ("""
#include <perfmon/perfmon_intel.h>

static perfmon_intel_pmc_cpu_model_t cpu_model_table[] = {
""")

for v in r.model:
    if "," in v:
        (m, s)  = v.split(",")
        m = int(m, 0)
        s = int(s, 0)
        c.write ("  {}0x{:02X}, 0x{:02X}, 1{},\n".format("{", m, s, "}"))
    else:
        m = int(v, 0)
        c.write ("  {}0x{:02X}, 0x00, 0{},\n".format("{", m, "}"))
c.write ("""
};

static perfmon_intel_pmc_event_t event_table[] = {
""")

for obj in objects:
    MSRIndex = obj["MSRIndex"]
    if MSRIndex != "0":
      continue

    EventCode = obj["EventCode"]
    UMask = obj["UMask"]
    EventName = obj["EventName"].lower()
    if "," in EventCode:
        continue

    c.write ("  {\n")
    c.write ("   .event_code = {}{}{},\n".format("{", EventCode, "}"))
    c.write ("   .umask = {},\n".format(UMask))
    c.write ("   .event_name = \"{}\",\n".format(EventName))
    c.write ("   },\n")


c.write ("""  {
   .event_name = 0,
   },
};

PERFMON_REGISTER_INTEL_PMC (cpu_model_table, event_table);

""")

c.close()
