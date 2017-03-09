--[[
/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
]]

local vpp = require "vpp-lapi"

local ffi = require "ffi"

ffi.cdef([[
   struct timespec {
               long tv_sec;        /* seconds */
               long tv_nsec;       /* nanoseconds */
           };

   int clock_gettime(int clk_id, struct timespec *tp);
]])


local time_cache = ffi.new("struct timespec[1]")
local time_cache_1 = time_cache[0]
function get_ns()
  ffi.C.clock_gettime(0, time_cache)
  return time_cache_1.tv_nsec + 1000000000 * time_cache_1.tv_sec
end

function do_bench()
  local cycle_start = get_ns()
  local n_iterations =  10000
  local count = 1
  for i = 1,n_iterations do
    -- print(i)
    vpp:api_call("show_version")
    count = count + 1
    -- print(i, "done")
  end
  cycle_end = get_ns()
  local tps = n_iterations*1000000000LL/(cycle_end - cycle_start)
  print (tostring(count) .. " iterations, average speed " .. tostring(tps) .. " per second")
  return tps
end

root_dir = "/home/ubuntu/vpp"
pneum_path = root_dir .. "/build-root/install-vpp_debug-native/vpp-api/lib64/libpneum.so"
vpp:init({ pneum_path = pneum_path })
vpp:json_api(root_dir .. "/build-root/install-vpp_debug-native/vpp/vpp-api/vpe.api.json")

vpp:connect("lua-bench")
local n_tests = 10
local tps_acc = 0LL
for i=1,n_tests do
  tps_acc = tps_acc + do_bench()
end
print("Average tps across the tests: " .. tostring(tps_acc/n_tests))

vpp:disconnect()


