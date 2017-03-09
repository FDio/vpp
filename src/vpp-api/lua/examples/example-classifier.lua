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
local bit = require("bit")

root_dir = "/home/ubuntu/vpp"
pneum_path = root_dir .. "/build-root/install-vpp_debug-native/vpp-api/lib64/libpneum.so"


vpp:init({ pneum_path = pneum_path })

vpp:json_api(root_dir .. "/build-root/install-vpp_debug-native/vpp/vpp-api/vpe.api.json")

vpp:connect("aytest")

-- api calls

print("Calling API to add a new classifier table")
reply = vpp:api_call("classify_add_del_table", {
  context = 43,
  memory_size = bit.lshift(2, 20),
  client_index = 42,
  is_add = 1,
  nbuckets = 32,
  skip_n_vectors = 0,
  match_n_vectors = 1,
  mask = "\255\255\255\255\255\255\255\255" .. "\255\255\255\255\255\255\255\255"
})
print(vpp.dump(reply))
print("---")


vpp:disconnect()


