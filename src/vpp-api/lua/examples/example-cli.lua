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

vpp = require "vpp-lapi"

root_dir = "/home/ubuntu/vpp"
pneum_path = root_dir .. "/build-root/install-vpp_debug-native/vpp-api/lib64/libpneum.so"

vpp:init({ pneum_path = pneum_path })

vpp:json_api(root_dir .. "/build-root/install-vpp_debug-native/vpp/vpp-api/vpe.api.json")

vpp:connect("aytest")

-- api calls
reply = vpp:api_call("show_version")
print("Version: ", reply[1].version)
print(vpp.hex_dump(reply[1].version))
print(vpp.dump(reply))
print("---")


reply = vpp:api_call("cli_inband", { cmd = "show vers" }) 
print(vpp.dump(reply))
print("---")


vpp:disconnect()


