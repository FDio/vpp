# Copyright (c) 2022 Intel and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from vpp_papi.vpp_papi import VppEnum
from ParseGraph import *
from Path import *
import json
import re
import os

parsegraph_path = os.getcwd() + "/parsegraph"


def Forge(pattern, actions, file_flag):
    pg = ParseGraph.Create(parsegraph_path)
    if pg == None:
        print("error: create parsegraph failed")
        return None

    if not file_flag:
        token = ParsePattern(pattern)
        if token == None:
            return None
    else:
        if not os.path.exists(pattern):
            print("error: file not exist '%s' " % (pattern))
            return
        f = open(pattern, "r", encoding="utf-8")
        token = json.load(f)
        if "actions" in token:
            actions = token["actions"]

    path = Path.Create(token)
    if path == None:
        print("error: path not exit")
        return None

    result = pg.Forge(path)
    if result == None:
        print("error: result not available")
        return None

    spec, mask = GetBinary(result.ToJSON())

    # create generic flow
    my_flow = {
        "type": VppEnum.vl_api_flow_type_v2_t.FLOW_TYPE_GENERIC_V2,
        "flow": {
            "generic": {
                "pattern": {"spec": bytes(spec.encode()), "mask": bytes(mask.encode())}
            }
        },
    }

    # update actions entry
    my_flow = GetAction(actions, my_flow)

    return my_flow


def GetAction(actions, flow):
    if len(actions.split(" ")) > 1:
        type = actions.split(" ")[0]
    else:
        type = actions

    if type == "mark":
        flow.update(
            {
                "actions": VppEnum.vl_api_flow_action_v2_t.FLOW_ACTION_MARK_V2,
                "mark_flow_id": int(actions.split(" ")[1]),
            }
        )
    elif type == "next-node":
        flow.update(
            {
                "actions": VppEnum.vl_api_flow_action_v2_t.FLOW_ACTION_REDIRECT_TO_NODE_V2,
                "redirect_node_index": int(actions.split(" ")[1]),
            }
        )
    elif type == "buffer-advance":
        flow.update(
            {
                "actions": VppEnum.vl_api_flow_action_v2_t.FLOW_ACTION_BUFFER_ADVANCE_V2,
                "buffer_advance": int(actions.split(" ")[1]),
            }
        )
    elif type == "redirect-to-queue":
        flow.update(
            {
                "actions": VppEnum.vl_api_flow_action_v2_t.FLOW_ACTION_REDIRECT_TO_QUEUE_V2,
                "redirect_queue": int(actions.split(" ")[1]),
            }
        )
    elif type == "rss":
        flow.update({"actions": VppEnum.vl_api_flow_action_v2_t.FLOW_ACTION_RSS_V2})
    elif type == "rss-queues":
        queue_end = int(actions.split(" ")[-1])
        queue_start = int(actions.split(" ")[-3])
        flow.update(
            {
                "actions": VppEnum.vl_api_flow_action_v2_t.FLOW_ACTION_RSS_V2,
                "queue_index": queue_start,
                "queue_num": queue_end - queue_start + 1,
            }
        )
    elif type == "drop":
        flow.update({"actions": VppEnum.vl_api_flow_action_v2_t.FLOW_ACTION_DROP_V2})

    return flow


def GetBinary(flow_info):
    spec = "".join(flow_info["Packet"])
    mask = "".join(flow_info["Mask"])
    return spec, mask


def ParseFields(item):
    # get protocol name
    prot = item.split("(")[0]
    stack = {"header": prot}
    # get fields contents
    fields = re.findall(r"[(](.*?)[)]", item)
    if not fields:
        print("error: invalid pattern")
        return None
    if fields == [""]:
        return stack
    stack.update({"fields": []})
    return ParseStack(stack, fields[0].split(","))


def GetMask(item):
    if "format" in item:
        format = item["format"]
        if format == "mac":
            mask = "ff:ff:ff:ff:ff:ff"
        elif format == "ipv4":
            mask = "255.255.255.255"
        elif format == "ipv6":
            mask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        return mask
    if "size" in item:
        mask = str((1 << int(item["size"])) - 1)
    else:
        print("mask error")
    return mask


# parse protocol headers and its fields. Available fields are defined in corresponding nodes.
def ParseStack(stack, fields):
    prot = stack["header"]
    node_path = parsegraph_path + "/nodes/" + prot + ".json"
    if not os.path.exists(node_path):
        print("error file not exist '%s' " % (node_path))
        return None
    f = open(node_path, "r", encoding="utf-8")
    nodeinfo = json.load(f)
    for field in fields:
        fld_name = field.split("=")[0].strip()
        fld_value = (
            field.split("=")[-1].strip() if (len(field.split("=")) >= 2) else None
        )
        for item in nodeinfo["layout"]:
            if fld_name == item["name"]:
                mask = GetMask(item)
                stack["fields"].append(
                    {"name": fld_name, "value": fld_value, "mask": mask}
                )
                break
        if not stack["fields"]:
            print("warning: invalid field '%s'" % (fld_name))
            return None

    return stack


def ParsePattern(pattern):
    # create json template
    json_tmp = {"type": "path", "stack": []}

    items = pattern.split("/")
    for item in items:
        stack = ParseFields(item)
        if stack == None:
            return None
        json_tmp["stack"].append(stack)

    return json_tmp
