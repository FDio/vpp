from Path import *
from ParseGraph import *
import re
import os
import json

parsegraph_path = os.getcwd() + "/src/plugins/packetforge/base/parsegraph"

def Forge(pattern, file_flag):
    result = GetPath(pattern, file_flag)
    if (result == None):
        return '', ''

    spec, mask = GetBinary(result.ToJSON())
    return spec, mask

def GetPath(pattern, file_flag):
    pg = ParseGraph.Create(parsegraph_path)
    if (pg == None):
        print("error: create parsegraph failed")
        return None

    if (not file_flag):
        token = ParsePattern(pattern)
        if (token == None):
            return None
    else:
        if (not os.path.exists(pattern)):
            print("error: file not exist '%s' " % (pattern))
            return
        f = open(pattern, 'r', encoding='utf-8')
        token = json.load(f)

    path = Path.Create(token)
    if (path == None):
        print("error: path not exit")
        return None

    result = pg.Forge(path)
    if (result == None):
        print("error: result not available")
        return None
    
    return result

def GetBinary(flow_info):
    spec = ''.join(flow_info["Packet"])
    mask = ''.join(flow_info["Mask"])
    return spec, mask

def ParseFields(item):
    # get protocol name
    prot = item.split('(')[0]
    stack = {"header": prot}
    # get fields contents
    fields = re.findall(r'[(](.*?)[)]', item)
    if (not fields):
        print("error: invalid pattern")
        return None
    if (fields == ['']):
        return stack
    stack.update({"fields": []})
    return ParseStack(stack, fields[0].split(','))

def GetMask(item):
    if ("format" in item):
        format = item["format"]
        if (format == "mac"):
            mask = "ff.ff.ff.ff.ff.ff"
        elif (format == "ipv4"):
            mask = "255.255.255.255"
        elif (format == "ipv6"):
            mask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        return mask
    if ("size" in item):
        mask = str((1 << int(item["size"])) - 1)
    else:
        print("mask error")
    return mask

# parse protocol headers and its fields. Available fields are defined in corresponding nodes.
def ParseStack(stack, fields):
    prot = stack["header"]
    node_path = parsegraph_path + "/nodes/" + prot + ".json"
    if (not os.path.exists(node_path)):
        print("error file not exist '%s' " % (node_path))
        return None
    f = open(node_path, 'r', encoding='utf-8')
    nodeinfo = json.load(f)
    for field in fields:
        fld_name = field.split('=')[0].strip()
        fld_value = field.split('=')[-1].strip() if (len(field.split('=')) >= 2) else None
        for item in nodeinfo["layout"]:
            if fld_name == item["name"]:
                mask = GetMask(item)
                stack["fields"].append({"name": fld_name, "value": fld_value, "mask": mask})
                break
        if (not stack["fields"]):
            print("warning: invalid field '%s'" % (fld_name))
            return None

    return stack

def ParsePattern(pattern):
    # create json template
    json_tmp = {"type": "path", "stack": []}

    items = pattern.split("/")
    for item in items:
        stack = ParseFields(item)
        if (stack == None):
            return None
        json_tmp["stack"].append(stack)

    return json_tmp
