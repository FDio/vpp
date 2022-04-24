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

from NodeField import *
from NodeAttribute import *
import json


class Node:
    def __init__(self):
        self.fields = []
        self.attributes = []
        self.attrsDict = {}
        self.fieldDict = {}

    def Create(jsonfile):
        f = open(jsonfile, "r", encoding="utf-8")
        token = json.load(f)

        if token == None:
            return None

        if token["type"] != "node":
            return None

        node = Node()

        name = token["name"]
        if name == None:
            return None

        node.Name = name

        if token["layout"] == None:
            return None

        for ft in token["layout"]:
            field = NodeField.Create(ft)
            if field == None:
                return None
            node.fields.append(field)
            if not field.IsReserved:
                node.fieldDict[field.Name] = field

        if "attributes" in token and token["attributes"] != None:
            for ft in token["attributes"]:
                attr = NodeAttribute.Create(ft)
                node.attrsDict[attr.Name] = attr
                node.attributes.append(attr)

        node.JSON = jsonfile
        return node
