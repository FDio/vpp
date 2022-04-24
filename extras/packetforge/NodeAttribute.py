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

from InputFormat import *
import ExpressionConverter


class NodeAttribute:
    def __init__(self):
        self.DefaultValue = None

    def Create(token):
        if token == None:
            return None

        attr = NodeAttribute()

        if token["name"] == None:
            return None
        if token["size"] == None:
            return None

        # name
        attr.Name = token["name"]

        inputFormat = InputFormat.bytearray
        res, u16 = ExpressionConverter.ToNum(token["size"])

        # size
        if res:
            attr.Size = u16
            if u16 <= 8:
                inputFormat = InputFormat.u8
            elif u16 <= 16:
                inputFormat = InputFormat.u16
            elif u16 <= 32:
                inputFormat = InputFormat.u32
            elif u16 <= 64:
                inputFormat = InputFormat.u64
            else:
                inputFormat = InputFormat.bytearray
        else:
            return None

        if "format" in token and token["format"] != None:
            inputFormat = InputFormat[token["format"]]

        attr.Format = inputFormat
        if "default" in token and token["default"] != None:
            attr.DefaultValue = token["default"]
            ret, _ = ExpressionConverter.Verify(attr.Format, attr.DefaultValue)
            if not ret:
                return None

        return attr
