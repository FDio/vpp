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

import ExpressionConverter
from InputFormat import *


class NodeField:
    def __init__(self):
        self.DefaultValue = None
        self.IsReserved = None
        self.IsReadonly = None
        self.IsAutoIncrease = None
        self.IsIncreaseLength = None
        self.Optional = None
        self.VariableSize = None

    def Create(token):
        if token == None:
            return None

        field = NodeField()

        if token["name"] == None:
            return None
        if token["size"] == None:
            return None

        # name
        field.Name = token["name"]

        if field.Name == "reserved":
            field.IsReserved = True

        inputFormat = InputFormat.bytearray
        res, u16 = ExpressionConverter.ToNum(token["size"])

        # size
        if res:
            field.Size = u16
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
            field.Size = 0
            field.VariableSize = token["size"]

        if "format" in token and token["format"] != None:
            inputFormat = InputFormat[token["format"]]

        field.Format = inputFormat

        if "default" in token and token["default"] != None:
            field.DefaultValue = token["default"]
            ret, _ = ExpressionConverter.Verify(field.Format, field.DefaultValue)
            if not ret:
                return None

        if "readonly" in token and token["readonly"] == "true" or field.IsReserved:
            field.IsReadonly = True
        if "autoincrease" in token and token["autoincrease"] == "true":
            field.IsAutoIncrease = True
            field.IsReadonly = True
        if "increaselength" in token and token["increaselength"] == "true":
            field.IsIncreaseLength = True
        if "optional" in token:
            field.Optional = token["optional"]

        return field
