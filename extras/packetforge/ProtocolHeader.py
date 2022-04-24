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

from ProtocolHeaderAttribute import *
from ProtocolHeaderField import *
from InputFormat import *
import ExpressionConverter
import copy


class ProtocolHeader:
    def __init__(self, node):
        self.fields = []
        self.attributes = []
        self.fieldDict = {}
        self.attributeDict = {}
        self.Buffer = []
        self.Mask = []

        self.node = node
        for field in self.node.fields:
            phf = ProtocolHeaderField(field.Size, field.DefaultValue, None, field)
            self.fields.append(phf)
            if field.Name != "reserved":
                self.fieldDict[field.Name] = phf

        for attr in self.node.attributes:
            pha = ProtocolHeaderAttribute(attr.Size, attr.DefaultValue, attr)
            self.attributes.append(pha)
            self.attributeDict[attr.Name] = pha

    def Name(self):
        return self.node.Name

    def Fields(self):
        return self.fields

    def Attributes(self):
        return self.attributes

    def setField(self, name, expression, auto):
        if name == "reserved":
            return False

        if name not in self.fieldDict:
            return False

        field = self.fieldDict[name]

        if field.UpdateValue(expression, auto):
            field.UpdateSize()
            return True

        return False

    def SetField(self, name, expression):
        return self.setField(name, expression, False)

    def SetFieldAuto(self, name, expression):
        return self.setField(name, expression, True)

    def SetAttribute(self, name, expression):
        if name not in self.attributeDict:
            return False
        attr = self.attributeDict[name]

        return attr.UpdateValue(expression)

    def SetMask(self, name, expression):
        if name not in self.fieldDict:
            return False
        field = self.fieldDict[name]

        return field.UpdateMask(expression)

    def resolveOptional(self, condition):
        if condition == None:
            return True

        tokens = condition.split("|")

        if len(tokens) > 1:
            result = False

            for token in tokens:
                result |= self.resolveOptional(token)

            return result

        tokens = condition.split("&")

        if len(tokens) > 1:
            result = True

            for token in tokens:
                result &= self.resolveOptional(token)

            return result

        key = None
        value = None

        if "!=" in tokens[0]:
            index = tokens[0].find("!=")
            key = tokens[0][:index].strip()
            value = tokens[0][index + 1 :].strip()
        elif "=" in tokens[0]:
            index = tokens[0].find("=")
            key = tokens[0][:index].strip()
            value = tokens[0][index + 1 :].strip()
        else:
            return False

        if key not in self.fieldDict:
            return False

        f = self.fieldDict[key]
        return ExpressionConverter.Equal(f.Value, value)

    def resolveSize(self, exp):
        shift = 0
        key = exp

        if "<<" in exp:
            offset = exp.find("<<")
            key = exp[0:offset].strip()
            shift = int(exp[offset + 2 :].strip())

        if self.fieldDict.has_key(key):
            field = self.fieldDict[key]
            _, u16 = ExpressionConverter.ToNum(field.Value)
            if u16:
                return u16 << shift
            else:
                return 0

        if self.attributeDict.has_key(key):
            attr = self.attributeDict[key]
            _, u16 = ExpressionConverter.ToNum(attr.Value)
            if u16:
                return u16 << shift
            else:
                return 0

        return 0

    def Adjust(self):
        autoIncreases = []
        increaseHeaders = []

        self.resolveAllSize()

        for phf in self.fields:
            if phf.Field.IsAutoIncrease:
                autoIncreases.append(phf)
            if phf.Field.IsIncreaseLength and self.resolveOptional(phf.Field.Optional):
                increaseHeaders.append(phf)

        for f1 in autoIncreases:
            for f2 in increaseHeaders:
                f1.UpdateValue(
                    ExpressionConverter.IncreaseValue(f1.Value, f2.Size >> 3), True
                )

    def resolveAllSize(self):
        for phf in self.fields:
            if phf.Field.Optional != None and not self.resolveOptional(
                phf.Field.Optional
            ):
                size = 0
            else:
                if phf.Field.VariableSize != None:
                    size = self.resolveSize(phf.Field.VariableSize)
                else:
                    size = phf.Field.Size
            phf.Size = size

    def GetSize(self):
        size = 0

        for field in self.fields:
            size += field.Size

        return size >> 3

    def AppendAuto(self, size):
        for phf in self.fields:
            if not phf.Field.IsAutoIncrease:
                continue

            phf.UpdateValue(ExpressionConverter.IncreaseValue(phf.Value, size), True)

    def getField(self, name):
        if not self.fieldDict.has_key(name):
            return None
        field = self.fieldDict[name]

        return field.Value

    def getAttribute(self, name):
        if not self.attributeDict.has_key(name):
            return None

        return self.attributeDict[name].Value

    def GetValue(self, name):
        result = self.getField(name)

        if result == None:
            return self.getAttribute(name)

        return result

    def appendNum(self, big, exp, size):
        num = 0
        if exp != None:
            _, num = ExpressionConverter.ToNum(exp)
            if num == None:
                print("Invalid byte expression")
                return None

        # cut msb
        num = num & ((1 << size) - 1)
        big = big << size
        big = big | num
        return big

    def appendUInt64(self, big, exp, size):
        u64 = 0
        if exp != None:
            _, u64 = ExpressionConverter.ToNum(exp)
            if not u64:
                print("Invalid UInt32 expression")
                return False

        # cut msb
        if size < 64:
            u64 = u64 & ((1 << size) - 1)
        big = big << size
        big = big | u64
        return big

    def appendIPv4(self, big, exp):
        ipv4 = bytes(4)
        if exp != None:
            _, ipv4 = ExpressionConverter.ToIPv4Address(exp)
            if not ipv4:
                print("Inavalid IPv4 Address")
                return False

        for i in range(len(ipv4)):
            big = big << 8
            big = big | ipv4[i]

        return big

    def appendIPv6(self, big, exp):
        ipv6 = bytes(16)
        if exp != None:
            _, ipv6 = ExpressionConverter.ToIPv6Address(exp)
            if not ipv6:
                print("Inavalid IPv6 Address")
                return False

        for i in range(16):
            big = big << 8
            big = big | ipv6[i]

        return big

    def appendMAC(self, big, exp):
        mac = bytes(6)
        if exp != None:
            _, mac = ExpressionConverter.ToMacAddress(exp)
            if not mac:
                print("Inavalid MAC Address")
                return False

        for i in range(6):
            big = big << 8
            big = big | mac[i]

        return big

    def appendByteArray(self, big, exp, size):
        array = bytes(size >> 3)
        if exp != None:
            _, array = ExpressionConverter.ToByteArray(exp)
            if not array:
                print("Invalid byte array")
                return False

        for i in range(size >> 3):
            big = big << 8
            if i < len(array):
                big = big | array[i]

        return big

    def append(self, big, phf):
        bigVal = big["bigVal"]
        bigMsk = big["bigMsk"]

        if phf.Field.IsReserved:
            bigVal <<= phf.Size
            bigMsk <<= phf.Size
            big.update(bigVal=bigVal, bigMsk=bigMsk)
            return big, phf.Size

        size = phf.Size

        if (
            phf.Field.Format == InputFormat.u8
            or phf.Field.Format == InputFormat.u16
            or phf.Field.Format == InputFormat.u32
        ):
            bigVal = self.appendNum(bigVal, phf.Value, size)
            bigMsk = self.appendNum(bigMsk, phf.Mask, size)

        elif phf.Field.Format == InputFormat.u64:
            bigVal = self.appendUInt64(bigVal, phf.Value, size)
            bigMsk = self.appendUInt64(bigMsk, phf.Mask, size)

        elif phf.Field.Format == InputFormat.ipv4:
            bigVal = self.appendIPv4(bigVal, phf.Value)
            bigMsk = self.appendIPv4(bigMsk, phf.Mask)

        elif phf.Field.Format == InputFormat.ipv6:
            bigVal = self.appendIPv6(bigVal, phf.Value)
            bigMsk = self.appendIPv6(bigMsk, phf.Mask)

        elif phf.Field.Format == InputFormat.mac:
            bigVal = self.appendMAC(bigVal, phf.Value)
            bigMsk = self.appendMAC(bigMsk, phf.Mask)

        elif phf.Field.Format == InputFormat.bytearray:
            bigVal = self.appendByteArray(bigVal, phf.Value, size)
            bigMsk = self.appendByteArray(bigMsk, phf.Mask, size)

        else:
            print("Invalid input format")

        big.update(bigVal=bigVal, bigMsk=bigMsk)
        return big, size

    def Resolve(self):
        big = {"bigVal": 0, "bigMsk": 0}
        offset = 0

        for phf in self.fields:
            if phf.Size == 0:
                continue

            big, bits = self.append(big, phf)

            offset += bits

        byteList1 = []
        byteList2 = []

        bigVal = big["bigVal"]
        bigMsk = big["bigMsk"]

        while offset > 0:
            byteList1.append(bigVal & 0xFF)
            byteList2.append(bigMsk & 0xFF)
            bigVal = bigVal >> 8
            bigMsk = bigMsk >> 8
            offset -= 8

        byteList1.reverse()
        byteList2.reverse()
        buffer = copy.deepcopy(byteList1)
        mask = copy.deepcopy(byteList2)

        self.Buffer = buffer
        self.Mask = mask
