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

from InputFormat import InputFormat


def ByteArrayToString(data):
    if len(data) == 0:
        return ""

    sb = []

    for i in range(len(data) - 1):
        sb.append("%02x" % data[i])

    sb.append("%02x" % data[len(data) - 1])

    return sb


def ToNum(exp):
    if exp == None:
        return True, None

    exp = exp.strip()

    if exp.startswith("0x"):
        out = int(exp, 16)
    else:
        try:
            out = int(exp)
        except:
            return False, None

    return True, out


def ToIPv4Address(exp):
    ipv4 = [0] * 4

    exp = exp.strip()
    tokens = exp.split(".")

    if len(tokens) != 4:
        return False, bytes(4)

    for i in range(4):
        u8 = int(tokens[i])
        if u8 == None:
            return False, bytes(4)

        ipv4[i] = u8

    return True, bytes(ipv4)


def ToIPv6Address(exp):
    ipv6 = [0] * 16

    exp = exp.strip()
    tokens = exp.split(":")

    if len(tokens) != 8:
        return False, bytes(16)

    for i in range(8):
        u16 = int(tokens[i], 16)
        if u16 == None:
            return False, bytes(16)

        ipv6[i * 2] = u16 >> 8
        ipv6[i * 2 + 1] = u16 & 0xFF

    return True, bytes(ipv6)


def ToMacAddress(exp):
    mac = [0] * 6

    exp = exp.strip()
    tokens = exp.split(":")

    if len(tokens) != 6:
        return False, bytes(6)

    for i in range(6):
        u8 = int(tokens[i], 16)
        if u8 == None:
            return False, bytes(6)

        mac[i] = u8

    return True, bytes(mac)


def ToByteArray(exp):
    exp = exp.strip()
    tokens = exp.split(",")

    tmp = [] * len(tokens)

    for i in range(len(tokens)):
        _, num = ToNum(tokens[i])
        if num == 0:
            return False, bytes(len(tokens))

        tmp[i] = ToNum(tokens[i])

    return True, bytes(tmp)


def Verify(format, expression):
    if (
        format == InputFormat.u8
        or format == InputFormat.u16
        or format == InputFormat.u32
        or format == InputFormat.u64
    ):
        return ToNum(expression)
    elif format == InputFormat.ipv4:
        return ToIPv4Address(expression)
    elif format == InputFormat.ipv6:
        return ToIPv6Address(expression)
    elif format == InputFormat.mac:
        return ToMacAddress(expression)
    elif format == InputFormat.bytearray:
        return ToByteArray(expression)
    else:
        return False, 0


def IncreaseValue(expression, size):
    if expression == None:
        return str(size)

    _, num = ToNum(expression)
    return str(num + size)


def Equal(exp, val):
    if exp == None:
        num_1 = 0
    else:
        _, num_1 = ToNum(exp)
        if not num_1:
            return False

    _, num_2 = ToNum(val)
    if not num_2:
        return False

    return num_1 == num_2
