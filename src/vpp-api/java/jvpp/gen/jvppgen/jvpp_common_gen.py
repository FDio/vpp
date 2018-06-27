#!/usr/bin/env python2
#
# Copyright (c) 2018 Cisco and/or its affiliates.
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
from string import Template

from jvpp_model import is_array


def generate_fields(fields, access_modifier="public"):
    return "\n".join(_FIELD_TEMPLATE
                     .substitute(access_modifier=access_modifier, type=f.type.java_name_fqn, name=f.java_name)
                     for f in fields)

_FIELD_TEMPLATE = Template("""    ${access_modifier} ${type} ${name};""")


def generate_hash_code(fields):
    if len(fields) == 1 and is_array(fields[0]):
        return _HASH_CODE_SINGLE_ARRAY_TEMPLATE.substitute(array_field=fields[0].java_name)
    return _HASH_CODE_TEMPLATE.substitute(fields=", ".join(f.java_name for f in fields))

_HASH_CODE_TEMPLATE = Template("""
    @Override
    @io.fd.vpp.jvpp.coverity.SuppressFBWarnings("UWF_UNWRITTEN_PUBLIC_OR_PROTECTED_FIELD")
    public int hashCode() {
        return java.util.Objects.hash($fields);
    }""")

_HASH_CODE_SINGLE_ARRAY_TEMPLATE = Template("""
    @Override
    @io.fd.vpp.jvpp.coverity.SuppressFBWarnings("UWF_UNWRITTEN_PUBLIC_OR_PROTECTED_FIELD")
    public int hashCode() {
        return java.util.Arrays.hashCode($array_field);
    }""")


def generate_equals(class_name, fields):
    comparisons = []
    for f in fields:
        if is_array(f):
            comparisons.append(_EQUALS_ARRAY_FIELD_TEMPLATE.substitute(field_name=f.java_name))
        else:
            comparisons.append(_EQUALS_FIELD_TEMPLATE.substitute(field_name=f.java_name))

    if comparisons:
        comparisons.insert(0, _EQUALS_OTHER_TEMPLATE.substitute(cls_name=class_name))
    return _EQUALS_TEMPLATE.substitute(comparisons="\n".join(comparisons))

_EQUALS_TEMPLATE = Template("""
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
$comparisons

        return true;
    }""")

_EQUALS_OTHER_TEMPLATE = Template("""
        final $cls_name other = ($cls_name) o;
""")

_EQUALS_FIELD_TEMPLATE = Template("""        if (!java.util.Objects.equals(this.$field_name, other.$field_name)) {
            return false;
        }""")

_EQUALS_ARRAY_FIELD_TEMPLATE = Template("""        if (!java.util.Arrays.equals(this.$field_name, other.$field_name)) {
            return false;
        }""")


def generate_to_string(class_name, fields):
    to_string = []
    for f in fields:
        if is_array(f):
            to_string.append(_TO_STRING_ARRAY_FIELD_TEMPLATE.substitute(field_name=f.java_name))
        else:
            to_string.append(_TO_STRING_FIELD_TEMPLATE.substitute(field_name=f.java_name))

    to_string_fields = " \"}\";"
    if to_string:
        to_string_fields = " + \", \" +\n".join(to_string) + " + \"}\";"

    return _TO_STRING_TEMPLATE.substitute(
        class_name=class_name,
        to_string_fields=to_string_fields
    )

_TO_STRING_TEMPLATE = Template("""
    @Override
    public String toString() {
        return "$class_name{" +
$to_string_fields
    }""")

_TO_STRING_FIELD_TEMPLATE = Template("""                \"$field_name=\" + $field_name""")

_TO_STRING_ARRAY_FIELD_TEMPLATE = Template(
    """                \"$field_name=\" + java.util.Arrays.toString($field_name)""")
