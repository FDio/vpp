#!/usr/bin/env python3
#
# Copyright (c) 2017 Pantheon Technologies, s.r.o.
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
#

from abc import ABCMeta, abstractmethod, abstractproperty
from vapi_parse_json import JsonParser, Struct, Parameter, Message, StructType, Type
from itertools import chain
from typing import Iterable, List

import logging
import sys

logger = logging.getLogger()

def _struct_name_to_class_name(name: str) -> str:
    name = name.title().replace("_", "")
    return "".join((name[0].upper(), name[1:]))

class CachedObject():
    __metaclass__ = ABCMeta

    @abstractproperty
    def jni_type(self) -> str:
        return None

    @abstractproperty
    def cache_var_name(self) -> str:
        return None

class CachedMember(CachedObject):
    def __init__(self, parent: 'GeneratedAccessibleClass') -> None:
        self._parent = parent

    def __str__(self) -> str:
        return self.parent.fqcn

    @property
    def parent(self) -> 'GeneratedAccessibleClass':
        return self._parent

    @abstractproperty
    def cache_var_name(self) -> str:
        return self.parent.cache_var_name + "_"

    @abstractproperty
    def signature(self) -> str:
        return None


class CachedField(CachedMember):
    def __init__(self, parent: 'GeneratedAccessibleClass', parameter: Parameter) -> None:
        CachedMember.__init__(self, parent)
        self._parameter = parameter

    def __str__(self) -> str:
        return 'Field "%s %s" in %s' % (self._parameter.type, self.name, super().__str__())

    @property
    def name(self) -> str:
        return self._parameter.name

    @property
    def type_(self) -> Parameter:
        return self._parameter

    @property
    def jni_type(self) -> str:
        return "jfieldID"

    @property
    def cache_var_name(self) -> str:
        return "".join((super().cache_var_name, self.name, "Field"))

    @property
    def signature(self) -> str:
        # FIXME: generate a signature
        return "FIELD_SIG"


class GeneratedClass():
    def __init__(self, plugin: str, type_: Struct, subpackage: str="") -> None:
        self._plugin = plugin
        self._type_ = type_
        self._package = "io.fd.vpp.jvpp.%s%s" % (plugin, subpackage)
        self._class_name = _struct_name_to_class_name(type_.name)

    @property
    def plugin(self) -> str:
        return self._plugin;

    @property
    def type_(self) -> Struct:
        return self._type_;

    @property
    def package(self) -> str:
        return self._package

    @property
    def class_name(self) -> str:
        return self._class_name

    @property
    def fqcn(self) -> str:
        return ".".join((self.package, self._class_name))


class GeneratedAccessibleClass(GeneratedClass, CachedObject):
    # Cache:
    # - class
    # - field accessors

    # Generate:
    # - class
    # - object-to-struct
    def __init__(self, plugin: str, type_: Struct, subpackage: str="") -> None:
        GeneratedClass.__init__(self, plugin, type_, subpackage)

    @property
    def jni_type(self) -> str:
        return "jclass";

    @property
    def cache_var_name(self) -> str:
        return "".join(("jvpp", self.plugin, self.class_name, "Class"))

    @property
    def fields(self) -> List[CachedField]:
        return [CachedField(self, p) for p in self.type_.parameters if self.filter_member(p)]

    @property
    def cached_members(self) -> List[CachedMember]:
        return self.fields

    def filter_member(self, member: Parameter) -> bool:
        return True


class CachedMethod(CachedMember):
    def __init__(self, parent: GeneratedAccessibleClass, cache_var_suffix: str, jni_name: str, signature: str) -> None:
         CachedMember.__init__(self, parent)
         self._cache_var_suffix = cache_var_suffix
         self._jni_name = jni_name
         self._signature = signature

    def __str__(self) -> str:
        return 'Method %s.%s%s' % (super().__str__(), self.jni_name, self.signature)

    @staticmethod
    def noargConstructor(parent: GeneratedAccessibleClass) -> 'CachedMethod':
        return CachedMethod(parent, "NoargCtor", "<init>", "()V")

    @property
    def jni_type(self) -> str:
        return "jmethodID"

    @property
    def cache_var_name(self) -> str:
        return "".join((super().cache_var_name, self._cache_var_suffix))

    @property
    def jni_name(self) -> str:
        return self._jni_name

    @property
    def signature(self) -> str:
        return self._signature


class GeneratedInstantiableClass(GeneratedAccessibleClass):
    # Cache:
    # - class
    # - no-op constructor
    # - field accessors

    # Generate:
    # - class
    # - object-to-struct
    # - struct-to-object
    def __init__(self, plugin: str, type_: Struct, subpackage: str="") -> None:
        GeneratedAccessibleClass.__init__(self, plugin, type_, subpackage)

    @property
    def noarg_ctor(self) -> CachedMethod:
        return CachedMethod.noargConstructor(self)

    @property
    def cached_members(self) -> List[CachedMember]:
        return [self.noarg_ctor, *super().cached_members]

#
#
# Semantic meaning of a generated class, used to implement an RPC
# primitive.
#
# - it is either a reusable structure, TypeClass, or,
# - it is an RPC request, RequestClass, or
# - it is an RPC response, ReplyClass
#
# FIXME: package suffix should really be '.msg'
#

class MessageClass:
    __metaclass__ = ABCMeta

    def __init__(self, type_: Message) -> None:
        if (type_.header != None):
            self._header_fields = type_.header.field_names
        else:
            self._header_fields = [ ]
        self._crc = type_.crc

    @property
    def crc(self) -> str:
        return self._crc

    def is_header_member(self, member: Parameter) -> bool:
        return member.name in self._header_fields


class ReplyClass(GeneratedInstantiableClass, MessageClass):
    def __init__(self, plugin: str, type_: Message) -> None:
        MessageClass.__init__(self, type_)
        GeneratedInstantiableClass.__init__(self, plugin, type_, ".dto")

    def filter_member(self, member: Parameter) -> bool:
        return not self.is_header_member(member)

class RequestClass(GeneratedAccessibleClass, MessageClass):
    def __init__(self, plugin: str, type_: Message) -> None:
        MessageClass.__init__(self, type_)
        GeneratedAccessibleClass.__init__(self, plugin, type_, ".dto")

    def filter_member(self, member: Parameter) -> bool:
        return not self.is_header_member(member)

class TypeClass(GeneratedInstantiableClass):
    def __init__(self, plugin: str, type_: Type) -> None:
        GeneratedInstantiableClass.__init__(self, plugin, type_, ".types")


class GeneratedInterface(GeneratedClass):
    pass

#
#
# Java/JNI bridge classes.
#
# PluginServiceInterface serves as low-level JNI library API contract
# PluginServiceNativeImpl serves as the implementation bootstrap and
#                         Java-resistant guard.
#
# WARNING: Users should not be using these classes directly
# FIXME: These classes should not be public, as the only surface exposed
#        to Java should be a static factory bootstrap entry point,
#        resulting in a 'JNI initialized' service factory. That factory
#        should then provide various facade APIs to end users.
#
#
class PluginServiceInterface(GeneratedInterface):
    # FIXME: JVppAcl.java
    pass

class PluginServiceNativeImpl(GeneratedClass):
    # FIXME: JVppAccImpl.java
    pass


#
#
# Callback-driven end-user interface classes.
#
#
class ReplyCallbackInterface(GeneratedInterface):
    # FIXME: AclAddReplaceCallback
    # should take a RequestClass and a ReplyClass
    pass

class GlobalCallbackInterface(GeneratedInterface):
    # FIXME: JVppAclGlobalCallback
    # should take a list of ReplyCallbackInterface
    pass


#
#
# Interface definition-level model of a single plugin.
#
#
class PluginModel:
    def __init__(self, name: str, context: JsonParser) -> None:
        context.validate_json_data()
        self._name = name

        self._types = dict((t.name, TypeClass(name, t)) for t in context.types.values() if isinstance(t, StructType))
        self._replies = [ ]
        self._requests = [ ]
        for m in context.messages.values():
            if m.is_reply_only():
                self._replies.append(ReplyClass(name, m))
            else:
                self._requests.append(RequestClass(name, m))

    @staticmethod
    def forJsonFile(name: str, filename: str) -> 'PluginModel':
        ctx = JsonParser("", logger, "")
        ctx.parse_json_file(filename)
        return PluginModel(name, ctx)

    @property
    def name(self) -> str:
        return self._name;

    @property
    def types(self) -> Iterable[TypeClass]:
        return self._types.values();

    @property
    def requests(self) -> List[RequestClass]:
        return self._requests;

    @property
    def replies(self) -> List[ReplyClass]:
        return self._replies;

    def find_class(self, name: str) -> TypeClass:
        return self._types[name]

