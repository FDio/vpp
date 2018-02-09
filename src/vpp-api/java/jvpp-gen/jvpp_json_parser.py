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
#

import json


def underscore_to_camelcase_upper(name):
    name = name.title().replace("_", "")
    return name[0].upper() + name[1:]


class Type(object):
    def __init__(self, name):
        self.name = name


class SimpleType(Type):
    def __init__(self, name):
        super(SimpleType, self).__init__(name)


class Class(Type):
    def __init__(self, name, crc, fields):
        super(Class, self).__init__(name)
        self.crc = crc
        self.fields = fields


class Array(Type):
    def __init__(self, name, length, length_field):
        super(Array, self).__init__(name)
        self.length = length
        self.length_field = length_field


class Field(object):
    def __init__(self, name, type):
        self.name = name
        self.type = type


class Message(object):
    def __init__(self, name, crc, fields):
        self.name = name
        self.java_name = underscore_to_camelcase_upper(name)
        self.crc = crc
        self.fields = fields

    def __str__(self):
        return "Message{name:%s, java_name:%s, crc:%s, fields:%s}" % (self.name, self.java_name, self.crc, self.fields)
        # return "[%s]" % "], [".join([str(f) for f in self.fields])

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.name == other.name and
                self.java_name == other.java_name and
                self.crc == other.crc and
                self.fields == other.fields
                )

    def __hash__(self):
        return hash(self.name, self.java_name, self.crc, self.fields)


class Event(Message):
    def __init__(self, name, crc, fields):
        super(Event, self).__init__(name, crc, fields)


class Request(Message):
    def __init__(self, name, reply, crc, fields):
        super(Request, self).__init__(name, crc, fields)
        self.reply = underscore_to_camelcase_upper(reply)

    def __str__(self):
        return "Request{name:%s, reply:%s, crc:%s, fields:%s}" % (self.name, self.reply, self.crc, self.fields)


class Reply(Message):
    def __init__(self, name, request, crc, fields):
        super(Reply, self).__init__(name, crc, fields)
        self.request = underscore_to_camelcase_upper(request)

    def __str__(self):
        return "Reply{name:%s, request:%s, crc:%s, fields:%s}" % (self.name, self.request, self.crc, self.fields)


class Dump(Message):
    def __init__(self, name, details, crc, fields):
        super(Dump, self).__init__(name, crc, fields)
        self.details = underscore_to_camelcase_upper(details)

    def __str__(self):
        return "Dump{name:%s, details:%s, crc:%s, fields:%s}" % (self.name, self.details, self.crc, self.fields)


class Details(Message):
    def __init__(self, name, dump, crc, fields):
        super(Details, self).__init__(name, crc, fields)
        self.dump = underscore_to_camelcase_upper(dump)

    def __str__(self):
        return "Details{name:%s, dump:%s, crc:%s, fields:%s}" % (self.name, self.dump, self.crc, self.fields)


BASE_PACKAGE = "io.fd.vpp.jvpp"


def _is_crc(item):
    """ Check whether the item inside message definition is just crc """
    return type(item) == dict and 'crc' in item


def _is_stream(service):
    return "stream" in service


# todo rename to json API
class JsonParser(object):
    def __init__(self, logger, json_api_files, plugin_name):
        self.logger = logger
        self.plugin_package = BASE_PACKAGE + "." + plugin_name
        logger.info("Hello")
        logger.info(json_api_files)

        self._load_json_files(json_api_files)
        # parse_types()
        self._parse_services()
        self._parse_messages()

    def _load_json_files(self, json_api_files):
        self._enums = []
        self._types = []
        _messages = []
        self._services = {"other_request": {"reply": "other_reply"}}
        for file in json_api_files:
            with open(file) as f:
                j = json.load(f)
                self._enums.extend(j['enums'])
                self._types.extend(j['types'])
                _messages.extend(j['messages'])
                self._services.update(j['services'])

        self.json_messages_by_name = dict([(m[0], m[1:]) for m in _messages])

    def _parse_services(self):
        self._dumps_by_details = {}
        self._requests_by_reply = {}
        for name, service in self._services.iteritems():
            if _is_stream(service):
                self._dumps_by_details[service['reply']] = name
            else:
                self._requests_by_reply[service['reply']] = name

    def _parse_messages(self):
        self.messages = []
        for name, definition in self.json_messages_by_name.iteritems():
            self.messages.append(self._parse_message(name, definition))

    def _parse_message(self, name, definition):
        crc = None
        for item in definition:
            if _is_crc(item):
                crc = item['crc']
                # fixme add fields
        if self.is_service(name):
            service = self._services[name]
            if _is_stream(service):
                return Dump(name, service['reply'], crc, [])
            return Request(name, service['reply'], crc, [])
        elif self.is_reply(name):
            return Reply(name, self._requests_by_reply[name], crc, [])
        elif self.is_details(name):
            return Details(name, self._dumps_by_details[name], crc, [])
        return Event(name, crc, [])

    def is_service(self, name):
        return name in self._services

    def is_reply(self, name):
        return name in self._requests_by_reply

    def is_details(self, name):
        return name in self._dumps_by_details
