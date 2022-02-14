#!/usr/bin/env python3
#  Copyright (c) 2022. Intel Corporation.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import json, argparse, re

number_regex  = r'^(?:0[xX])?[0-9a-fA-F]*$'
counter_regex = r'(?:^(?:\d,)*(?:\d)$)|(?:^Fixed.*)'

ignore_events = [r'^OCR\..*',r'^OFFCORE_RESPONSE.*']
ignore_fields = [r'^Errata$']
lowercase_fields = [r'^Unit$']

def prune_events(events):
    _events = []
    _ignore_events = []

    for _ignore in ignore_events:
        _ignore_events += [re.compile(_ignore)]

    for _event in events:
        def ignore():
            for _ignore in _ignore_events:
                if _ignore.search(_event['EventName']) is not None:
                    return True
        if ignore():
            continue
        else:
            _events += [_event]

    return _events

def match_field(fields, field):
    _match_fields = []

    for _field in fields:
        _match_fields += [re.compile(_field)]

    for _field in _match_fields:
        if _field.search(field) is not None:
            return True

    return False

class _Value(object):
    def __init__(self, value):
        self.value = value

    @classmethod
    def test(cls, value):
        return True if cls.regex.search(value) is not None else False

    def __format__(self, format_spec):
        return self.value_format.format(self.value)

class _Number(_Value):
    regex = re.compile(number_regex)
    value_format = "{}"

class _Counter(_Value):
    regex = re.compile(counter_regex, re.IGNORECASE)

    def __format__(self, format_spec):
        fixed_regex = re.compile(r'(?:^Fixed.*)', re.IGNORECASE)

        if fixed_regex.search(self.value) is not None:
            return str("0x00")
        else:
            r = 0
            for bit_shift in self.value.split(','):
                r |= 1 << int(bit_shift)

            return '0x{:02X}'.format(r)

class _String(_Value):
    value_format = "\"{}\""

    def __init__(self, value):
        trans = str.maketrans('\n\r','  ')
        self.value = value.translate(trans)

    @classmethod
    def test(cls, value):
        return True

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument('-i', '--input', action="store",
                                  help="input JSON file name", required = True)
    p.add_argument('-o', '--output', action="store",
                   help="output JSON file name", required = True)
    p.add_argument('-m', '--macro', action="store",
                   help="macro name", required = True)

    _fields = [_Number, _Counter, _String]
    args = p.parse_args()

    _def = open(args.output, 'w')
    macro = args.macro

    with open(args.input, 'r') as fp:
        events = json.load(fp)
        events = prune_events(events)

        for event in events:
            tokens = []

            for _key in event.keys():

                if match_field(ignore_fields, _key):
                    continue

                if match_field(lowercase_fields, _key):
                    event[_key] = event[_key].lower()

                for _field in _fields:
                    if _field.test(event[_key]):
                        tokens += [format(_field(event[_key]))]
                        break
            _def.write(macro + '(' + ','.join(tokens) + ')\n')
