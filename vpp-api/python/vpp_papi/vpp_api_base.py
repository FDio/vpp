#
# Copyright (c) 2016 Cisco and/or its affiliates.
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
# Module storing all global variables, shared between main module and plugins
#
import threading

#
# Global variables
#
results = {}
waiting_for_reply = False
plugins = {}

class ContextId(object):
    def __init__(self):
        self.context = 0
    def __call__(self, id):
        self.context += 1
        return self.context
get_context = ContextId()

def waiting_for_reply_clear():
    global waiting_for_reply
    waiting_for_reply = False

def waiting_for_reply_set():
    global waiting_for_reply
    waiting_for_reply = True

def is_waiting_for_reply():
    return waiting_for_reply

def event_callback_set(callback):
    global event_callback
    event_callback = callback

def event_callback_call(r):
    global event_callback
    event_callback(r)

def results_event_set(context):
    results[context]['e'].set()

def results_event_clear(context):
    results[context]['e'].clear()

def results_event_wait(context, timeout):
    return (results[context]['e'].wait(timeout))

def results_set(context, r):
    results[context]['r'] = r

def results_append(context, r):
    results[context]['r'].append(r)

def is_results_context(context):
    return context in results

def is_results_more(context):
    return 'm' in results[context]

def results_more_set(context):
    results[context]['m'] = True

def results_prepare(context):
    results[context] = {}
    results[context]['e'] = threading.Event()
    results[context]['e'].clear()
    results[context]['r'] = []

def results_get(context):
    return results[context]['r']

def plugin_register(name, func_table, name_to_id_table, version, msg_id_base_set):
    plugins[name] = {}
    p = plugins[name]
    p['func_table'] = func_table
    p['name_to_id_table'] = name_to_id_table
    p['version'] = version
    p['msg_id_base_set'] = msg_id_base_set

def plugin_show():
    for p in plugins:
        print(p)
