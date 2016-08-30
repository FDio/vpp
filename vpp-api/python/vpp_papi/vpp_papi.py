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
# Import C API shared object
#
from __future__ import print_function

import signal, os, sys
from struct import *

scriptdir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(scriptdir)
import vpp_api
from vpp_api_base import *

# Import API definitions. The core VPE API is imported into main namespace
import memclnt
from vpe import *
vpe = sys.modules['vpe']

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def msg_handler(msg):
    if not msg:
        eprint('vpp_api.read failed')
        return

    id = unpack('>H', msg[0:2])
    if id[0] == memclnt.VL_API_RX_THREAD_EXIT:
        return;

    #
    # Decode message and returns a tuple.
    #
    try:
        r = api_func_table[id[0]](msg)
    except:
        eprint('Message decode failed', id[0], api_func_table[id[0]])
        raise

    if 'context' in r._asdict():
        if r.context > 0:
            context = r.context

    #
    # XXX: Call provided callback for event
    # Are we guaranteed to not get an event during processing of other messages?
    # How to differentiate what's a callback message and what not? Context = 0?
    #
    if not is_waiting_for_reply():
        event_callback_call(r)
        return

    #
    # Collect results until control ping
    #
    if id[0] == vpe.VL_API_CONTROL_PING_REPLY:
        results_event_set(context)
        waiting_for_reply_clear()
        return
    if not is_results_context(context):
        eprint('Not expecting results for this context', context)
        return
    if is_results_more(context):
        results_append(context, r)
        return

    results_set(context, r)
    results_event_set(context)
    waiting_for_reply_clear()

def connect(name):
    signal.alarm(3) # 3 second
    rv = vpp_api.connect(name, msg_handler)
    signal.alarm(0)

    #
    # Assign message id space for plugins
    #
    plugin_map_plugins()

    return rv

def disconnect():
    rv = vpp_api.disconnect()
    return rv

# CLI convenience wrapper
def cli_exec(cmd):
    cmd += '\n'
    r = cli_inband(len(cmd), cmd)
    return r.reply[0].decode().rstrip('\x00')

def register_event_callback(callback):
    event_callback_set(callback)

def plugin_name_to_id(plugin, name_to_id_table, base):
    try:
        m = globals()[plugin]
    except KeyError:
        m = sys.modules[plugin]
    for name in name_to_id_table:
        setattr(m, name, name_to_id_table[name] + base)

def plugin_map_plugins():
    for p in plugins:
        if p == 'memclnt' or p == 'vpe':
            continue

        #
        # Find base
        # Update api table
        #
        version = plugins[p]['version']
        name = p + '_' + format(version, '08x')
        r = memclnt.get_first_msg_id(name.encode('ascii'))
        ## TODO: Add error handling / raise exception
        if r.retval != 0:
            eprint('Failed getting first msg id for:', p)
            continue

        # Set base
        base = r.first_msg_id
        msg_id_base_set = plugins[p]['msg_id_base_set']
        msg_id_base_set(base)
        plugins[p]['base'] = base
        func_table = plugins[p]['func_table']
        i = r.first_msg_id
        # Insert doesn't extend the table
        if i + len(func_table) > len(api_func_table):
            fill = [None] * (i + len(func_table) - len(api_func_table))
            api_func_table.extend(fill)
        for entry in func_table:
            api_func_table[i] = entry
            i += 1
        plugin_name_to_id(p, plugins[p]['name_to_id_table'], base)

#
# Set up core API
#
memclnt.msg_id_base_set(1)
plugins['memclnt']['base'] = 1
msg_id_base_set(len(plugins['memclnt']['func_table']) + 1)
plugins['vpe']['base'] = len(plugins['memclnt']['func_table']) + 1
api_func_table = []
api_func_table.append(None)
api_func_table[1:] = plugins['memclnt']['func_table'] + plugins['vpe']['func_table']
plugin_name_to_id('memclnt', plugins['memclnt']['name_to_id_table'], 1)
plugin_name_to_id('vpe', plugins['vpe']['name_to_id_table'], plugins['vpe']['base'])
