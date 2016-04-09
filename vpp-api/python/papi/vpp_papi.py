#!/usr/bin/env python3

import sys, time, threading, signal, os, logging
from struct import *
from collections import namedtuple

#
# Import C API shared object
#
import pneum

context = 0
results = {}
waiting_for_reply = False

#
# XXX: Make this return a unique number
#
def get_context(id):
    global context
    context += 1
    return context

from api_vpp_papi import *

def msg_handler(msg):
    global result, context, event_callback, waiting_for_reply
    if not msg:
        logging.warning('pneum.read failed')
        return

    id = unpack('>H', msg[0:2])
    logging.debug('Received message', id[0])
    if id[0] == VL_API_RX_THREAD_EXIT:
        logging.info("We got told to leave")
        return;

    #
    # Decode message and returns a tuple.
    #
    logging.debug('api_func', api_func_table[id[0]])
    r = api_func_table[id[0]](msg)
    if not r:
        logging.warning('Message decode failed', id[0])
        return

    if 'context' in r._asdict():
        if r.context > 0:
            context = r.context

    #
    # XXX: Call provided callback for event
    # Are we guaranteed to not get an event during processing of other messages?
    # How to differentiate what's a callback message and what not? Context = 0?
    #
    logging.debug('R:', context, r, waiting_for_reply)
    if waiting_for_reply == False:
        event_callback(r)
        return

    #
    # Collect results until control ping
    #
    if id[0] == VL_API_CONTROL_PING_REPLY:
        results[context]['e'].set()
        waiting_for_reply = False
        return
    if not context in results:
        logging.warning('Not expecting results for this context', context)
        return
    if 'm' in results[context]:
        results[context]['r'].append(r)
        return

    results[context]['r'] = r
    results[context]['e'].set()
    waiting_for_reply = False

def connect(name):
    signal.alarm(3) # 3 second
    rv = pneum.connect(name, msg_handler)
    signal.alarm(0)
    logging.info("Connect:", rv)
    return rv

def disconnect():
    rv = pneum.disconnect()
    logging.info("Disconnected")
    return rv

def register_event_callback(callback):
    global event_callback
    event_callback = callback
