#!/usr/bin/env python3

from __future__ import print_function
from cffi import FFI
import time

ffi = FFI()
ffi.cdef("""
typedef uint64_t counter_t;
typedef struct {
  counter_t packets;
  counter_t bytes;
} vlib_counter_t;

typedef enum {
  STAT_DIR_TYPE_ILLEGAL = 0,
  STAT_DIR_TYPE_SCALAR_INDEX,
  STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE,
  STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED,
  STAT_DIR_TYPE_ERROR_INDEX,
  STAT_DIR_TYPE_NAME_VECTOR,
} stat_directory_type_t;

typedef struct
{
  stat_directory_type_t type;
  union {
    uint64_t index;
    uint64_t value;
    uint64_t *data;
  };
  char name[128]; // TODO change this to pointer to "somewhere"
} stat_segment_directory_entry_t;

typedef struct
{
  char *name;
  stat_directory_type_t type;
  union
  {
    double scalar_value;
    counter_t *error_vector;
    counter_t **simple_counter_vec;
    vlib_counter_t **combined_counter_vec;
    uint8_t **name_vector;
  };
} stat_segment_data_t;

typedef struct
{
  uint64_t version;
  void *base;
  uint64_t epoch;
  uint64_t in_progress;
  stat_segment_directory_entry_t *directory_vector;
  uint64_t **error_vector;
} stat_segment_shared_header_t;

typedef struct
{
  uint64_t current_epoch;
  stat_segment_shared_header_t *shared_header;
  stat_segment_directory_entry_t *directory_vector;
  ssize_t memory_size;
} stat_client_main_t;

stat_client_main_t * stat_client_get(void);
void stat_client_free(stat_client_main_t * sm);
int stat_segment_connect_r (char *socket_name, stat_client_main_t * sm);
int stat_segment_connect (char *socket_name);
void stat_segment_disconnect_r (stat_client_main_t * sm);
void stat_segment_disconnect (void);

uint32_t *stat_segment_ls_r (uint8_t ** patterns, stat_client_main_t * sm);
uint32_t *stat_segment_ls (uint8_t ** pattern);
stat_segment_data_t *stat_segment_dump_r (uint32_t * stats,
                                          stat_client_main_t * sm);
stat_segment_data_t *stat_segment_dump (uint32_t * counter_vec);
void stat_segment_data_free (stat_segment_data_t * res);

double stat_segment_heartbeat_r (stat_client_main_t * sm);
int stat_segment_vec_len(void *vec);
uint8_t **stat_segment_string_vector(uint8_t **string_vector, char *string);
char *stat_segment_index_to_name_r (uint32_t index, stat_client_main_t * sm);
uint64_t stat_segment_version(void);
uint64_t stat_segment_version_r(stat_client_main_t *sm);
void free(void *ptr);
""")  # noqa: E501


# Utility functions
def make_string_vector(api, strings):
    vec = ffi.NULL
    if type(strings) is not list:
        strings = [strings]
    for s in strings:
        vec = api.stat_segment_string_vector(vec, ffi.new("char []",
                                                          s.encode('utf-8')))
    return vec


def make_string_list(api, vec):
    vec_len = api.stat_segment_vec_len(vec)
    return [ffi.string(vec[i]) for i in range(vec_len)]


# 2-dimensonal array of thread, index
def simple_counter_vec_list(api, e):
    vec = []
    for thread in range(api.stat_segment_vec_len(e)):
        len_interfaces = api.stat_segment_vec_len(e[thread])
        if_per_thread = [e[thread][interfaces]
                         for interfaces in range(len_interfaces)]
        vec.append(if_per_thread)
    return vec


def vlib_counter_dict(c):
    return {'packets': c.packets,
            'bytes': c.bytes}


def combined_counter_vec_list(api, e):
    vec = []
    for thread in range(api.stat_segment_vec_len(e)):
        len_interfaces = api.stat_segment_vec_len(e[thread])
        if_per_thread = [vlib_counter_dict(e[thread][interfaces])
                         for interfaces in range(len_interfaces)]
        vec.append(if_per_thread)
    return vec


def error_vec_list(api, e):
    vec = []
    for thread in range(api.stat_segment_vec_len(e)):
        vec.append(e[thread])
    return vec


def name_vec_list(api, e):
    return [ffi.string(e[i]).decode('utf-8') for i in
            range(api.stat_segment_vec_len(e)) if e[i] != ffi.NULL]


def stat_entry_to_python(api, e):
    # Scalar index
    if e.type == 1:
        return e.scalar_value
    if e.type == 2:
        return simple_counter_vec_list(api, e.simple_counter_vec)
    if e.type == 3:
        return combined_counter_vec_list(api, e.combined_counter_vec)
    if e.type == 4:
        return error_vec_list(api, e.error_vector)
    if e.type == 5:
        return name_vec_list(api, e.name_vector)
    raise NotImplementedError()


class VPPStatsIOError(IOError):
    message = "Stat segment client connection returned: " \
              "%(retval)s %(strerror)s."

    strerror = {-1: "Stat client couldn't open socket",
                -2: "Stat client socket open but couldn't connect",
                -3: "Receiving file descriptor failed",
                -4: "mmap fstat failed",
                -5: "mmap map failed"
                }

    def __init__(self, message=None, **kwargs):
        if 'retval' in kwargs:
            self.retval = kwargs['retval']
            kwargs['strerror'] = self.strerror[int(self.retval)]

        if not message:
            try:
                message = self.message % kwargs
            except Exception:
                message = self.message
        else:
            message = message % kwargs

        super(VPPStatsIOError, self).__init__(message)


class VPPStatsClientLoadError(RuntimeError):
    pass


class VPPStats(object):
    VPPStatsIOError = VPPStatsIOError

    default_socketname = '/run/vpp/stats.sock'
    sharedlib_name = 'libvppapiclient.so'

    def __init__(self, socketname=default_socketname, timeout=10):
        self.socketname = socketname
        self.timeout = timeout
        self.connected = False
        try:
            self.api = ffi.dlopen(VPPStats.sharedlib_name)
        except Exception:
            raise VPPStatsClientLoadError("Could not open: %s" %
                                          VPPStats.sharedlib_name)

    def connect(self):
        self.client = self.api.stat_client_get()

        poll_end_time = time.time() + self.timeout
        while time.time() < poll_end_time:
            rv = self.api.stat_segment_connect_r(
                self.socketname.encode('utf-8'), self.client)
            # Break out if success or any other error than "no such file"
            # (indicating that VPP hasn't started yet)
            if rv == 0 or ffi.errno != 2:
                self.connected = True
                break

        if rv != 0:
            raise VPPStatsIOError(retval=rv)

    def heartbeat(self):
        if not self.connected:
            self.connect()
        return self.api.stat_segment_heartbeat_r(self.client)

    def ls(self, patterns):
        if not self.connected:
            self.connect()
        return self.api.stat_segment_ls_r(make_string_vector(self.api,
                                                             patterns),
                                          self.client)

    def lsstr(self, patterns):
        if not self.connected:
            self.connect()
        rv = self.api.stat_segment_ls_r(make_string_vector(self.api,
                                                           patterns),
                                        self.client)

        if rv == ffi.NULL:
            raise VPPStatsIOError()
        return [ffi.string(self.api.stat_segment_index_to_name_r(
            rv[i], self.client)).decode('utf-8')
                for i in range(self.api.stat_segment_vec_len(rv))]

    def dump(self, counters):
        if not self.connected:
            self.connect()
        stats = {}
        rv = self.api.stat_segment_dump_r(counters, self.client)
        # Raise exception and retry
        if rv == ffi.NULL:
            raise VPPStatsIOError()
        rv_len = self.api.stat_segment_vec_len(rv)

        for i in range(rv_len):
            n = ffi.string(rv[i].name).decode('utf-8')
            e = stat_entry_to_python(self.api, rv[i])
            if e is not None:
                stats[n] = e
        return stats

    def get_counter(self, name):
        retries = 0
        while True:
            try:
                d = self.ls(name)
                s = self.dump(d)
                if len(s) > 1:
                    raise AttributeError('Matches multiple counters {}'
                                         .format(name))
                k, v = s.popitem()
                return v
            except VPPStatsIOError:
                if retries > 10:
                    return None
                retries += 1

    def get_err_counter(self, name):
        """Get an error counter. The errors from each worker thread
           are summed"""
        return sum(self.get_counter(name))

    def disconnect(self):
        try:
            self.api.stat_segment_disconnect_r(self.client)
            self.api.stat_client_free(self.client)
            self.connected = False
            del self.client
        except AttributeError:
            # no need to disconnect if we're not connected
            pass

    def set_errors(self):
        '''Return all errors counters > 0'''
        retries = 0
        while True:
            try:
                error_names = self.ls(['/err/'])
                error_counters = self.dump(error_names)
                break
            except VPPStatsIOError:
                if retries > 10:
                    return None
                retries += 1

        return {k: sum(error_counters[k])
                for k in error_counters.keys() if sum(error_counters[k])}

    def set_errors_str(self):
        '''Return all errors counters > 0 pretty printed'''
        s = ['ERRORS:']
        error_counters = self.set_errors()
        for k in sorted(error_counters):
            s.append('{:<60}{:>10}'.format(k, error_counters[k]))
        return '%s\n' % '\n'.join(s)
