# Copyright 2018 Vinci Consulting Corp. All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import shlex


class VppConfig(object):
    stanzas = ['unix', 'api-trace', 'api-segment',
               'socksvr', 'cpu', 'statseg', 'dpdk', 'plugins', 'tuntap',
               'punt']
    kw = {'unix': ['interactive', 'nodaemon', 'log', 'full-coredump',
                   'coredump-size', 'cli-listen', 'runtime-dir', 'gid'],
          'api-trace': ['on', 'nitems', 'save-api-table'],
          'api-segment': ['prefix', 'gid'],
          'socksvr': ['default'],
          'cpu': ['main-core', 'corelist-workers', 'skip-cores',
                  'workers', 'scheduler-policy', 'scheduler-priority'],
          'statseg': ['socket-name'],
          'dpdk': ['dev', 'vdev', 'uio-driver', 'no-multi-seg', 'num-mbufs',
                   'socket-mem', 'no-tx-checksum-offload'],
          'plugins': ['path', 'plugin'],
          'tuntap': ['name', 'mtu', 'enable', 'disable', 'ethernet',
                     'have-normal-interface'],
          'punt': ['socket']
          }
    default_values = {'unix': {'interactive': None,
                               }
                      }

    def __init__(self):
        self.values = type(self).default_values
        self.plugins = []

    def add(self, stanza, key, val):
        if stanza not in type(self).stanzas:
            raise ValueError("stanza '%s' must be in %s" %
                             (stanza, type(self).stanzas))
        if key not in type(self).kw[stanza]:
            raise ValueError("key '%s' must be in %s" %
                             (key, type(self).kw[stanza]))
        self.values[stanza][key] = val

    def add_plugin(self, key, val):
        self.plugins.append((key, val,))

    def __str__(self):
        result = ''
        for stanza in type(self).stanzas:
            try:
                if self.values[stanza]:
                    result = '%s\n%s {' % (result, stanza)
                    for key in type(self).kw[stanza]:
                        try:
                            if key in self.values[stanza]:
                                result = '%s\n    %s %s' % (
                                    result, key,
                                    self.values[stanza][key]
                                    if self.values[stanza][key] is not
                                    None else '')
                        except KeyError:
                            # no key: nothing to do
                            pass
                        if stanza == 'plugins' and key == 'plugin':
                            for plugin, val in self.plugins:
                                result = '%s\n    plugin %s { % s }' % (
                                    result, plugin,
                                    val if val is not None else '')
                    result = '%s\n}\n' % result
            except KeyError:
                # no stanza not in self.values: nothing to do
                pass
        return result

    def shlex(self):
        return shlex.split(str(self))


class MinimalVppConfig(VppConfig):
    default_values = {'unix': {'interactive': None,
                               'cli-listen': 'run/vpp/cli.sock',
                               'gid': 1000
                               }
                      }


class VppTestCaseVppConfig(VppConfig):
    default_values = {'unix': {'nodaemon': None,
                               'full-coredump': None,
                               },
                      'api-trace': {'on': None},
                      'api-segment': {},
                      'cpu': {},
                      'statseg': {},
                      'plugins': {}
                      }
