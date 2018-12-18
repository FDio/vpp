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
import unittest


class VppConfig(object):
    stanzas = ['unix', 'api-trace', 'api-segment',
               'socksvr', 'cpu', 'statseg', 'dpdk', 'plugins', 'tuntap',
               'punt']
    kw = {'unix': ['interactive', 'nodaemon', 'log', 'full-coredump',
                   'coredump-size', 'cli-listen', 'runtime-dir', 'gid'],
          'acl-plugin': ['connection hash buckets', 'connection hash memory',
                         'connection count max', 'main heap size',
                         'hash lookup heap size', 'hash lookup hash buckets',
                         'hash lookup hash memory', 'use tuple merge',
                         'tuple merge split threshold', 'reclassify sessions'],
          'api-queue': ['len', 'length'],
          'api-trace': ['on', 'enable, ''nitems', 'save-api-table'],
          'api-segment': ['prefix', 'gid'],
          'cj': ['on', 'records'],
          'cpu': ['main-core', 'corelist-workers', 'skip-cores',
                  'workers', 'scheduler-policy', 'scheduler-priority'],
          'dns': ['max-cache-size', 'max-ttl'],
          'dpdk': ['dev', 'vdev', 'name', 'hqos', 'rss',
                   'no-multi-seg',
                   'num-mbufs', 'num-rx-queues', 'num-tx-queues',
                   'num-rx-desc', 'num-tx-desc',
                   'socket-mem', 'no-tx-checksum-offload', 'uio-driver',
                   'vlan-strip-offload', 'workers'],
          # currently don't support dynamic keys
          # 'heapsize': [],
          'l2learn': ['limit'],
          'l2tp': ['lookup-v6-src', 'lookup-v6-dst',
                   'lookup-session-id'],
          'nat': ['connection tracking', 'deterministic', 'dslite ce',
                  'endpoint-dependent', 'inside VRF id',
                  'max translations per user',
                  'nat64 bib hash bucket', 'nat64 bib hash memory',
                  'nat64 st hash buckets',
                  'outside ip6 VRF id', 'outside VRF id', 'out2in dpo'
                  'static mapping only',
                  'translation hash buckets',
                  'translation hash memory',
                  'user hash buckets', 'user hash memory',
                  ],
          'mactime': ['lookup-table-buckets', 'lookup-table-memory',
                      'timezone_offset'],
          'mc': ['interface', 'no-delay', 'no-validate', 'max-delay',
                 'min-delay', 'n-bytes', 'n-packets',
                 'max-n-bytes',
                 'min-n-bytes',
                 'seed', 'window', 'verbose', ],
          'oam': ['interval', 'misses-allowed'],
          'plugins': ['path', 'plugin'],
          'punt': ['socket'],
          'session': ['event-queue-length', 'preallocated-sessions',
                      'v4-session-table-buckets', 'v4-halfopen-table-buckets',
                      'v6-session-table-buckets', 'v6-halfopen-table-buckets',
                      'v6-halfopen-table-buckets'
                      ],
          'socksvr': ['default', 'socket-name'],
          'statseg': ['socket-name'],
          'tapcli': ['disable', 'mtu'],
          'tcp': ['buffer-fail-fraction', 'cc-algo', 'max-rx-fifo',
                  'no-tx-pacing', 'preallocated-connections',
                  'preallocated-half-open-connections',
                  ],
          'tuntap': ['name', 'mtu', 'enable', 'disable',
                     'ether', 'ethernet',
                     'have-normal', 'have-normal-interface'
                     ],
          'vhost-user': ['coalesce-frames', 'coalesce-time',
                         'dont-dump-memory']


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
                      'acl-plugin': {},
                      'api-queue': {},
                      'api-trace': {'on': None},
                      'api-segment': {},
                      'cj': {},
                      'cpu': {},
                      'dns': {},
                      'dpdk': {},
                      # currently don't support dynamic keys
                      # 'heapsize': {},
                      'l2learn': {},
                      'l2tp': {},
                      'mactime': {},
                      'mc': {},
                      'nat': {},
                      'oam': {},
                      'plugins': {},
                      'punt': {},
                      'session': {},
                      'socksvr': {'default': None},
                      'statseg': {},
                      'tapcli': {},
                      'tcp': {},
                      'tuntap': {},
                      'vhost-user': {},
                      }


class TestVppConfig(unittest.TestCase):

    def setUp(self):
        self.config = VppTestCaseVppConfig()

    def test_unix(self):
        size = None
        tempdir = '/tmp'

        # reset default values for this test.
        self.config.default_values['unix'] = {}
        self.config.add('unix', 'coredump-size', size
                        if size is not None else 'unlimited')
        self.assertIn('unix {\n    coredump-size unlimited\n}\n',
                      str(self.config))

        self.config.add('unix', 'runtime-dir', tempdir)
        self.assertIn('runtime-dir /tmp', str(self.config))

    def test_api_segment(self):
        shm_prefix = '/dev/shm'
        self.config.add('api-segment', 'prefix', shm_prefix)
        self.assertIn('api-segment {\n    prefix /dev/shm\n}\n',
                      str(self.config))

    def test_cpu(self):
        luc = 0
        self.config.add('cpu', 'main-core', str(luc))
        self.assertIn('cpu {\n    main-core 0\n}\n', str(self.config))

    def test_statseg(self):
        stats_sock = '/stats.sock'
        self.config.add('statseg', 'socket-name', stats_sock)
        self.assertIn('statseg {\n    socket-name /stats.sock\n}\n',
                      str(self.config))

    def test_plugin(self):
        plugin_path = '/foo'
        self.config.add('plugins', 'path', plugin_path)
        self.assertIn('plugins {\n    path /foo\n}\n',
                      str(self.config))

        self.config.add_plugin('dpdk_plugin.so', 'disable')
        self.config.add_plugin('unittest_plugin.so', 'enable')
        self.assertIn('plugin dpdk_plugin.so { disable }\n',
                      str(self.config))
        self.assertIn('plugin unittest_plugin.so { enable }\n',
                      str(self.config))


if __name__ == '__main__':
    unittest.main()
