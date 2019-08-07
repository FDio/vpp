#  Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
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

import inspect
import importlib
import logging
import os
import framework

from parameterized import parameterized

import vpp_object

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def find_subclasses(class_type):
    subclasses = []
    for file in os.listdir(os.path.dirname(os.path.abspath(__file__))):
        if not file.startswith('_') and file.endswith('.py'):
            try:
                logger.debug('file: %s' % (file))
                # strip off ".py"
                module = importlib.import_module(file[:-3], 'test')
                for x in dir(module):
                    obj = getattr(module, x)
                    if inspect.isclass(obj):
                        _class = getattr(module, x)
                        if issubclass(_class, class_type):
                            logger.debug('found subclass: %s' % _class)
                            subclasses.append(_class)
            except ImportError as e:
                logger.debug('exc: %s' % e)
            except OSError as e:
                logger.debug('exc: %s' % e)
            except (TypeError, SyntaxError):
                pass

    return subclasses


class TestVppObject(unittest.TestCase):
    """TestVppObject"""

    def test_has_details_record(self):
        vpp_objects = sorted(set([v for v in find_subclasses(
            vpp_object.VppObject) if v != vpp_object.VppObject and (
                                  not hasattr(v, 'DETAILS_RECORD') or
                                  v.DETAILS_RECORD is None or
                                  not v.DETAILS_RECORD.endswith('_details'))]))
#        print(('\n'.join([repr(v) for v in vpp_objects])))
        self.assertIsNone(vpp_object,
                          "Please set 'DETAILS_RECORD' in %r." %
                          vpp_objects)

    def test_has_eq_(self):
        vpp_objects = sorted(set([v for v in find_subclasses(
            vpp_object.VppObject) if v != vpp_object.VppObject and
                                          '__eq__' not in vars(v)]))

    def test_eq(self):
        pass


if __name__ == '__main__':
    framework.main(verbosity=2)
