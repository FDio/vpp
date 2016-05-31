#!/usr/bin/env python
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

import os

import callback_gen
import util
from string import Template

from util import remove_suffix

global_callback_template = Template("""
package $base_package.$notification_package;

public interface NotificationRegistry extends java.lang.AutoCloseable, $callbacks {

    $register_callback_methods

    @Override
    void close();
}
""")


def generate_notification_registry(func_list, base_package, notification_package, callback_package, dto_package, inputfile):
    """ Generates notification registry interface and implementation """
    print "Generating Notification interfaces and implementation"

    if not os.path.exists(notification_package):
        raise Exception("%s folder is missing" % notification_package)

    callbacks = []
    methods = []
    for func in func_list:

        if not util.is_notification(func['name']):
            continue

        camel_case_name_with_suffix = util.underscore_to_camelcase_upper(func['name'])
        notification_dto = util.add_notification_suffix(camel_case_name_with_suffix)
        callback_ifc = notification_dto + callback_gen.callback_suffix
        fully_qualified_callback_ifc = "{0}.{1}.{2}".format(base_package, callback_package, callback_ifc)
        callbacks.append(fully_qualified_callback_ifc)

        methods.append("java.lang.AutoCloseable register{0}({1} callback);".format(callback_ifc, fully_qualified_callback_ifc))

    callback_file = open(os.path.join(notification_package, "NotificationRegistry.java"), 'w')
    callback_file.write(global_callback_template.substitute(inputfile=inputfile,
                                                            callbacks=", ".join(callbacks),
                                                            register_callback_methods= "\n    ".join(methods),
                                                            base_package=base_package,
                                                            notification_package=notification_package))
    callback_file.flush()
    callback_file.close()
