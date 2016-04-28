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

import os, util
from string import Template

jvpp_ifc_template = Template("""
package $base_package;

public interface JVpp extends java.lang.AutoCloseable {

    /**
     * Generic dispatch method for sending requests to VPP
     */
    int send($base_package.$dto_package.JVppRequest request);

    @Override
    void close();

$methods
}
""")

jvpp_impl_template = Template("""
package $base_package;

public final class JVppImpl implements $base_package.JVpp {

    private final $base_package.VppConnection connection;

    public JVppImpl(final $base_package.VppConnection connection) {
        if(connection == null) {
            throw new java.lang.NullPointerException("Connection is null");
        }
        this.connection = connection;
    }

    @Override
    public void close() {
        connection.close();
    }

    @Override
    public int send($base_package.$dto_package.JVppRequest request) {
        return request.send(this);
    }

$methods
}
""")

method_template = Template("""    int $name($base_package.$dto_package.$request request);""")
method_native_template = Template(
    """    private static native int ${name}0($base_package.$dto_package.$request request);""")
method_impl_template = Template("""    public final int $name($base_package.$dto_package.$request request) {
        if(request == null) {
            throw new java.lang.NullPointerException("Null request object");
        }
        connection.checkActive();
        return ${name}0(request);
    }
""")

no_arg_method_template = Template("""    int $name();""")
no_arg_method_native_template = Template("""    private static native int ${name}0();""")
no_arg_method_impl_template = Template("""    public final int $name() {
        connection.checkActive();
        return ${name}0();
    }
""")


def generate_jvpp(func_list, base_package, dto_package):
    """ Generates JVpp interface and JNI implementation """
    print "Generating JVpp"

    methods = []
    methods_impl = []
    for func in func_list:

        if util.is_notification(func['name']) or util.is_ignored(func['name']):
            # TODO handle notifications
            continue

        camel_case_name = util.underscore_to_camelcase(func['name'])
        camel_case_name_upper = util.underscore_to_camelcase_upper(func['name'])
        if util.is_reply(camel_case_name):
            continue

        if len(func['args']) == 0:
            methods.append(no_arg_method_template.substitute(name=camel_case_name,
                                                             base_package=base_package,
                                                             dto_package=dto_package))
            methods_impl.append(
                no_arg_method_native_template.substitute(name=camel_case_name,
                                                         base_package=base_package,
                                                         dto_package=dto_package))
            methods_impl.append(no_arg_method_impl_template.substitute(name=camel_case_name,
                                                                       base_package=base_package,
                                                                       dto_package=dto_package))
        else:
            methods.append(method_template.substitute(name=camel_case_name,
                                                      request=camel_case_name_upper,
                                                      base_package=base_package,
                                                      dto_package=dto_package))
            methods_impl.append(method_native_template.substitute(name=camel_case_name,
                                                                  request=camel_case_name_upper,
                                                                  base_package=base_package,
                                                                  dto_package=dto_package))
            methods_impl.append(method_impl_template.substitute(name=camel_case_name,
                                                                request=camel_case_name_upper,
                                                                base_package=base_package,
                                                                dto_package=dto_package))

    jvpp_file = open("JVpp.java", 'w')
    jvpp_file.write(
        jvpp_ifc_template.substitute(methods="\n".join(methods),
                                     base_package=base_package,
                                     dto_package=dto_package))
    jvpp_file.flush()
    jvpp_file.close()

    jvpp_file = open("JVppImpl.java", 'w')
    jvpp_file.write(jvpp_impl_template.substitute(methods="\n".join(methods_impl),
                                                  base_package=base_package,
                                                  dto_package=dto_package))
    jvpp_file.flush()
    jvpp_file.close()
