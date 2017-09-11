from jvpp_connection import TestJVppConnection


class TestJVpp(TestJVppConnection):
    """ JVPP Core Test Case """

    def invoke_for_jvpp_core(self, api_jar_name, test_class_name):
        self.jvpp_connection_test(api_jar_name=api_jar_name,
                                  test_class_name=test_class_name,
                                  timeout=10)

    def test_vpp_core_callback_api(self):
        """ JVPP Core Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-core",
                                  test_class_name="io.fd.vpp.jvpp.core.test."
                                                  "CallbackApiTest")

    def test_vpp_core_future_api(self):
        """JVPP Core Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-core",
                                  test_class_name="io.fd.vpp.jvpp.core.test."
                                                  "FutureApiTest")

    def test_vpp_acl_callback_api(self):
        """ JVPP Acl Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-acl",
                                  test_class_name="io.fd.vpp.jvpp.acl.test."
                                                  "CallbackApiTest")

    def test_vpp_acl_future_api(self):
        """JVPP Acl Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-acl",
                                  test_class_name="io.fd.vpp.jvpp.acl.test."
                                                  "FutureApiTest")

    def test_vpp_ioamexport_callback_api(self):
        """ JVPP Ioamexport Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioamexport",
                                  test_class_name="io.fd.vpp.jvpp.ioamexport."
                                                  "test.CallbackApiTest")

#    def test_vpp_ioamexport_future_api(self):
#        """JVPP Ioamexport Future Api Test Case"""
#        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioamexport",
#                                  test_class_name="io.fd.vpp.jvpp.ioamexport."
#                                                  "test.FutureApiTest")

    def test_vpp_ioampot_callback_api(self):
        """ JVPP Ioampot Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioampot",
                                  test_class_name="io.fd.vpp.jvpp.ioampot."
                                                  "test.CallbackApiTest")

    def test_vpp_ioampot_future_api(self):
        """JVPP Ioampot Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioampot",
                                  test_class_name="io.fd.vpp.jvpp.ioampot."
                                                  "test.FutureApiTest")

    def test_vpp_ioamtrace_callback_api(self):
        """ JVPP Ioamtrace Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioamtrace",
                                  test_class_name="io.fd.vpp.jvpp.ioamtrace."
                                                  "test.CallbackApiTest")

    def test_vpp_ioamtrace_future_api(self):
        """JVPP Ioamtrace Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-ioamtrace",
                                  test_class_name="io.fd.vpp.jvpp.ioamtrace."
                                                  "test.FutureApiTest")

    def test_vpp_snat_callback_api(self):
        """ JVPP Snat Callback Api Test Case """
        self.invoke_for_jvpp_core(api_jar_name="jvpp-nat",
                                  test_class_name="io.fd.vpp.jvpp.nat.test."
                                                  "CallbackApiTest")

    def test_vpp_snat_future_api(self):
        """JVPP Snat Future Api Test Case"""
        self.invoke_for_jvpp_core(api_jar_name="jvpp-nat",
                                  test_class_name="io.fd.vpp.jvpp.nat.test."
                                                  "FutureApiTest")
