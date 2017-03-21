from test_jvpp import TestJVpp

class TestJVppCore(TestJVpp):
    """ JVPP Core Test Case """

    def invoke_for_jvpp_core(self, test_class_name):
        self.jvpp_connection_test(api_jar_name="jvpp-core", test_class_name=test_class_name, timeout=10)

    def test_callback_api(self):
        """ JVPP Core Callback api Test Case """
        self.invoke_for_jvpp_core(test_class_name="io.fd.vpp.jvpp.core.test.CallbackApiTest")

    def test_notification_facade(self):
        """ JVPP Core Notification facade Test Case """
        self.invoke_for_jvpp_core(test_class_name="io.fd.vpp.jvpp.core.test.CallbackJVppFacadeNotificationTest")

    def test_callback_facade(self):
        """ JVPP Core Callback facade Test Case """
        self.invoke_for_jvpp_core(test_class_name="io.fd.vpp.jvpp.core.test.CallbackJVppFacadeTest")

    def test_callback_notification_api(self):
        """ JVPP Core Callback Notification api Test Case """
        self.invoke_for_jvpp_core(test_class_name="io.fd.vpp.jvpp.core.test.CallbackNotificationApiTest")

    def test_controll_ping(self):
        """ JVPP Core Control ping Test Case """
        self.invoke_for_jvpp_core(test_class_name="io.fd.vpp.jvpp.core.test.ControlPingTest")

    def test_future_api_notifications(self):
        """ JVPP Core Future Notification api Test Case """
        self.invoke_for_jvpp_core(test_class_name="io.fd.vpp.jvpp.core.test.FutureApiNotificationTest")

    def test_future_api(self):
        """ JVPP Core Future api Test Case """
        self.invoke_for_jvpp_core(test_class_name="io.fd.vpp.jvpp.core.test.FutureApiTest")

    # Api specific tests
    def test_create_sub_interface(self):
        """ JVPP Core Create sub-interface Test Case """
        self.invoke_for_jvpp_core(test_class_name="io.fd.vpp.jvpp.core.test.CreateSubInterfaceTest")

    def test_l2_acl(self):
        """ JVPP Core L2 acl Test Case """
        self.invoke_for_jvpp_core(test_class_name="io.fd.vpp.jvpp.core.test.L2AclTest")

    def test_lisp_adjacency(self):
        """ JVPP Core lisp adjacency Test Case """
        self.invoke_for_jvpp_core(test_class_name="io.fd.vpp.jvpp.core.test.LispAdjacencyTest")
