This package contains basic tests for jvpp. To run the tests:

- Make sure VPP is running
- From VPP's build-root/ folder execute:
  - sudo java -cp build-vpp-native/vpp-api/java/jvpp-16.09.jar org.openvpp.jvpp.test.[test name]

Available tests:
ControlPingTest - Simple test executing a single control ping using low level JVpp APIs
CallbackApiTest - Similar to ControlPingTest, invokes more complex calls (e.g. interface dump) using low level JVpp APIs
CallbackNotificationApiTest - Tests interface notifications using low level JVpp APIs
FutureApiTest - Execution of more complex calls using Future based JVpp facade
FutureApiNotificationTest - Tests interface notifications using Future based JVpp facade
CallbackJVppFacadeTest - Execution of more complex calls using Callback based JVpp facade
CallbackJVppFacadeNotificationTest - Tests interface notifications using Callback based JVpp facade
L2AclTest - Tests L2 ACL creation
CreateSubInterfaceTest - Tests sub-interface creation
OnErrorCallbackTest - simple test failing with onError
