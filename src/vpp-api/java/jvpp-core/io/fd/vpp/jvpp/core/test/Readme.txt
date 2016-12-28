This package contains basic tests for jvpp. To run the tests:

- Make sure VPP is running
- From VPP's build-root/ folder execute:
  - sudo java -cp build-vpp-native/vpp-api/java/jvpp-registry-17.01.jar:build-vpp-native/vpp-api/java/jvpp-core-17.01.jar io.fd.vpp.jvpp.core.test.[test name]

Available tests:
CallbackApiTest - Similar to ControlPingTest, invokes more complex calls (e.g. interface dump) using low level JVpp APIs
CallbackJVppFacadeNotificationTest - Tests interface notifications using Callback based JVpp facade
CallbackJVppFacadeTest - Execution of more complex calls using Callback based JVpp facade
CallbackNotificationApiTest - Tests interface notifications using low level JVpp APIs
ControlPingTest - Simple test executing a single control ping using low level JVpp APIs
CreateSubInterfaceTest - Tests sub-interface creation
FutureApiNotificationTest - Tests interface notifications using Future based JVpp facade
FutureApiTest - Execution of more complex calls using Future based JVpp facade
L2AclTest - Tests L2 ACL creation
LispAdjacencyTest - Tests lisp adjacency creation and read (custom vpe.api type support showcase)
