/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.fd.vpp.jvpp;

import java.util.HashMap;
import java.util.Map;

/**
 * Base exception representing failed operation of JVpp request call
 */
public abstract class VppBaseCallException extends Exception {
    private final String methodName;
    private final int errorCode;

    private static Map<Integer, String> getErrorMsgMap() {
        Map<Integer, String> msg_map = new HashMap<>();

        msg_map.put(-1, "Unspecified Error");
        msg_map.put(-2, "Invalid sw_if_index");
        msg_map.put(-3, "No such FIB / VRF");
        msg_map.put(-4, "No such inner FIB / VRF");
        msg_map.put(-5, "No such label");
        msg_map.put(-6, "No such entry");
        msg_map.put(-7, "Invalid value");
        msg_map.put(-8, "Invalid value #2");
        msg_map.put(-9, "Unimplemented");
        msg_map.put(-10, "Invalid sw_if_index #2");
        msg_map.put(-11, "System call error #1");
        msg_map.put(-12, "System call error #2");
        msg_map.put(-13, "System call error #3");
        msg_map.put(-14, "System call error #4");
        msg_map.put(-15, "System call error #5");
        msg_map.put(-16, "System call error #6");
        msg_map.put(-17, "System call error #7");
        msg_map.put(-18, "System call error #8");
        msg_map.put(-19, "System call error #9");
        msg_map.put(-20, "System call error #10");
        msg_map.put(-30, "Feature disabled by configuration");
        msg_map.put(-31, "Invalid registration");
        msg_map.put(-50, "Next hop not in FIB");
        msg_map.put(-51, "Unknown destination");
        msg_map.put(-52, "Prefix matches next hop");
        msg_map.put(-53, "Next hop not found (multipath)");
        msg_map.put(-54, "No matching interface for probe");
        msg_map.put(-55, "Invalid VLAN");
        msg_map.put(-56, "VLAN subif already exists");
        msg_map.put(-57, "Invalid src address");
        msg_map.put(-58, "Invalid dst address");
        msg_map.put(-59, "Address length mismatch");
        msg_map.put(-60, "Address not found for interface");
        msg_map.put(-61, "Address not link-local");
        msg_map.put(-62, "ip6 not enabled");
        msg_map.put(10, "Operation in progress");
        msg_map.put(-63, "No such graph node");
        msg_map.put(-64, "No such graph node #2");
        msg_map.put(-65, "No such table");
        msg_map.put(-66, "No such table #2");
        msg_map.put(-67, "No such table #3");
        msg_map.put(-68, "Subinterface already exists");
        msg_map.put(-69, "Subinterface creation failed");
        msg_map.put(-70, "Invalid memory size requested");
        msg_map.put(-71, "Invalid interface");
        msg_map.put(-72, "Invalid number of tags for requested operation");
        msg_map.put(-73, "Invalid argument");
        msg_map.put(-74, "Unexpected interface state");
        msg_map.put(-75, "Tunnel already exists");
        msg_map.put(-76, "Invalid decap-next");
        msg_map.put(-77, "Response not ready");
        msg_map.put(-78, "Not connected to the data plane");
        msg_map.put(-79, "Interface already exists");
        msg_map.put(-80, "Operation not allowed on slave of BondEthernet");
        msg_map.put(-81, "Value already exists");
        msg_map.put(-82, "Source and destination are the same");
        msg_map.put(-83, "IP6 multicast address required");
        msg_map.put(-84, "Segement routing policy name required");
        msg_map.put(-85, "Not running as root");
        msg_map.put(-86, "Connection to the data plane already exists");
        msg_map.put(-87, "Unsupported JNI version");
        msg_map.put(-88, "Failed to attach to Java thread");
        msg_map.put(-89, "Invalid worker thread");
        msg_map.put(-90, "LISP is disabled");
        msg_map.put(-91, "Classify table not found");
        msg_map.put(-92, "Unsupported LSIP EID type");
        msg_map.put(-93, "Cannot create pcap file");
        msg_map.put(-94, "Invalid adjacency type for this operation");
        msg_map.put(-95, "Operation would exceed configured capacity of ranges");
        msg_map.put(-96, "Operation would exceed capacity of number of ports");
        msg_map.put(-97, "Invalid address family");
        msg_map.put(-98, "Invalid sub-interface sw_if_index");
        msg_map.put(-99, "Table too big");
        msg_map.put(-100, "Cannot enable/disable feature");
        msg_map.put(-101, "Duplicate BFD object");
        msg_map.put(-102, "No such BFD object");
        msg_map.put(-103, "BFD object in use");
        msg_map.put(-104, "BFD feature not supported");
        msg_map.put(-105, "Address in use");
        msg_map.put(-106, "Address not in use");
        msg_map.put(-107, "Queue full");
        msg_map.put(-108, "Unknown URI type");
        msg_map.put(-109, "URI FIFO segment create failed");
        msg_map.put(-110, "RLOC address is local");
        msg_map.put(-111, "BFD object cannot be manipulated at this time");
        msg_map.put(-112, "Invalid GPE mode");
        msg_map.put(-113, "LISP GPE entries are present");
        msg_map.put(-114, "Address found for interface");
        msg_map.put(-115, "Session failed to connect");
        msg_map.put(-116, "Entry already exists");
        msg_map.put(-117, "svm segment create fail");
        msg_map.put(-118, "application not attached");
        msg_map.put(-119, "Bridge domain already exists");
        msg_map.put(-120, "Bridge domain has member interfaces");
        msg_map.put(-121, "Bridge domain 0 can't be deleted/modified");
        msg_map.put(-122, "Bridge domain ID exceed 16M limit");
        msg_map.put(-123, "Unsupported");
        return msg_map;
    }

    /**
     * Constructs an VppCallbackException with the specified api method name and error code.
     *
     * @param methodName name of a method, which invocation or execution failed
     * @param errorCode  negative error code value associated with this failure
     * @throws NullPointerException     if apiMethodName is null
     */
    public VppBaseCallException(final String methodName, final int errorCode) {
        super(String.format("vppApi.%s failed with error code: %d", methodName, errorCode));
        this.methodName = java.util.Objects.requireNonNull(methodName, "apiMethodName is null!");
        this.errorCode = errorCode;
        if(errorCode >= 0) {
            throw new IllegalArgumentException("Error code must be < 0. Was " + errorCode +
                    " for " + methodName );
        }
    }

    /**
     * Constructs an VppCallbackException with the specified api method name, error description and error code.
     *
     * @param methodName name of a method, which invocation or execution failed
     * @param message    description of error reason
     * @param errorCode  negative error code value associated with this failure
     * @throws NullPointerException     if apiMethodName is null
     */
    public VppBaseCallException(final String methodName, final String message, final int errorCode) {
        super(String.format("vppApi.%s failed: %s (error code: %d)", methodName,message, errorCode));
        this.methodName = java.util.Objects.requireNonNull(methodName, "apiMethodName is null!");
        this.errorCode = errorCode;
        if(errorCode >= 0) {
            throw new IllegalArgumentException("Error code must be < 0. Was " + errorCode +
                    " for " + methodName );
        }
    }

    /**
     * Returns  name of a method, which invocation failed.
     *
     * @return method name
     */
    public String getMethodName() {
        return methodName;
    }

    /**
     * Returns the error code associated with this failure.
     *
     * @return a negative integer error code
     */
    public int getErrorCode() {
        return errorCode;
    }
}
