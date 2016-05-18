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

package org.openvpp.jvpp;

/**
 * Exception thrown when Vpp jAPI method invocation failed.
 */
public class VppInvocationException extends Exception {
    private final String methodName;        // request name causing exception thrown
    private final int errorCode;            // result of the operation

    /**
     * Constructs an VppApiInvocationFailedException with the specified api method name and error code.
     *
     * @param methodName method name that failed to invoke
     * @param errorCode  negative error code value associated with this failure
     * @throws NullPointerException     if apiMethodName is null
     */
    public VppInvocationException(final String methodName, final int errorCode) {
        super(String.format("vppApi.%s failed with error code: %d ", methodName, errorCode));
        this.methodName = java.util.Objects.requireNonNull(methodName, "apiMethodName is null!");
        this.errorCode = errorCode;
    }

    /**
     * Returns method name that failed to invoke.
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
