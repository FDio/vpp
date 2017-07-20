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


/**
 * Base exception representing failed operation of JVpp request call
 */
public abstract class VppBaseCallException extends Exception {
    private final String methodName;
    private final int errorCode;

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
