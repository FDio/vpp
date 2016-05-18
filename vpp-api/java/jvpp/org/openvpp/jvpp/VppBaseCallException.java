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
 * Base exception representing failed operation of JVpp request call
 */
public abstract class VppBaseCallException extends Exception {
    private final String methodName;    // method name causing failure
    private final int ctxId;            // request context identifier
    private final int errorCode;        // result of the request operation

    /**
     * Constructs an VppCallbackException with the specified api method name and error code.
     *
     * @param methodName name of a method, which invocation or execution failed
     * @param ctxId      api request context identifier
     * @param errorCode  negative error code value associated with this failure
     * @throws NullPointerException     if apiMethodName is null
     */
    public VppBaseCallException(final String methodName, final int ctxId, final int errorCode) {
        super(String.format("vppApi.%s failed with error code: %d (ctxId=%d) ", methodName, errorCode, ctxId));
        this.methodName = java.util.Objects.requireNonNull(methodName, "apiMethodName is null!");
        this.ctxId = ctxId;
        this.errorCode = errorCode;
        if(errorCode >= 0) {
            throw new IllegalArgumentException("Error code must be < 0. Was " + errorCode +
                    " for " + methodName + " invocation: " + ctxId);
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
     * Returns api request context identifier.
     *
     * @return value of context identifier
     */
    public int getCtxId() {
        return ctxId;
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
