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
 * Callback Exception representing failed operation of JVpp request call
 */
public class VppCallbackException extends VppBaseCallException {

    /**
     * Constructs an VppCallbackException with the specified api method name and error code.
     *
     * @param methodName method name that failed to invoke
     * @param ctxId      api request context identifier
     * @param errorCode  negative error code value associated with this failure
     * @throws NullPointerException     if apiMethodName is null
     */
    public VppCallbackException(final String methodName, final int ctxId, final int errorCode ){
        super(methodName, ctxId, errorCode);
    }
}
