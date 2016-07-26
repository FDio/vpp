package org.openvpp.jvpp;

import org.openvpp.jvpp.callback.JVppCallback;
import org.openvpp.jvpp.dto.JVppRequest;

public interface JVpp extends AutoCloseable {

    int send(JVppRequest var1) throws VppInvocationException;

    void init(final VppConnection connection, final JVppCallback callback, final long queueAddress, final int clientIndex);

    int ping() throws VppInvocationException;
}
