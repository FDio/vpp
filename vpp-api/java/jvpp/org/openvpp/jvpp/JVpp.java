package org.openvpp.jvpp;

import org.openvpp.jvpp.dto.JVppRequest;

public interface JVpp extends AutoCloseable {

    int send(JVppRequest var1) throws VppInvocationException;

    void close();

    void init(final long queueAddress, final int clientIndex);
}
