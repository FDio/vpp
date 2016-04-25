package org.openvpp.jvpp;

public interface VppConnection extends AutoCloseable {

    /**
     * Check if this instance connection is active.
     *
     * @throws IllegalStateException if this instance was disconnected.
     */
    void checkActive() throws IllegalStateException;

    /**
     * Closes Vpp connection.
     */
    @Override
    void close();
}
