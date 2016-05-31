package org.openvpp.jvpp.notification;

import java.io.Closeable;
import org.openvpp.jvpp.callback.SwInterfaceSetFlagsNotificationCallback;

public interface NotificationRegistry extends Closeable, SwInterfaceSetFlagsNotificationCallback {

    AutoCloseable registerSwInterfaceSetFlagsNotificationCallback(SwInterfaceSetFlagsNotificationCallback callback);

    @Override
    void close();
}
