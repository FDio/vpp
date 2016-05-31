package org.openvpp.jvpp.notification;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.openvpp.jvpp.callback.JVppCallback;
import org.openvpp.jvpp.callback.SwInterfaceSetFlagsNotificationCallback;
import org.openvpp.jvpp.dto.JVppNotification;
import org.openvpp.jvpp.dto.SwInterfaceSetFlagsNotification;

public final class GenericNotificationRegistry implements NotificationRegistry {

    private final ConcurrentMap<Class<? extends JVppNotification>, JVppCallback> registeredCallbacks =
        new ConcurrentHashMap<>();

    public AutoCloseable registerSwInterfaceSetFlagsNotificationCallback(final SwInterfaceSetFlagsNotificationCallback callback){
        if(null != registeredCallbacks.putIfAbsent(SwInterfaceSetFlagsNotification.class, callback)){
            throw new IllegalArgumentException("Callback for " + SwInterfaceSetFlagsNotificationCallback.class +
                "notification already registered");
        }
        return () -> registeredCallbacks.remove(SwInterfaceSetFlagsNotification.class);
    }

    @Override
    public void onSwInterfaceSetFlagsNotification(
        final SwInterfaceSetFlagsNotification swInterfaceSetFlagsNotification) {
        final JVppCallback jVppCallback = registeredCallbacks.get(SwInterfaceSetFlagsNotification.class);
        if (null != jVppCallback) {
            ((SwInterfaceSetFlagsNotificationCallback) registeredCallbacks
                .get(SwInterfaceSetFlagsNotification.class))
                .onSwInterfaceSetFlagsNotification(swInterfaceSetFlagsNotification);
        }

//        LOG.warn
    }

    @Override
    public void close() {
        registeredCallbacks.clear();
    }
}
