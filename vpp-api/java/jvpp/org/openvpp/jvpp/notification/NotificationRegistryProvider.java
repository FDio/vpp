package org.openvpp.jvpp.notification;

public abstract class NotificationRegistryProvider {

    private final NotificationRegistryImpl notificationRegistry = new NotificationRegistryImpl();

    public final NotificationRegistry getNotificationRegistry() {
        return notificationRegistry;
    }

    protected final GlobalNotificationCallback getNotificationCallback() {
        return notificationRegistry;
    }
}
