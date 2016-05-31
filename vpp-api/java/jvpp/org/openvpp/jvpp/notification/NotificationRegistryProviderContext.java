package org.openvpp.jvpp.notification;

/**
 * Base class for notification aware JVpp facades
 */
public abstract class NotificationRegistryProviderContext implements NotificationRegistryProvider {

    private final NotificationRegistryImpl notificationRegistry = new NotificationRegistryImpl();

    public final NotificationRegistry getNotificationRegistry() {
        return notificationRegistry;
    }

    /**
     * Get instance of notification callback. Can be used to propagate notifications from JVpp facade
     */
    protected final GlobalNotificationCallback getNotificationCallback() {
        return notificationRegistry;
    }
}
