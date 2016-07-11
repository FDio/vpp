package org.openvpp.jvpp.notification;

/**
 * Base class for notification aware JVpp facades
 */
public abstract class NotificationRegistryProviderContext implements NotificationRegistryProvider {

    // FIXME make it generic: NotificationRegistryImpl is generated
    // private final NotificationRegistryImpl notificationRegistry = new NotificationRegistryImpl();

    public final NotificationRegistry getNotificationRegistry() {
        return null; //notificationRegistry;
    }

    /**
     * Get instance of notification callback. Can be used to propagate notifications from JVpp facade
     */
    // FIXME
    // protected final GlobalNotificationCallback getNotificationCallback() {
    //    return notificationRegistry;
    //}
}
