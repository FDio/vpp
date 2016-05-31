package org.openvpp.jvpp.notification;

/**
 * Provides notification registry
 */
public interface NotificationRegistryProvider {

    /**
     * Get current notification registry instance
     */
    NotificationRegistry getNotificationRegistry();
}
