package org.openvpp.jvpp.test;

import java.io.PrintStream;
import org.openvpp.jvpp.dto.SwInterfaceSetFlags;
import org.openvpp.jvpp.dto.SwInterfaceSetFlagsNotification;
import org.openvpp.jvpp.dto.WantInterfaceEvents;

final class NotificationUtils {

    private NotificationUtils() {}

    static PrintStream printNotification(final SwInterfaceSetFlagsNotification msg) {
        return System.out.printf("Received interface notification: ifc: %d, admin: %d, link: %d, deleted: %d\n",
            msg.swIfIndex, msg.adminUpDown, msg.linkUpDown, msg.deleted);
    }

    static SwInterfaceSetFlags getChangeInterfaceState() {
        final SwInterfaceSetFlags swInterfaceSetFlags = new SwInterfaceSetFlags();
        swInterfaceSetFlags.swIfIndex = 0;
        swInterfaceSetFlags.adminUpDown = 1;
        swInterfaceSetFlags.deleted = 0;
        return swInterfaceSetFlags;
    }

    static WantInterfaceEvents getEnableInterfaceNotificationsReq() {
        WantInterfaceEvents wantInterfaceEvents = new WantInterfaceEvents();
        wantInterfaceEvents.pid = 1;
        wantInterfaceEvents.enableDisable = 1;
        return wantInterfaceEvents;
    }

    static WantInterfaceEvents getDisableInterfaceNotificationsReq() {
        WantInterfaceEvents wantInterfaceEvents = new WantInterfaceEvents();
        wantInterfaceEvents.pid = 1;
        wantInterfaceEvents.enableDisable = 0;
        return wantInterfaceEvents;
    }
}
