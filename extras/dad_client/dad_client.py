#!/usr/bin/env python3
"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Cisco and/or its affiliates.

IPv6 DAD Client Example in Python

This example demonstrates how to use the VPP Python API to:
- Enable/configure IPv6 DAD
- Register for DAD event notifications
- Monitor address state transitions (TENTATIVE -> PREFERRED/DUPLICATE)
- Handle duplicate address detection scenarios
"""

import sys
import signal
import time
from vpp_papi import VPPApiClient

# DAD States (from ip6_dad.h)
DAD_STATE_IDLE = 0
DAD_STATE_TENTATIVE = 1
DAD_STATE_PREFERRED = 2
DAD_STATE_DUPLICATE = 3

STATE_NAMES = {
    DAD_STATE_IDLE: "IDLE",
    DAD_STATE_TENTATIVE: "TENTATIVE",
    DAD_STATE_PREFERRED: "PREFERRED",
    DAD_STATE_DUPLICATE: "DUPLICATE"
}

class DADClient:
    """Simple DAD event monitoring client"""

    def __init__(self):
        self.vpp = None
        self.running = True

    def connect(self):
        """Connect to VPP"""
        print("Connecting to VPP...")
        self.vpp = VPPApiClient(apifiles=[/usr/share/vpp/api])
        self.vpp.connect("dad_client")
        print("✓ Connected to VPP")

    def disconnect(self):
        """Disconnect from VPP"""
        if self.vpp:
            print("\nDisconnecting from VPP...")
            self.vpp.disconnect()
            print("✓ Disconnected")

    def enable_dad(self, transmits=1, delay=1.0):
        """
        Enable DAD with configuration

        Args:
            transmits: Number of NS transmissions (1-10)
            delay: Delay between transmissions in seconds (0.1-10.0)
        """
        print(f"\nEnabling DAD (transmits={transmits}, delay={delay}s)...")
        try:
            reply = self.vpp.api.ip6_dad_enable_disable(
                enable=True,
                dad_transmits=transmits,
                dad_retransmit_delay=delay
            )
            if reply.retval == 0:
                print("✓ DAD enabled")
            else:
                print(f"✗ DAD enable failed: retval={reply.retval}")
                return False
        except Exception as e:
            print(f"✗ DAD enable error: {e}")
            return False
        return True

    def register_for_events(self):
        """Register to receive DAD event notifications"""
        print("\nRegistering for DAD events...")
        try:
            reply = self.vpp.api.want_ip6_dad_events(enable=True)
            if reply.retval == 0:
                print("✓ Registered for DAD events")
            else:
                print(f"✗ Registration failed: retval={reply.retval}")
                return False
        except Exception as e:
            print(f"✗ Registration error: {e}")
            return False
        return True

    def handle_dad_event(self, event):
        """
        Handle DAD event notification

        Args:
            event: ip6_dad_event message from VPP
        """
        state = event.state
        state_name = STATE_NAMES.get(state, "UNKNOWN")
        sw_if_index = event.sw_if_index
        address = event.address
        dad_count = event.dad_count
        dad_transmits = event.dad_transmits

        print(f"\n📢 DAD Event Received:")
        print(f"   Interface : sw_if_index {sw_if_index}")
        print(f"   Address   : {address}")
        print(f"   State     : {state_name} ({state})")
        print(f"   Progress  : {dad_count}/{dad_transmits}")

        # Handle different states
        if state == DAD_STATE_TENTATIVE:
            if dad_count == 0:
                print(f"   → Initial TENTATIVE state (before first NS)")
            else:
                print(f"   → TENTATIVE after NS #{dad_count}")

        elif state == DAD_STATE_PREFERRED:
            print(f"   → SUCCESS: Address is now usable (PREFERRED)")
            print(f"   ✓ No duplicate detected after {dad_count} probes")

        elif state == DAD_STATE_DUPLICATE:
            print(f"   → FAILURE: Duplicate address detected!")
            print(f"   ⚠ IMPORTANT: IP address REMAINS CONFIGURED but in DUPLICATE state")
            print(f"   ⚠ Application should decide what to do:")
            print(f"      1. Log error / send alert")
            print(f"      2. Generate new IPv6 address (e.g., privacy extensions)")
            print(f"      3. Remove address manually")
            print(f"      4. Disable interface")
            print(f"      5. Failover to backup address")

            # Example: Application-level decision
            print(f"\n   📋 Suggested action: Generate new address with privacy extensions")

    def monitor_events(self, duration=30):
        """
        Monitor DAD events for specified duration

        Args:
            duration: Duration in seconds to monitor (0 = infinite)
        """
        print(f"\n👀 Monitoring DAD events" + (f" for {duration}s..." if duration > 0 else "..."))
        print("   (Press Ctrl+C to stop)")

        start_time = time.time()

        try:
            while self.running:
                # Check for events
                try:
                    events = self.vpp.message_queue.get(timeout=1.0)

                    # Handle events
                    if hasattr(events, __iter__):
                        for event in events:
                            if hasattr(event, _fields) and state in event._fields:
                                self.handle_dad_event(event)
                    elif hasattr(events, _fields) and state in events._fields:
                        self.handle_dad_event(events)

                except:
                    # Timeout or no events
                    pass

                # Check duration
                if duration > 0 and (time.time() - start_time) >= duration:
                    break

        except KeyboardInterrupt:
            print("\n\n⚠ Interrupted by user")

        print("\n✓ Monitoring stopped")

    def run(self):
        """Main execution"""
        print("="*70)
        print("  IPv6 DAD Client Example (Python)")
        print("="*70)

        try:
            # Connect to VPP
            self.connect()

            # Enable DAD with 2 transmits, 1.0s delay
            if not self.enable_dad(transmits=2, delay=1.0):
                return 1

            # Register for events
            if not self.register_for_events():
                return 1

            # Monitor events for 30 seconds
            # In real application, this would run continuously
            self.monitor_events(duration=30)

        except Exception as e:
            print(f"\n✗ Error: {e}")
            return 1
        finally:
            self.disconnect()

        print("\n" + "="*70)
        print("  Example completed")
        print("="*70)
        return 0


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\nReceived signal, exiting...")
    sys.exit(0)


if __name__ == "__main__":
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Run client
    client = DADClient()
    sys.exit(client.run())
