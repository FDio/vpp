#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco and/or its affiliates.
"""
IPv6 DAD Client Example using VPP Python API

This example demonstrates how to:
- Connect to VPP using vpp-papi
- Enable and configure DAD
- Register for DAD event notifications
- Monitor all DAD state transitions (TENTATIVE, PREFERRED, DUPLICATE)
- Handle duplicate detection events

Requirements:
    pip3 install vpp-papi

Usage:
    sudo ./dad_client.py
"""

import sys
import time
from vpp_papi import VPPApiClient


class DADClient:
    """VPP IPv6 DAD Event Monitor"""

    # DAD state constants from VPP API
    DAD_STATE_IDLE = 0
    DAD_STATE_TENTATIVE = 1
    DAD_STATE_PREFERRED = 2
    DAD_STATE_DUPLICATE = 3

    STATE_NAMES = {
        DAD_STATE_IDLE: "IDLE",
        DAD_STATE_TENTATIVE: "TENTATIVE",
        DAD_STATE_PREFERRED: "PREFERRED",
        DAD_STATE_DUPLICATE: "DUPLICATE",
    }

    def __init__(self):
        """Initialize VPP API client"""
        self.vpp = None
        self.running = False

    def connect(self):
        """Connect to VPP API"""
        print("Connecting to VPP...")
        try:
            self.vpp = VPPApiClient(apifiles=["/usr/share/vpp/api"])
            self.vpp.connect("dad_client")
            print("✓ Connected to VPP")
            return True
        except Exception as e:
            print(f"✗ Failed to connect to VPP: {e}")
            return False

    def disconnect(self):
        """Disconnect from VPP API"""
        if self.vpp:
            try:
                # Unregister from events before disconnecting
                self.vpp.api.want_ip6_dad_events(enable=False)
            except:
                pass
            self.vpp.disconnect()
            print("Disconnected from VPP")

    def enable_dad(self, transmits=1, delay=1.0):
        """
        Enable and configure DAD

        Args:
            transmits: Number of NS probes to send (default: 1, RFC 4862)
            delay: Delay between probes in seconds (default: 1.0, RFC 4862)
        """
        print(f"\nEnabling DAD (transmits={transmits}, delay={delay}s)...")
        try:
            reply = self.vpp.api.ip6_dad_enable_disable(
                enable=True, dad_transmits=transmits, dad_retransmit_delay=delay
            )
            if reply.retval == 0:
                print("✓ DAD enabled successfully")
                return True
            else:
                print(f"✗ Failed to enable DAD: retval={reply.retval}")
                return False
        except Exception as e:
            print(f"✗ Exception enabling DAD: {e}")
            return False

    def register_for_events(self):
        """Register to receive DAD event notifications"""
        print("\nRegistering for DAD event notifications...")
        try:
            reply = self.vpp.api.want_ip6_dad_events(
                enable=True, pid=0  # 0 = use current connection
            )
            if reply.retval == 0:
                print("✓ Registered for DAD events")
                return True
            else:
                print(f"✗ Failed to register: retval={reply.retval}")
                return False
        except Exception as e:
            print(f"✗ Exception registering for events: {e}")
            return False

    def handle_dad_event(self, event):
        """
        Handle a DAD event notification

        Args:
            event: ip6_dad_event message from VPP
        """
        # Extract event details
        sw_if_index = event.sw_if_index
        address = str(event.address)
        state = event.state
        dad_count = event.dad_count

        state_name = self.STATE_NAMES.get(state, f"UNKNOWN({state})")

        # Format output
        timestamp = time.strftime("%H:%M:%S")
        print(f"\n[{timestamp}] DAD Event:")
        print(f"  Interface:  sw_if_index={sw_if_index}")
        print(f"  Address:    {address}")
        print(f"  State:      {state_name}")
        print(f"  DAD Count:  {dad_count}")

        # Provide interpretation based on state
        if state == self.DAD_STATE_TENTATIVE:
            if dad_count == 0:
                print("  → DAD process started (initial TENTATIVE)")
            else:
                print(f"  → NS probe #{dad_count} sent, no conflict detected yet")

        elif state == self.DAD_STATE_PREFERRED:
            print("  → ✓ DAD succeeded! Address is PREFERRED and ready to use")

        elif state == self.DAD_STATE_DUPLICATE:
            print("  → ✗ DUPLICATE DETECTED!")
            print("  → ⚠️  Address remains configured but should not be used")
            print("  → Application must decide: remove address or take other action")

    def monitor_events(self, duration=30):
        """
        Monitor DAD events for a specified duration

        Args:
            duration: How long to monitor in seconds (default: 30)
        """
        print(f"\n{'='*60}")
        print(f"Monitoring DAD events for {duration} seconds...")
        print("Add IPv6 addresses to interfaces to trigger DAD events")
        print(f"{'='*60}")

        self.running = True
        start_time = time.time()

        try:
            while self.running and (time.time() - start_time) < duration:
                # Poll for events with timeout
                try:
                    event = self.vpp.read(timeout=1)
                    if event:
                        # Check if it's a DAD event
                        if hasattr(event, "name") and event.name == "ip6_dad_event":
                            self.handle_dad_event(event)
                except TimeoutError:
                    # No events received in this interval
                    pass
                except Exception as e:
                    print(f"Error reading event: {e}")
                    break

            elapsed = time.time() - start_time
            print(f"\n{'='*60}")
            print(f"Monitoring stopped after {elapsed:.1f} seconds")
            print(f"{'='*60}")

        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            self.running = False

    def show_configuration(self):
        """Display current DAD configuration"""
        print("\nQuerying DAD configuration...")
        try:
            reply = self.vpp.api.ip6_dad_dump()
            if hasattr(reply, "enabled"):
                print(f"  Enabled:           {reply.enabled}")
                print(f"  Transmits:         {reply.dad_transmits}")
                print(f"  Retransmit Delay:  {reply.dad_retransmit_delay}s")
            else:
                print("  No configuration information available")
        except Exception as e:
            print(f"  Failed to query configuration: {e}")


def main():
    """Main program"""
    print("=" * 60)
    print("VPP IPv6 DAD Event Monitor")
    print("=" * 60)

    # Create client
    client = DADClient()

    # Connect to VPP
    if not client.connect():
        sys.exit(1)

    try:
        # Enable DAD with RFC 4862 defaults (1 transmit, 1 second delay)
        if not client.enable_dad(transmits=1, delay=1.0):
            client.disconnect()
            sys.exit(1)

        # Show current configuration
        client.show_configuration()

        # Register for event notifications
        if not client.register_for_events():
            client.disconnect()
            sys.exit(1)

        # Monitor events for 30 seconds
        # During this time, you can add IPv6 addresses in another terminal:
        #   vppctl set interface ip address <interface> <ipv6-address>
        client.monitor_events(duration=30)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
    finally:
        # Cleanup
        client.disconnect()

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
