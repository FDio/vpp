#!/usr/bin/env python

# Utility functions for QEMU tests ##

import subprocess


def create_namespace(ns):
    try:
        subprocess.run(["ip", "netns", "add", ns])
    except subprocess.CalledProcessError as e:
        raise Exception("Error creating namespace:", e.output)


def list_namespace(ns):
    """List the IP address of a namespace"""
    try:
        subprocess.run(["ip", "netns", "exec", ns, "ip", "addr"])
    except subprocess.CalledProcessError as e:
        raise Exception("Error listing namespace IP:", e.output)
