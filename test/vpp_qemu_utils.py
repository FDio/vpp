#!/usr/bin/env python

# Utility functions for QEMU tests ##

import subprocess


def create_namespace(ns):
    """create one or more namespaces.

    arguments:
    ns -- a string value or an iterable of namespace names
    """
    if isinstance(ns, str):
        namespaces = [ns]
    else:
        namespaces = ns
    try:
        for namespace in namespaces:
            subprocess.run(["ip", "netns", "add", namespace])
    except subprocess.CalledProcessError as e:
        raise Exception("Error creating namespace:", e.output)


def delete_namespace(ns):
    """delete one or more namespaces.

    arguments:
    ns -- a string value or an iterable of namespace names
    """
    if isinstance(ns, str):
        namespaces = [ns]
    else:
        namespaces = ns
    try:
        for namespace in namespaces:
            subprocess.run(["ip", "netns", "del", namespace])
    except subprocess.CalledProcessError as e:
        raise Exception("Error deleting namespace:", e.output)


def list_namespace(ns):
    """List the IP address of a namespace"""
    try:
        subprocess.run(["ip", "netns", "exec", ns, "ip", "addr"])
    except subprocess.CalledProcessError as e:
        raise Exception("Error listing namespace IP:", e.output)
