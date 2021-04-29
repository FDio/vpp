#!/usr/bin/env python3

import sys
import json

objects = json.load(sys.stdin)

for i in range(len(objects) - 1, -1, -1):
    obj = objects[i]

    # Remove everything except .c files
    if not obj["file"].endswith(".c"):
        objects.remove(obj)
        continue

    # remove duplicates introduced my multiarch
    if "CLIB_MARCH_VARIANT" in obj["command"]:
        objects.remove(obj)
        continue

    # remove if there is no command
    if obj["command"] == "":
        objects.remove(obj)
        continue

    # remove ccache prefix
    s = str.split(obj["command"])
    if s[0] == "ccache":
        s.remove(s[0])
        s[0] = s[0].split("/")[-1]
    obj["command"] = " ".join(s)

json.dump(objects, sys.stdout, indent=2)
