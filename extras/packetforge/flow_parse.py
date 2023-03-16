# Copyright (c) 2022 Intel and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys, getopt
import packetforge


def Main(argv):
    file_flag = False
    operation = None
    try:
        opts, args = getopt.getopt(
            argv,
            "hf:p:a:i:I:",
            [
                "help",
                "show",
                "file=",
                "pattern=",
            ],
        )
    except getopt.GetoptError:
        print("flow_parse.py --show -f <file> -p <pattern>")
        sys.exit()
    for opt, arg in opts:
        if opt == "-h":
            print("flow_parse.py --show -f <file> -p <pattern>")
            sys.exit()
        elif opt == "--show":
            operation = "show"
        elif opt in ("-f", "--file"):
            json_file = arg
            file_flag = True
        elif opt in ("-p", "--pattern") and not file_flag:
            pattern = arg

    if operation == None:
        print("Error: Please choose the operation: show")
        sys.exit()

    if not file_flag:
        result = packetforge.Forge(pattern, None, False, True)
    else:
        result = packetforge.Forge(json_file, None, True, True)

    return result


if __name__ == "__main__":
    # Parse the arguments
    my_flow = Main(sys.argv[1:])

    print(my_flow)

# command example:
# python flow_parse.py --show -p "mac()/ipv4(src=1.1.1.1,dst=2.2.2.2)/udp()"
