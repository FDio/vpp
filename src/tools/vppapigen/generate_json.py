#!/usr/bin/env python3
#  Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import argparse
import pathlib
import subprocess
BASE_DIR = subprocess.check_output('git rev-parse --show-toplevel',
                                   shell=True).strip().decode()
vppapigen_bin = pathlib.Path('/usr/local/bin/vppapigen.py').as_posix()

src_dir_depth = 3
output_path = pathlib.Path(
    '%s/build-root/install-vpp-native/vpp/share/vpp/api/' % BASE_DIR)
output_path_debug = pathlib.Path(
    '%s/build-root/install-vpp_debug-native/vpp/share/vpp/api/' % BASE_DIR)

output_dir_map = {
    'plugins': 'plugins',
    'vlibmemory': 'core',
    'vnet': 'core',
    'vlib': 'core',
    'vpp': 'core',
}


def api_search_globs(src_dir):
    globs = []
    for g in output_dir_map:
        globs.extend(list(src_dir.glob('%s/**/*.api' % g)))
    return globs


def api_files(src_dir):
    print("Searching '%s' for .api files." % src_dir.as_posix())
    return [x for x in api_search_globs(src_dir)]


def vppapigen(vppapigen_bin, output_path, src_dir, src_file):
    try:
        subprocess.check_output(
            [vppapigen_bin, '--includedir', src_dir.as_posix(),
             '--input', src_file.as_posix(), 'JSON',
             '--output', '%s/%s/%s.json' % (
                 output_path,
                 output_dir_map[src_file.as_posix().split('/')[
                     src_dir_depth + BASE_DIR.count('/') - 1]],
                 src_file.name)])
    except KeyError:
        print('src_file: %s' % src_file)
        raise


def main():
    cliparser = argparse.ArgumentParser(
        description='VPP API JSON definition generator')
    cliparser.add_argument('--srcdir', action='store',
                           default='%s/src' % BASE_DIR),
    cliparser.add_argument('--output', action='store',
                           help='directory to store files'),
    cliparser.add_argument('--debug-target', action='store_true',
                           default=False,
                           help="'True' if -debug target"),
    args = cliparser.parse_args()

    src_dir = pathlib.Path(args.srcdir)
    output_target = output_path_debug if args.debug_target else output_path

    if args.output:
        output_dir = pathlib.Path(args.output)
    else:
        output_dir = pathlib.Path(output_target)

    for d in output_dir_map.values():
        output_dir.joinpath(d).mkdir(exist_ok=True, parents=True)

    for f in output_dir.glob('**/*.api.json'):
        f.unlink()

    for f in api_files(src_dir):
        vppapigen(vppapigen_bin, output_dir, src_dir, f)
    print('json files written to: %s/.' % output_dir)


if __name__ == '__main__':
    main()
