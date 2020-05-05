#!/usr/bin/env python3

import sys
import os
import argparse
from subprocess import run, PIPE

def crc_from_apigen(repo, filename):
    apigen = f'src/tools/vppapigen/vppapigen.py --includedir {repo}/src --input {repo}/{filename} CRC'
    rv = run(apigen.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode != 0:
        print('RV2', rv)
        sys.exit(rv.returncode)
    t = {}
    for l in rv.stdout.decode('ascii').split('\n'):
        if len(l):
            name, crc = l.split(':')
            t[name] = crc
    return t

def dict_compare(d1, d2):
    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    intersect_keys = d1_keys.intersection(d2_keys)
    added = d1_keys - d2_keys
    removed = d2_keys - d1_keys
    modified = {o : (d1[o], d2[o]) for o in intersect_keys if d1[o] != d2[o]}
    same = set(o for o in intersect_keys if d1[o] == d2[o])
    return added, removed, modified, same

def main():
    parser = argparse.ArgumentParser(description='VPP CRC checker.')
    parser.add_argument('--old', dest='old',
                        help='root of repository to compare against')
    parser.add_argument('apifile')

    args = parser.parse_args()

    # Generate CRC manifest for old file
    # Generate CRC manifest for current file
    old = crc_from_apigen(args.old, args.apifile)
    new = crc_from_apigen('.', args.apifile)

    # Compare the two
    added, removed, modified, same = dict_compare(new, old)
    for k in added:
        print(f'added: {k}')
    for k in removed:
        print(f'removed: {k}')
    for k in modified.keys():
        print(f'modified: {k}')

    if modified:
        os.exit(-1)

if __name__ == '__main__':
    main()
