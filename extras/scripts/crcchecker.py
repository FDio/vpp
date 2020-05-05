#!/usr/bin/env python3

import sys
import os
import json
import argparse
from subprocess import run, PIPE, check_output

rootdir = os.path.dirname(os.path.realpath(__file__)) + '/../..'

def crc_from_apigen(revision, filename):
    apigen_bin = f'{rootdir}/src/tools/vppapigen/vppapigen.py'
    if revision:
        apigen = (f'{apigen_bin} --git-revision {revision} --includedir src '
                  f'--input {filename} CRC')
    else:
        apigen = (f'{apigen_bin} --includedir src --input {filename} CRC')
    rv = run(apigen.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode == 1:
        print(f'Skipping: {revision}:{filename}, {rv}')
        return {}
    if rv.returncode != 0:
        print(f'vppapigen failed for {filename} with command\n {apigen}\n error:',
              rv.stderr.decode('ascii'))
        sys.exit(-2)

    return json.loads(rv.stdout)


def dict_compare(d1, d2):
    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    intersect_keys = d1_keys.intersection(d2_keys)
    added = d1_keys - d2_keys
    removed = d2_keys - d1_keys
    modified = {o: (d1[o], d2[o]) for o in intersect_keys if d1[o]['crc'] != d2[o]['crc']}
    same = set(o for o in intersect_keys if d1[o] == d2[o])
    return added, removed, modified, same


def filelist_from_git_ls():
    filelist = []
    git_ls = 'git ls-files *.api'
    rv = run(git_ls.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode != 0:
        sys.exit(rv.returncode)

    for l in rv.stdout.decode('ascii').split('\n'):
        if len(l):
            filelist.append(l)
    return filelist


def filelist_from_patchset():
    filelist = []
    git_cmd = '((git diff HEAD~1.. --name-only;git ls-files -m) | sort -u)'
    rv = check_output(git_cmd, shell=True)
    for l in rv.decode('ascii').split('\n'):
        if len(l) and os.path.splitext(l)[1] == '.api':
            filelist.append(l)
    return filelist


def report(added, removed, modified, same):
    backwards_incompatible = 0
    for k in added:
        print(f'added: {k}')
    for k in removed:
        print(f'removed: {k}')
    for k in modified.keys():
        oldversion = int(modified[k][1]['version'])
        newversion = int(modified[k][0]['version'])
        if oldversion > 0:
            print(f'modified: {k} (production)')
            backwards_incompatible += 1
        else:
            print(f'modified: {k}')
    return backwards_incompatible


def main():
    parser = argparse.ArgumentParser(description='VPP CRC checker.')
    parser.add_argument('--git-revision',
                        help='Git revision to compare against')
    parser.add_argument('--dump-manifest', action='store_true',
                        help='Dump CRC for all messages')
    parser.add_argument('--check-patchset', action='store_true',
                        help='Dump CRC for all messages')
    parser.add_argument('files', nargs='*')

    args = parser.parse_args()

    # Dump CRC for messages in given files / revision
    if args.dump_manifest:
        files = args.files if args.files else filelist_from_git_ls()
        crcs = {}
        for f in files:
            crcs.update(crc_from_apigen(args.git_revision, f))
        for k, v in crcs.items():
            print(f'{k}: {v}')
        sys.exit(0)

    # Find changes between current patchset and given revision (previous)
    if args.check_patchset:
        if args.git_revision:
            print('Argument git-revision ignored')
        files = filelist_from_patchset()
    else:
        # Find changes between current workspace and revision
        # Find changes between a given file and a revision
        files = args.files if args.files else filelist_from_git_ls()

    revision = args.git_revision if args.git_revision else 'HEAD~1'

    oldcrcs = {}
    newcrcs = {}
    for f in files:
        newcrcs.update(crc_from_apigen(None, f))
        oldcrcs.update(crc_from_apigen(revision, f))

    added, removed, modified, same = dict_compare(newcrcs, oldcrcs)
    backwards_incompatible = report(added, removed, modified, same)

    if args.check_patchset:
        if backwards_incompatible:
            # alert on changing production API
            print("crcchecker: Changing production APIs in an incompatible way", file=sys.stderr)
            sys.exit(-1)
        else:
            print('*' * 67)
            print('* VPP CHECKAPI SUCCESSFULLY COMPLETED')
            print('*' * 67)

if __name__ == '__main__':
    main()
