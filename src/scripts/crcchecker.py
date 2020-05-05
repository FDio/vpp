#!/usr/bin/env python3

import sys
import os
import argparse
from subprocess import run, PIPE, check_output

rootdir = os.path.dirname(os.path.realpath(__file__)) + '/..'


def crc_from_apigen(revision, filename):
    if revision:
        apigen = (f'{rootdir}/tools/vppapigen/vppapigen.py '
                  '--git-revision {revision} --includedir src '
                  '--input {filename} CRC')
    else:
        apigen = (f'{rootdir}/tools/vppapigen/vppapigen.py '
                  '--includedir src --input {filename} CRC')
    rv = run(apigen.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode != 0:
        print(f'Skipping: {revision}:{filename}')
        return {}
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
    modified = {o: (d1[o], d2[o]) for o in intersect_keys if d1[o] != d2[o]}
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
    print('RV', rv)
    for l in rv.decode('ascii').split('\n'):
        if len(l) and os.path.splitext(l)[1] == '.api':
            filelist.append(l)
    return filelist


def report(args):
    added, removed, modified, same = args
    for k in added:
        print(f'added: {k}')
    for k in removed:
        print(f'removed: {k}')
    for k in modified.keys():
        print(f'modified: {k}')


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
    report(dict_compare(newcrcs, oldcrcs))


if __name__ == '__main__':
    main()
