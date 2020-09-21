#!/usr/bin/env python3

import sys
import os
import json
import argparse
from subprocess import run, PIPE, check_output, CalledProcessError

rootdir = os.path.dirname(os.path.realpath(__file__)) + '/../../src'

def crc_from_apigen(revision, filename):
    if not revision and not os.path.isfile(filename):
        print(f'skipping: {filename}', file=sys.stderr)
        return {}
    apigen_bin = f'{rootdir}/src/tools/vppapigen/vppapigen.py'
    if revision:
        apigen = (f'{apigen_bin} --git-revision {revision} --includedir src '
                  f'--input {filename} CRC')
    else:
        apigen = (f'{apigen_bin} --includedir src --input {filename} CRC')
    rv = run(apigen.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode == 2: # No such file
        print(f'skipping: {revision}:{filename} {rv}', file=sys.stderr)
        return {}
    if rv.returncode != 0:
        print(f'vppapigen failed for {revision}:{filename} with command\n {apigen}\n error: {rv}',
              rv.stderr.decode('ascii'), file=sys.stderr)
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


def is_uncommitted_changes():
    git_status = 'git status --porcelain -uno'
    rv = run(git_status.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode != 0:
        sys.exit(rv.returncode)

    if len(rv.stdout):
        return True
    return False


def filelist_from_git_grep(filename):
    filelist = []
    try:
        rv = check_output(f'git grep -e "import .*{filename}" -- *.api', shell=True)
    except CalledProcessError as err:
        return []
        print('RV', err.returncode)
    for l in rv.decode('ascii').split('\n'):
        if l:
            f, p = l.split(':')
            filelist.append(f)
    return filelist


def filelist_from_patchset():
    filelist = []
    git_cmd = '((git diff HEAD~1.. --name-only;git ls-files -m) | sort -u)'
    rv = check_output(git_cmd, shell=True)
    for l in rv.decode('ascii').split('\n'):
        if len(l) and os.path.splitext(l)[1] == '.api':
            filelist.append(l)

    # Check for dependencies (imports)
    imported_files = []
    for f in filelist:
        imported_files.extend(filelist_from_git_grep(os.path.basename(f)))

    filelist.extend(imported_files)
    return set(filelist)

def is_deprecated(d, k):
    if 'options' in d[k] and 'deprecated' in d[k]['options']:
        return True
    return False

def is_in_progress(d, k):
    try:
        if d[k]['options']['status'] == 'in_progress':
            return True
    except:
        return False

def report(new, old):
    added, removed, modified, same = dict_compare(new, old)
    backwards_incompatible = 0
    # print the full list of in-progress messages
    # they should eventually either disappear of become supported
    for k in new.keys():
        newversion = int(new[k]['version'])
        if newversion == 0 or is_in_progress(new, k):
            print(f'in-progress: {k}')
    for k in added:
        print(f'added: {k}')
    for k in removed:
        oldversion = int(old[k]['version'])
        if oldversion > 0 and not is_deprecated(old, k) and not is_in_progress(old, k):
            backwards_incompatible += 1
            print(f'removed: ** {k}')
        else:
            print(f'removed: {k}')
    for k in modified.keys():
        oldversion = int(old[k]['version'])
        newversion = int(new[k]['version'])
        if oldversion > 0 and not is_in_progress(old, k):
            backwards_incompatible += 1
            print(f'modified: ** {k}')
        else:
            print(f'modified: {k}')

    # check which messages are still there but were marked for deprecation
    for k in new.keys():
        newversion = int(new[k]['version'])
        if newversion > 0 and is_deprecated(new, k):
            if k in old:
                if not is_deprecated(old, k):
                    print(f'deprecated: {k}')
            else:
                print(f'added+deprecated: {k}')

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
    parser.add_argument('--diff', help='Files to compare (on filesystem)', nargs=2)

    args = parser.parse_args()

    if args.diff and args.files:
        parser.print_help()
        sys.exit(-1)

    # Diff two files
    if args.diff:
        oldcrcs = crc_from_apigen(None, args.diff[0])
        newcrcs = crc_from_apigen(None, args.diff[1])
        backwards_incompatible = report(newcrcs, oldcrcs)
        sys.exit(0)

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
            print('Argument git-revision ignored', file=sys.stderr)
        # Check there are no uncomitted changes
        if is_uncommitted_changes():
            print('Please stash or commit changes in workspace', file=sys.stderr)
            sys.exit(-1)
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

    backwards_incompatible = report(newcrcs, oldcrcs)

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
