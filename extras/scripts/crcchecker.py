#!/usr/bin/env python3

'''
crcchecker is a tool to used to enforce that .api messages do not change.
API files with a semantic version < 1.0.0 are ignored.
'''

import sys
import os
import json
import argparse
import re
from subprocess import run, PIPE, check_output, CalledProcessError

# pylint: disable=subprocess-run-check

ROOTDIR = os.path.dirname(os.path.realpath(__file__)) + '/../..'
APIGENBIN = f'{ROOTDIR}/src/tools/vppapigen/vppapigen.py'


def crc_from_apigen(revision, filename):
    '''Runs vppapigen with crc plugin returning a JSON object with CRCs for
    all APIs in filename'''
    if not revision and not os.path.isfile(filename):
        print(f'skipping: {filename}', file=sys.stderr)
        # Return <class 'set'> instead of <class 'dict'>
        return {-1}

    if revision:
        apigen = (f'{APIGENBIN} --git-revision {revision} --includedir src '
                  f'--input {filename} CRC')
    else:
        apigen = (f'{APIGENBIN} --includedir src --input {filename} CRC')
    returncode = run(apigen.split(), stdout=PIPE, stderr=PIPE)
    if returncode.returncode == 2:  # No such file
        print(f'skipping: {revision}:{filename} {returncode}', file=sys.stderr)
        return {}
    if returncode.returncode != 0:
        print(f'vppapigen failed for {revision}:{filename} with '
              'command\n {apigen}\n error: {rv}',
              returncode.stderr.decode('ascii'), file=sys.stderr)
        sys.exit(-2)

    return json.loads(returncode.stdout)


def dict_compare(dict1, dict2):
    '''Compare two dictionaries returning added, removed, modified
    and equal entries'''
    d1_keys = set(dict1.keys())
    d2_keys = set(dict2.keys())
    intersect_keys = d1_keys.intersection(d2_keys)
    added = d1_keys - d2_keys
    removed = d2_keys - d1_keys
    modified = {o: (dict1[o], dict2[o]) for o in intersect_keys
                if dict1[o]['crc'] != dict2[o]['crc']}
    same = set(o for o in intersect_keys if dict1[o] == dict2[o])
    return added, removed, modified, same


def filelist_from_git_ls():
    '''Returns a list of all api files in the git repository'''
    filelist = []
    git_ls = 'git ls-files *.api'
    returncode = run(git_ls.split(), stdout=PIPE, stderr=PIPE)
    if returncode.returncode != 0:
        sys.exit(returncode.returncode)

    for line in returncode.stdout.decode('ascii').split('\n'):
        if line:
            filelist.append(line)
    return filelist


def is_uncommitted_changes():
    '''Returns true if there are uncommitted changes in the repo'''
    git_status = 'git status --porcelain -uno'
    returncode = run(git_status.split(), stdout=PIPE, stderr=PIPE)
    if returncode.returncode != 0:
        sys.exit(returncode.returncode)

    if returncode.stdout:
        return True
    return False


def filelist_from_git_grep(filename):
    '''Returns a list of api files that this <filename> api files imports.'''
    filelist = []
    try:
        returncode = check_output(f'git grep -e "import .*{filename}"'
                                  ' -- *.api',
                                  shell=True)
    except CalledProcessError:
        return []
    for line in returncode.decode('ascii').split('\n'):
        if line:
            filename, _ = line.split(':')
            filelist.append(filename)
    return filelist


def filelist_from_patchset(pattern):
    '''Returns list of api files in changeset and the list of api
    files they import.'''
    filelist = []
    git_cmd = ('((git diff HEAD~1.. --name-only;git ls-files -m) | '
               'sort -u | grep "\\.api$")')
    try:
        res = check_output(git_cmd, shell=True)
    except CalledProcessError:
        return []

    # Check for dependencies (imports)
    imported_files = []
    for line in res.decode('ascii').split('\n'):
        if not line:
            continue
        if not re.search(pattern, line):
            continue
        filelist.append(line)
        imported_files.extend(filelist_from_git_grep(os.path.basename(line)))

    filelist.extend(imported_files)
    return set(filelist)


def is_deprecated(message):
    '''Given a message, return True if message is deprecated'''
    if 'options' in message:
        if 'deprecated' in message['options']:
            return True
        # recognize the deprecated format
        if 'status' in message['options'] and \
           message['options']['status'] == 'deprecated':
            print("WARNING: please use 'option deprecated;'")
            return True
    return False


def is_in_progress(message):
    '''Given a message, return True if message is marked as in_progress'''
    if 'options' in message:
        if 'in_progress' in message['options']:
            return True
        # recognize the deprecated format
        if 'status' in message['options'] and \
           message['options']['status'] == 'in_progress':
            print("WARNING: please use 'option in_progress;'")
            return True
    return False


def report(new, old):
    '''Given a dictionary of new crcs and old crcs, print all the
    added, removed, modified, in-progress, deprecated messages.
    Return the number of backwards incompatible changes made.'''

    # pylint: disable=too-many-branches

    new.pop('_version', None)
    old.pop('_version', None)
    added, removed, modified, _ = dict_compare(new, old)
    backwards_incompatible = 0

    # print the full list of in-progress messages
    # they should eventually either disappear of become supported
    for k in new.keys():
        newversion = int(new[k]['version'])
        if newversion == 0 or is_in_progress(new[k]):
            print(f'in-progress: {k}')
    for k in added:
        print(f'added: {k}')
    for k in removed:
        oldversion = int(old[k]['version'])
        if oldversion > 0 and not is_deprecated(old[k]) and not \
           is_in_progress(old[k]):
            backwards_incompatible += 1
            print(f'removed: ** {k}')
        else:
            print(f'removed: {k}')
    for k in modified.keys():
        oldversion = int(old[k]['version'])
        newversion = int(new[k]['version'])
        if oldversion > 0 and not is_in_progress(old[k]):
            backwards_incompatible += 1
            print(f'modified: ** {k}')
        else:
            print(f'modified: {k}')

    # check which messages are still there but were marked for deprecation
    for k in new.keys():
        newversion = int(new[k]['version'])
        if newversion > 0 and is_deprecated(new[k]):
            if k in old:
                if not is_deprecated(old[k]):
                    print(f'deprecated: {k}')
            else:
                print(f'added+deprecated: {k}')

    return backwards_incompatible


def check_patchset():
    '''Compare the changes to API messages in this changeset.
    Ignores API files with version < 1.0.0.
    Only considers API files located under the src directory in the repo.
    '''
    files = filelist_from_patchset('^src/')
    revision = 'HEAD~1'

    oldcrcs = {}
    newcrcs = {}
    for filename in files:
        # Ignore files that have version < 1.0.0
        _ = crc_from_apigen(None, filename)
        # Ignore removed files
        if isinstance(_, set) == 0:
            if isinstance(_, set) == 0 and _['_version']['major'] == '0':
                continue
            newcrcs.update(_)

        oldcrcs.update(crc_from_apigen(revision, filename))

    backwards_incompatible = report(newcrcs, oldcrcs)
    if backwards_incompatible:
        # alert on changing production API
        print("crcchecker: Changing production APIs in an incompatible way",
              file=sys.stderr)
        sys.exit(-1)
    else:
        print('*' * 67)
        print('* VPP CHECKAPI SUCCESSFULLY COMPLETED')
        print('*' * 67)


def main():
    '''Main entry point.'''
    parser = argparse.ArgumentParser(description='VPP CRC checker.')
    parser.add_argument('--git-revision',
                        help='Git revision to compare against')
    parser.add_argument('--dump-manifest', action='store_true',
                        help='Dump CRC for all messages')
    parser.add_argument('--check-patchset', action='store_true',
                        help='Check patchset for backwards incompatbile changes')
    parser.add_argument('files', nargs='*')
    parser.add_argument('--diff', help='Files to compare (on filesystem)',
                        nargs=2)

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
        for filename in files:
            crcs.update(crc_from_apigen(args.git_revision, filename))
        for k, value in crcs.items():
            print(f'{k}: {value}')
        sys.exit(0)

    # Find changes between current patchset and given revision (previous)
    if args.check_patchset:
        if args.git_revision:
            print('Argument git-revision ignored', file=sys.stderr)
        # Check there are no uncomitted changes
        if is_uncommitted_changes():
            print('Please stash or commit changes in workspace',
                  file=sys.stderr)
            sys.exit(-1)
        check_patchset()
        sys.exit(0)

    # Find changes between current workspace and revision
    # Find changes between a given file and a revision
    files = args.files if args.files else filelist_from_git_ls()

    revision = args.git_revision if args.git_revision else 'HEAD~1'

    oldcrcs = {}
    newcrcs = {}
    for file in files:
        newcrcs.update(crc_from_apigen(None, file))
        oldcrcs.update(crc_from_apigen(revision, file))

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
