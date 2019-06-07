#!/usr/bin/env python3

import json
import os
import fnmatch
import sys
import subprocess
from shutil import move, copy, rmtree
from glob import glob

# Preamble error checking
try:  
   ws_root = os.environ['WS_ROOT']
except KeyError: 
   print('ERROR: Please set the environment variable WS_ROOT!\n')
   sys.exit(1)

   
# global variables
ws_src_dir = f'{ws_root}/src'
ws_build_root_dir = f'{ws_root}/build-root'
api_test_dir = os.path.dirname(os.path.realpath(__file__))
api_src_dir = f'{api_test_dir}/src'
api_src_orig_dir = f'{api_src_dir}/orig'
api_json_dir = f'{api_test_dir}/json'
api_json_orig_dir = f'{api_json_dir}/orig'
test_api_fname = 'ip.api'
test_api_json_fname = f'{test_api_fname}.json'


# functions
def find(pattern, path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result


def rebuild_ip_api_json(test_dir, parent_api_file=test_api_fname):
    test_name = os.path.basename(test_dir)
    print(f'Rebuilding {test_name} ...')
    
    # update parent_api_file modification time
    #
    # We need to touch the parent api file because
    # cmake dependencies are broken for imported api type files
    # (eg. ip_types.api)
    os.utime(find(parent_api_file, ws_src_dir)[0], None)

    test_api_files = find('*.api', test_dir)
    for test_api_file_path in test_api_files:
        test_api_file = os.path.basename(test_api_file_path)
        src_api_file_path = find(test_api_file, ws_src_dir)[0]

        # backup existing api file being modified
        move(src_api_file_path, f'{src_api_file_path}.save')

        # install test api source file
        copy(test_api_file_path, src_api_file_path)
    
    # rebuild
    make_results = subprocess.run(['make', 'build'], cwd=ws_root, check=True)
    if make_results.returncode:
        print(f'ERROR: Build failed for {test_dir}:\n{make_results.stderr}')
        
    for test_api_file_path in test_api_files:
        test_api_file = os.path.basename(test_api_file_path)
        src_api_file_path = find(test_api_file, ws_src_dir)[0]

        # restore original api file
        move(f'{src_api_file_path}.save', src_api_file_path)

    print(f'Rebuild {test_name} complete.')
    return make_results.returncode


def json_file_api_msg_crc(api_json_file):
    with open(api_json_file) as f:
        api_json = json.load(f)

    api_crc = {}
    for msg in api_json['messages']:
        api_crc[msg[0]] =  msg[-1]['crc']
    return api_crc


def run_crc_test(src_dir, dst_dir, output_results=True):
    test_name = src_dir.split('/')[-1]
    if output_results:
       test_descr = subprocess.check_output(f'grep api-crc-test {src_dir}/*'
                                            '| cut -d\'*\' -f2'
                                            '| cut -d\':\' -f2',
                                            shell=True).rstrip()\
            .decode('utf-8')
    dst_api_json_dir = f'{api_json_dir}/{test_name}'
    dst_api_json_path = f'{dst_api_json_dir}/{test_api_json_fname}'
    if rebuild_ip_api_json(src_dir):
        return

    build_api_json_path = find(test_api_json_fname, ws_build_root_dir)
    
    if not len(build_api_json_path):
        print(f'ERROR: {test_api_json_fname} not found in {ws_build_root_dir}')
        return
    
    # copy resulting api.json file into json dir
    if os.path.exists(dst_api_json_dir):
        rmtree(dst_api_json_dir)

    os.mkdir(dst_api_json_dir)
    copy (build_api_json_path[0], dst_api_json_path)

    if not output_results: return
    
    # Output the results
    test_api_crc = json_file_api_msg_crc(dst_api_json_path)
    new_crc = 0
    for api_msg in test_api_crc:
        if test_api_crc[api_msg] != orig_api_crc[api_msg]:
            new_crc += 1
            if new_crc == 1:
                print(f'\n   {test_name} {test_descr}: API Messages With New CRC\n'
                      '------------------------------------------------'
                      '-----------------------------------')
            print(f'{api_msg:50}'
                  f'orig: {orig_api_crc[api_msg]}  '
                  f'new: {test_api_crc[api_msg]}')

    print('------------------------------------------------'
          '-----------------------------------\n'
          f'   {test_name}{test_descr}: {new_crc} API Message CRCs changed!\n')


# main source code
if not os.path.exists(api_json_dir): os.mkdir(api_json_dir)
run_crc_test(api_src_orig_dir, api_json_dir, output_results=False)
orig_api_crc = json_file_api_msg_crc(f'{api_json_orig_dir}/'
                                     f'{test_api_json_fname}')
for test_dir in sorted(glob(f'{api_src_dir}/test*/')):
    run_crc_test(test_dir.rstrip('/'), api_json_dir)
