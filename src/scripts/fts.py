#!/usr/bin/env python3

import argparse
import ipaddress
import os
import re
import sys
from pprint import pprint
from subprocess import PIPE, run

import yaml

from jsonschema import validate

# VPP feature JSON schema
schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "description": {"type": "string"},
        "maintainer": {"type": "string"},
        "state": {"type": "string",
                  "enum": ["production", "experimental"]},
        "features": {"$ref": "#/definitions/features"},
        "missing": {"$ref": "#/definitions/features"},
        "properties": {"type": "array",
                       "items": {"type": "string",
                                 "enum": ["API", "CLI", "STATS",
                                          "MULTITHREAD"]},
                       },
    },
    "additionalProperties": False,
    "definitions": {
        "featureobject": {
            "type": "object",
            "patternProperties": {
                "^.*$": {"$ref": "#/definitions/features"},
            },
        },
        "features": {
            "type": "array",
            "items": {"anyOf": [{"$ref": "#/definitions/featureobject"},
                                {"type": "string"},
                                ]},
            "minItems": 1,
        },
    },
}


def filelist_from_git_status():
    filelist = []
    git_status = 'git status --porcelain */FEATURE.yaml'
    rv = run(git_status.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode != 0:
        sys.exit(rv.returncode)

    for l in rv.stdout.decode('ascii').split('\n'):
        if len(l):
            filelist.append(l.split()[1])
    return filelist


def filelist_from_git_ls():
    filelist = []
    git_ls = 'git ls-files :(top)*/FEATURE.yaml'
    rv = run(git_ls.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode != 0:
        sys.exit(rv.returncode)

    for l in rv.stdout.decode('ascii').split('\n'):
        if len(l):
            filelist.append(l)
    return filelist


def output_features(indent, fl):
    for f in fl:
        if type(f) is dict:
            for k, v in f.items():
                print('{}- {}'.format(' ' * indent, k))
                output_features(indent + 2, v)
        else:
            print('{}- {}'.format(' ' * indent, f))


def output_markdown(features):
    for k, v in features.items():
        print('# {}'.format(v['name']))
        print('Maintainer: {}  '.format(v['maintainer']))
        print('State: {}\n'.format(v['state']))
        print('{}\n'.format(v['description']))
        output_features(0, v['features'])
        if 'missing' in v:
            print('\n## Missing')
            output_features(0, v['missing'])
        print()


def main():
    parser = argparse.ArgumentParser(description='VPP Feature List.')
    parser.add_argument('--validate', dest='validate', action='store_true',
                        help='validate the FEATURE.yaml file')
    parser.add_argument('--git-status', dest='git_status', action='store_true',
                        help='Get filelist from git status')
    parser.add_argument('--all', dest='all', action='store_true',
                        help='Validate all files in repository')
    parser.add_argument('--markdown', dest='markdown', action='store_true',
                        help='Output feature table in markdown')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('r'),
                        default=sys.stdin)
    args = parser.parse_args()

    features = {}

    if args.git_status:
        filelist = filelist_from_git_status()
    elif args.all:
        filelist = filelist_from_git_ls()
    else:
        filelist = args.infile

    for featurefile in filelist:
        featurefile = featurefile.rstrip()

        # Load configuration file
        with open(featurefile) as f:
            cfg = yaml.load(f, Loader=yaml.SafeLoader)
        validate(instance=cfg, schema=schema)
        features[featurefile] = cfg

    if args.markdown:
        output_markdown(features)


if __name__ == '__main__':
    main()
