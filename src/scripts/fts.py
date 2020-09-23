#!/usr/bin/env python3

import sys
import os
import ipaddress
import yaml
from pprint import pprint
import re
from jsonschema import validate, exceptions
import argparse
from subprocess import run, PIPE
from io import StringIO

# VPP feature JSON schema
schema = {
    "$schema": "http://json-schema.org/schema#",
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "description": {"type": "string"},
        "maintainer": {"$ref": "#/definitions/maintainers"},
        "state": {"type": "string",
                  "enum": ["production", "experimental", "development"]},
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
        "maintainers": {
            "anyof": [{
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
            },
                {"type": "string"}],
        },
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
    git_status = 'git status --porcelain */FEATURE*.yaml'
    rv = run(git_status.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode != 0:
        sys.exit(rv.returncode)

    for l in rv.stdout.decode('ascii').split('\n'):
        if len(l):
            filelist.append(l.split()[1])
    return filelist


def filelist_from_git_ls():
    filelist = []
    git_ls = 'git ls-files :(top)*/FEATURE*.yaml'
    rv = run(git_ls.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode != 0:
        sys.exit(rv.returncode)

    for l in rv.stdout.decode('ascii').split('\n'):
        if len(l):
            filelist.append(l)
    return filelist

def version_from_git():
    git_describe = 'git describe'
    rv = run(git_describe.split(), stdout=PIPE, stderr=PIPE)
    if rv.returncode != 0:
        sys.exit(rv.returncode)
    return rv.stdout.decode('ascii').split('\n')[0]

class MarkDown():
    _dispatch = {}

    def __init__(self, stream):
        self.stream = stream
        self.toc = []

    def print_maintainer(self, o):
        write = self.stream.write
        if type(o) is list:
            write('Maintainers: ' +
                  ', '.join('{m}'.format(m=m) for m in
                            o) + '  \n')
        else:
            write('Maintainer: {o}  \n'.format(o=o))

    _dispatch['maintainer'] = print_maintainer

    def print_features(self, o, indent=0):
        write = self.stream.write
        for f in o:
            indentstr = ' ' * indent
            if type(f) is dict:
                for k, v in f.items():
                    write('{indentstr}- {k}\n'.format(indentstr=indentstr, k=k))
                    self.print_features(v, indent + 2)
            else:
                write('{indentstr}- {f}\n'.format(indentstr=indentstr, f=f))
        write('\n')
    _dispatch['features'] = print_features

    def print_markdown_header(self, o):
        write = self.stream.write
        write('## {o}\n'.format(o=o))
        version = version_from_git()
        write('VPP version: {version}\n\n'.format(version=version))
    _dispatch['markdown_header'] = print_markdown_header

    def print_name(self, o):
        write = self.stream.write
        write('### {o}\n'.format(o=o))
        self.toc.append(o)
    _dispatch['name'] = print_name

    def print_description(self, o):
        write = self.stream.write
        write('\n{o}\n\n'.format(o=o))
    _dispatch['description'] = print_description

    def print_state(self, o):
        write = self.stream.write
        write('Feature maturity level: {o}  \n'.format(o=o))
    _dispatch['state'] = print_state

    def print_properties(self, o):
        write = self.stream.write
        write('Supports: {s}  \n'.format(s=" ".join(o)))
    _dispatch['properties'] = print_properties

    def print_missing(self, o):
        write = self.stream.write
        write('\nNot yet implemented:  \n')
        self.print_features(o)
    _dispatch['missing'] = print_missing

    def print_code(self, o):
        write = self.stream.write
        write('Source Code: [{o}]({o}) \n'.format(o=o))
    _dispatch['code'] = print_code

    def print(self, t, o):
        write = self.stream.write
        if t in self._dispatch:
            self._dispatch[t](self, o,)
        else:
            write('NOT IMPLEMENTED: {t}\n')

def output_toc(toc, stream):
    write = stream.write
    write('## VPP Feature list:\n')

    for t in toc:
        ref = t.lower().replace(' ', '-')
        write('[{t}](#{ref})  \n'.format(t=t, ref=ref))

def featuresort(k):
    return k[1]['name']

def featurelistsort(k):
    orderedfields = {
        'name': 0,
        'maintainer': 1,
        'description': 2,
        'features': 3,
        'state': 4,
        'properties': 5,
        'missing': 6,
        'code': 7,
    }
    return orderedfields[k[0]]

def output_markdown(features, fields, notfields):
    stream = StringIO()
    m = MarkDown(stream)
    m.print('markdown_header', 'Feature Details:')
    for path, featuredef in sorted(features.items(), key=featuresort):
        codeurl = 'https://git.fd.io/vpp/tree/src/' + \
                  '/'.join(os.path.normpath(path).split('/')[1:-1])
        featuredef['code'] = codeurl
        for k, v in sorted(featuredef.items(), key=featurelistsort):
            if notfields:
                if k not in notfields:
                    m.print(k, v)
            elif fields:
                if k in fields:
                    m.print(k, v)
            else:
                m.print(k, v)

    tocstream = StringIO()
    output_toc(m.toc, tocstream)
    return tocstream, stream

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
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--include', help='List of fields to include')
    group.add_argument('--exclude', help='List of fields to exclude')
    args = parser.parse_args()
    features = {}

    if args.git_status:
        filelist = filelist_from_git_status()
    elif args.all:
        filelist = filelist_from_git_ls()
    else:
        filelist = args.infile

    if args.include:
        fields = args.include.split(',')
    else:
        fields = []
    if args.exclude:
        notfields = args.exclude.split(',')
    else:
        notfields = []

    for featurefile in filelist:
        featurefile = featurefile.rstrip()

        # Load configuration file
        with open(featurefile, encoding='utf-8') as f:
            cfg = yaml.load(f, Loader=yaml.SafeLoader)
        try:
            validate(instance=cfg, schema=schema)
        except exceptions.ValidationError:
            print('File does not validate: {featurefile}' \
                  .format(featurefile=featurefile), file=sys.stderr)
            raise
        features[featurefile] = cfg

    if args.markdown:
        stream = StringIO()
        tocstream, stream = output_markdown(features, fields, notfields)
        print(tocstream.getvalue())
        print(stream.getvalue())
        stream.close()


if __name__ == '__main__':
    main()
