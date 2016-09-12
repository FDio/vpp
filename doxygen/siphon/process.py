# Copyright (c) 2016 Comcast Cable Communications Management, LLC.
#
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

# Generation template class

import logging, sys, cgi, json

# Classes register themselves in this dictionary
"""Mapping of known processors to their classes"""
siphons = {}


"""Generate rendered output for siphoned data."""
class Siphon(object):

    # Set by subclasses
    """Our siphon name"""
    name = None

    # Set by subclasses
    """Name of an identifier used by this siphon"""
    identifier = None

    # Set by subclasses
    """The pyparsing object to use to parse with"""
    _parser = None

    """The input data"""
    _cmds = None

    """Logging handler"""
    log = None


    def __init__(self):
        super(Siphon, self).__init__()
        self.log = logging.getLogger("siphon.process.%s" % self.name)


    # Output renderers

    """Returns an object to be used as the sorting key in the item index."""
    def index_sort_key(self, group, dec):
        return group

    """Returns a string to use as the header at the top of the item index."""
    def index_header(self):
        raise NotImplementedError

    """Returns the string fragment to use for each section in the item
    index."""
    def index_section(self, group):
        return "\n@subpage %s\n\n" % self.page_label(group)

    """Returns the string frament to use for each entry in the item index."""
    def index_entry(self, meta, item):
        return "* [%s](@ref %s)\n" % (item["name"], meta["label"])

    """Returns an object, typically a string, to be used as the sorting key
    for items within a section."""
    def sort_key(self, item):
        return item['name']

    """Returns a string to use as the header when rendering the item."""
    def header(self, group, dec):
        raise NotImplementedError

    """Returns a string to use as the body when rendering the item."""
    def format(self, meta, item):
        raise NotImplementedError

    """Returns a string to use as the label for the page reference."""
    def page_label(self, group):
        return "__".join((
            self.name,
            group.replace("/", "_").replace(".", "_")))

    """Returns a string to use as the label for the section reference."""
    def item_label(self, group, item):
        return "__".join((self.page_label(group), item))


    # Processing methods

    """Parse the input file into a more usable dictionary structure."""
    def load_json(self, files):
        self._cmds = {}
        line_num = 0
        line_start = 0
        for filename in files:
            self.log.info("Parsing items in file \"%s\"." % filename)
            data = None
            with open(filename, "r") as fd:
                data = json.load(fd)

            self._cmds['_global'] = data['global']

            # iterate the items loaded and regroup it
            for item in data["items"]:
                try:
                    o = self._parser.parse(item['block'])
                except:
                    self.log.error("Exception parsing item: %s\n%s" \
                            % (json.dumps(item, separators=(',', ': '),
                                indent=4),
                                item['block']))
                    raise

                # Augment the item with metadata
                o["meta"] = {}
                for key in item:
                    if key == 'block':
                        continue
                    o['meta'][key] = item[key]

                # Add the item (and all the dicts leading to it, if needed)
                group = item['group']
                file = item['file']
                macro = o["macro"]
                name = o["name"]

                if group not in self._cmds:
                    self._cmds[group] = {}

                if file not in self._cmds[group]:
                    self._cmds[group][file] = {}

                if macro not in self._cmds[group][file]:
                    self._cmds[group][file][macro] = {}

                self._cmds[group][file][macro][name] = o

    """Iterate over the input data, calling render methods to generate the
    output."""
    def process(self, out=None):

        if out is None:
            out = sys.stdout

        # Accumulated body contents
        contents = ""

        # Write the header for this siphon type
        out.write(self.index_header())

        # Sort key helper for the index
        def group_sort_key(item):
            return self.index_sort_key(item, self._cmds['_global'])

        # Iterate the dictionary and process it
        for group in sorted(self._cmds.keys(), key=group_sort_key):
            if group.startswith('_'):
                continue

            self.log.info("Processing items in group \"%s\"." % group)

            out.write(self.index_section(group))

            dec = self._cmds['_global']
            contents += self.header(group, dec)

            for file in sorted(self._cmds[group].keys()):
                if group.startswith('_'):
                    continue

                self.log.debug("- Processing items from file \"%s\"." % file)

                for macro in sorted(self._cmds[group][file].keys()):
                    if macro != self.identifier:
                        continue
                    self.log.debug("-- Processing items in macro \"%s\"." % macro)

                    meta = {
                        "group": group,
                        "file": file,
                        "macro": macro,
                    }

                    def item_sort_key(item):
                        return self.sort_key(self._cmds[group][file][macro][item])

                    for item in sorted(self._cmds[group][file][macro].keys(), key=item_sort_key):
                        self.log.debug("--- Processing item \"%s\"." % item)

                        # update per-item meta data
                        meta["item"] = item
                        meta["label"] = self.item_label(group, item)

                        s = self.index_entry(meta, self._cmds[group][file][macro][item])
                        out.write(s)

                        contents += self.format(meta, self._cmds[group][file][macro][item])

        # Deliver the accumulated body output
        out.write(contents)
