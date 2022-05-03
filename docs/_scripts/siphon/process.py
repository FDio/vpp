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

import html.parser
import json
import logging
import os
import sys
import re

import jinja2

# Classes register themselves in this dictionary
"""Mapping of known processors to their classes"""
siphons = {}

"""Mapping of known output formats to their classes"""
formats = {}


class Siphon(object):
    """Generate rendered output for siphoned data."""

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

    """Group key to (directory,file) mapping"""
    _group = None

    """Logging handler"""
    log = None

    """Directory to look for siphon rendering templates"""
    template_directory = None

    """Directory to output parts in"""
    outdir = None

    """Template environment, if we're using templates"""
    _tplenv = None

    def __init__(self, template_directory, format, outdir, repository_link):
        super(Siphon, self).__init__()
        self.log = logging.getLogger("siphon.process.%s" % self.name)

        # Get our output format details
        fmt_klass = formats[format]
        fmt = fmt_klass()
        self._format = fmt

        # Sort out the template search path
        def _tpldir(name):
            return os.sep.join((template_directory, fmt.name, name))

        self.template_directory = template_directory
        searchpath = [
            _tpldir(self.name),
            _tpldir("default"),
        ]
        self.outdir = outdir
        loader = jinja2.FileSystemLoader(searchpath=searchpath)
        self._tplenv = jinja2.Environment(
            loader=loader,
            trim_blocks=True,
            autoescape=False,
            keep_trailing_newline=True,
        )

        # Convenience, get a reference to the internal escape and
        # unescape methods in html.parser. These then become
        # available to templates to use, if needed.
        self._h = html.parser.HTMLParser()
        self.escape = html.escape
        self.unescape = html.unescape

        # TODO: customize release
        self.repository_link = repository_link

    # Output renderers

    """Returns an object to be used as the sorting key in the item index."""

    def index_sort_key(self, group):
        return group

    """Returns a string to use as the header at the top of the item index."""

    def index_header(self):
        return self.template("index_header")

    """Returns the string fragment to use for each section in the item
    index."""

    def index_section(self, group):
        return self.template("index_section", group=group)

    """Returns the string fragment to use for each entry in the item index."""

    def index_entry(self, meta, item):
        return self.template("index_entry", meta=meta, item=item)

    """Returns an object, typically a string, to be used as the sorting key
    for items within a section."""

    def item_sort_key(self, item):
        return item["name"]

    """Returns a key for grouping items together."""

    def group_key(self, directory, file, macro, name):
        _global = self._cmds["_global"]

        if file in _global and "group_label" in _global[file]:
            self._group[file] = (directory, file)
            return file

        self._group[directory] = (directory, None)
        return directory

    """Returns a key for identifying items within a grouping."""

    def item_key(self, directory, file, macro, name):
        return name

    """Returns a string to use as the header when rendering the item."""

    def item_header(self, group):
        return self.template("item_header", group=group)

    """Returns a string to use as the body when rendering the item."""

    def item_format(self, meta, item):
        return self.template("item_format", meta=meta, item=item)

    """Returns a string to use as the label for the page reference."""

    def page_label(self, group):
        return "_".join((self.name, self.sanitize_label(group)))

    """Returns a title to use for a page."""

    def page_title(self, group):
        _global = self._cmds["_global"]
        (directory, file) = self._group[group]

        if file and file in _global and "group_label" in _global[file]:
            return _global[file]["group_label"]

        if directory in _global and "group_label" in _global[directory]:
            return _global[directory]["group_label"]

        return directory

    """Returns a string to use as the label for the section reference."""

    def item_label(self, group, item):
        return "__".join((self.name, item))

    """Label sanitizer; for creating Doxygen references"""

    def sanitize_label(self, value):
        return value.replace(" ", "_").replace("/", "_").replace(".", "_")

    """Template processor"""

    def template(self, name, **kwargs):
        tpl = self._tplenv.get_template(name + self._format.extension)
        return tpl.render(this=self, **kwargs)

    # Processing methods

    """Parse the input file into a more usable dictionary structure."""

    def load_json(self, files):
        self._cmds = {}
        self._group = {}

        line_num = 0
        line_start = 0
        for filename in files:
            filename = os.path.relpath(filename)
            self.log.info('Parsing items in file "%s".' % filename)
            data = None
            with open(filename, "r") as fd:
                data = json.load(fd)

            self._cmds["_global"] = data["global"]

            # iterate the items loaded and regroup it
            for item in data["items"]:
                try:
                    o = self._parser.parse(item["block"])
                except Exception:
                    self.log.error(
                        "Exception parsing item: %s\n%s"
                        % (
                            json.dumps(item, separators=(",", ": "), indent=4),
                            item["block"],
                        )
                    )
                    raise

                # Augment the item with metadata
                o["meta"] = {}
                for key in item:
                    if key == "block":
                        continue
                    o["meta"][key] = item[key]

                # Load some interesting fields
                directory = item["directory"]
                file = item["file"]
                macro = o["macro"]
                name = o["name"]

                # Generate keys to group items by
                group_key = self.group_key(directory, file, macro, name)
                item_key = self.item_key(directory, file, macro, name)

                if group_key not in self._cmds:
                    self._cmds[group_key] = {}

                self._cmds[group_key][item_key] = o

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
        def group_sort_key(group):
            return self.index_sort_key(group)

        # Iterate the dictionary and process it
        for group in sorted(self._cmds.keys(), key=group_sort_key):
            if group.startswith("_"):
                continue

            self.log.info(
                'Processing items in group "%s" (%s).' % (group, group_sort_key(group))
            )

            # Generate the section index entry (write it now)
            out.write(self.index_section(group))

            # Generate the item header (save for later)
            contents += self.item_header(group)

            def item_sort_key(key):
                return self.item_sort_key(self._cmds[group][key])

            for key in sorted(self._cmds[group].keys(), key=item_sort_key):
                self.log.debug(
                    '--- Processing key "%s" (%s).' % (key, item_sort_key(key))
                )

                o = self._cmds[group][key]
                meta = {
                    "directory": o["meta"]["directory"],
                    "file": o["meta"]["file"],
                    "macro": o["macro"],
                    "name": o["name"],
                    "key": key,
                    "label": self.item_label(group, key),
                }

                # Generate the index entry for the item (write it now)
                out.write(self.index_entry(meta, o))

                # Generate the item itself (save for later)
                contents += self.item_format(meta, o)

            page_name = self.separate_page_names(group)
            if page_name != "":
                path = os.path.join(self.outdir, page_name)
                with open(path, "w+") as page:
                    page.write(contents)
                contents = ""

        # Deliver the accumulated body output
        out.write(contents)

    def do_cliexstart(self, matchobj):
        title = matchobj.group(1)
        title = " ".join(title.splitlines())
        content = matchobj.group(2)
        content = re.sub(r"\n", r"\n    ", content)
        return "\n\n.. code-block:: console\n\n    %s\n    %s\n\n" % (title, content)

    def do_clistart(self, matchobj):
        content = matchobj.group(1)
        content = re.sub(r"\n", r"\n    ", content)
        return "\n\n.. code-block:: console\n\n    %s\n\n" % content

    def do_cliexcmd(self, matchobj):
        content = matchobj.group(1)
        content = " ".join(content.splitlines())
        return "\n\n.. code-block:: console\n\n    %s\n\n" % content

    def process_list(self, matchobj):
        content = matchobj.group(1)
        content = self.reindent(content, 2)
        return "@@@@%s\nBBBB" % content

    def process_special(self, s):
        # ----------- markers to remove
        s = re.sub(r"@cliexpar\s*", r"", s)
        s = re.sub(r"@parblock\s*", r"", s)
        s = re.sub(r"@endparblock\s*", r"", s)
        s = re.sub(r"<br>", "", s)
        # ----------- emphasis
        # <b><em>
        s = re.sub(r"<b><em>\s*", "``", s)
        s = re.sub(r"\s*</b></em>", "``", s)
        s = re.sub(r"\s*</em></b>", "``", s)
        # <b>
        s = re.sub(r"<b>\s*", "**", s)
        s = re.sub(r"\s*</b>", "**", s)
        # <code>
        s = re.sub(r"<code>\s*", "``", s)
        s = re.sub(r"\s*</code>", "``", s)
        # <em>
        s = re.sub(r"'?<em>\s*", r"``", s)
        s = re.sub(r"\s*</em>'?", r"``", s)
        # @c <something>
        s = re.sub(r"@c\s(\S+)", r"``\1``", s)
        # ----------- todos
        s = re.sub(r"@todo[^\n]*", "", s)
        s = re.sub(r"@TODO[^\n]*", "", s)
        # ----------- code blocks
        s = re.sub(r"@cliexcmd{(.+?)}", self.do_cliexcmd, s, flags=re.DOTALL)
        s = re.sub(
            r"@cliexstart{(.+?)}(.+?)@cliexend", self.do_cliexstart, s, flags=re.DOTALL
        )
        s = re.sub(r"@clistart(.+?)@cliend", self.do_clistart, s, flags=re.DOTALL)
        # ----------- lists
        s = re.sub(r"^\s*-", r"\n@@@@", s, flags=re.MULTILINE)
        s = re.sub(r"@@@@(.*?)\n\n+", self.process_list, s, flags=re.DOTALL)
        s = re.sub(r"BBBB@@@@", r"-", s)
        s = re.sub(r"@@@@", r"-", s)
        s = re.sub(r"BBBB", r"\n\n", s)
        # ----------- Cleanup remains
        s = re.sub(r"@cliexend\s*", r"", s)
        return s

    def separate_page_names(self, group):
        return ""

    # This push the given textblock <indent> spaces right
    def reindent(self, s, indent):
        ind = " " * indent
        s = re.sub(r"\n", "\n" + ind, s)
        return s

    # This aligns the given textblock left (no indent)
    def noindent(self, s):
        s = re.sub(r"\n[ \f\v\t]*", "\n", s)
        return s


class Format(object):
    """Output format class"""

    """Name of this output format"""
    name = None

    """Expected file extension of templates that build this format"""
    extension = None


class FormatMarkdown(Format):
    """Markdown output format"""

    name = "markdown"
    extension = ".md"


# Register 'markdown'
formats["markdown"] = FormatMarkdown


class FormatItemlist(Format):
    """Itemlist output format"""

    name = "itemlist"
    extension = ".itemlist"


# Register 'itemlist'
formats["itemlist"] = FormatItemlist
