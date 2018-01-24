#!/usr/bin/env python
import os, fnmatch, subprocess
starttag = 'v18.01-rc0'
endtag = 'v18.01-rc2'
apifiles = []
for root, dirnames, filenames in os.walk('.'):
    for filename in fnmatch.filter(filenames, '*.api'):
        apifiles.append(os.path.join(root, filename))
for f in apifiles:
    commits = subprocess.check_output(['git', 'log',
                                       '--oneline', starttag + '..' + endtag,
                                       f])
    if commits:
        print f
        print commits
