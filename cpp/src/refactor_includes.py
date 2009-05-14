# Refactors include directives:
#
#   #include "keyczar/foo.h" becomes #include <keyczar/foo.h>
#   #include "base/bar.h" becomes #include <keyczar/base/bar.h>
#
# Usage:
#
# python tools/refactor_includes.py /.../src/keyczar /usr/local/include
# python tools/refactor_includes.py /.../src/base /usr/local/include/keyczar
#
import os
import re
import sys

def IsHeader(filename):
    if filename.endswith('.h'):
        return True
    return False

def IterateSources(path) :
    for root, dirlist, filelist in os.walk(path) :
        for filename in filelist:
            if IsHeader(filename):
                yield root, filename

def RefactorDir(src_path, dst_path, prefix='keyczar'):
    if not os.path.isdir(src_path) or not os.path.isdir(dst_path):
        return False

    outer = os.path.dirname(src_path)

    for dirname, filename in IterateSources(src_path):
        include_dir = dirname[len(outer) + len(os.sep):]
        dst_include_path = os.path.join(dst_path, include_dir)

        if not os.path.isdir(dst_include_path):
            os.mkdir(dst_include_path)

        fo = file(os.path.join(dirname, filename), 'r')
        try:
            header = fo.read()
        finally:
            fo.close()

        print >> sys.stdout, "refactor_includes: updating file", filename

        # Rewrite "base/..." includes
        header_mod = re.sub(r'#include\s+"base/(.+)"',
                            r'#include <%s/base/\1>' % prefix,
                            header)
        # Rewrite "prefix/..." includes
        header_mod = re.sub(r'#include\s+"%s/(.+)"' % prefix,
                            r'#include <%s/\1>' % prefix,
                            header_mod)

        fo = file(os.path.join(dst_include_path, filename), 'w')
        try:
            fo.write(header_mod)
        finally:
            fo.close()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(1)
    RefactorDir(sys.argv[1], sys.argv[2])
