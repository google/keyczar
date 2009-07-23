""" installer

Copied from: http://www.scons.org/wiki/Installer

This module defines a minimal installer for scons build scripts.  It is aimed
at *nix like systems, but I guess it could easily be adapted to other ones as
well.
"""
import fnmatch
import os
import os.path
import distutils.sysconfig
import SCons.Defaults

PREFIX = "prefix"
EPREFIX = "eprefix"
BINDIR = "bindir"
LIBDIR = "libdir"
INCLUDEDIR = "includedir"
PYPACKAGE = "pypackage"

def AddOptions(opts):
    """ Adds the installer options to the opts.  """
    opts.Add(PREFIX, "Directory of architecture independant files.", "/usr")
    opts.Add(EPREFIX, "Directory of architecture dependant files.",
             "${%s}" % PREFIX)
    opts.Add(BINDIR, "Directory of executables.", "${%s}/bin" % EPREFIX)
    opts.Add(LIBDIR, "Directory of libraries.", "${%s}/lib" % EPREFIX)
    opts.Add(INCLUDEDIR, "Directory of header files.", "${%s}/include" % PREFIX)
    opts.Add(PYPACKAGE, "Directory of Python module.",
             distutils.sysconfig.get_python_lib())

class Installer:
    """ A basic installer. """
    def __init__(self, env):
        """ Initialize the installer.

        @param configuration A dictionary containing the configuration.
        @param env The installation environment.
        """
        self._prefix = env.get(PREFIX, "/usr")
        self._eprefix = env.get(EPREFIX, self._prefix)
        self._bindir = env.get(BINDIR, os.path.join(self._eprefix, "bin"))
        self._libdir = env.get(LIBDIR, os.path.join(self._eprefix, "lib"))
        self._includedir = env.get(INCLUDEDIR,
                                   os.path.join(self._prefix, "include"))
        self._pypackage = env.get(PYPACKAGE,
                                  distutils.sysconfig.get_python_lib())
        self._env = env

    def Add(self, destdir, name, basedir="", perm=0644):
        destination = os.path.join(destdir, basedir)
        obj = self._env.Install(destination, name)
        self._env.Alias("install", destination)
        for i in obj:
            self._env.AddPostAction(i, SCons.Defaults.Chmod(str(i), perm))

    def AddProgram(self, program):
        """ Install a program.

        @param program The program to install.
        """
        self.Add(self._bindir, program, perm=0755)

    def AddLibrary(self, library):
        """ Install a library.

        @param library the library to install.
        """
        self.Add(self._libdir, library)

    def AddHeader(self, header, basedir=""):
        self.Add(self._includedir, header, basedir)

    def AddHeaders(self, parent, pattern, basedir="", recursive=False):
        """ Installs a set of headers.

        @param parent The parent directory of the headers.
        @param pattern A pattern to identify the files that are headers.
        @param basedir The subdirectory in which to install the headers.
        @param recursive Search recursively for headers.
        """
        for entry in os.listdir(parent):
            entrypath = os.path.join(parent, entry)
            if os.path.isfile(entrypath) and fnmatch.fnmatch(entry, pattern):
                self.AddHeader(entrypath, basedir)
            elif os.path.isdir(entrypath) and recursive:
                self.AddHeaders(entrypath, pattern,
                                os.path.join(basedir, entry), recursive)

    def AddPythonModule(self, dlib, module_name):
        self.Add(self._pypackage, dlib)
        self.Add(self._pypackage, os.path.join(self._env['LIB_DIR'],
                                               module_name + '.py'))

