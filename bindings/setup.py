<<<<<<< HEAD
#!/usr/bin/env python

from setuptools import setup, Extension
import sys

if sys.platform == "win32":
    ext = Extension("cryptlib_py",
                    sources=["python.c"],
                    library_dirs=['../binaries'],
                    libraries=['cl32'])
else:
    ext = Extension("cryptlib_py",
                    sources=["python.c"],
                    library_dirs=['..'],
                    libraries=['cl'])

setup(name="cryptlib_py", ext_modules=[ext])
=======
#!/usr/bin/env python

from setuptools import setup, Extension
import sys

if sys.platform == "win32":
    ext = Extension("cryptlib_py",
                    sources=["python.c"],
                    library_dirs=['../binaries'],
                    libraries=['cl32'])
else:
    ext = Extension("cryptlib_py",
                    sources=["python.c"],
                    library_dirs=['..'],
                    libraries=['cl'])

setup(name="cryptlib_py", ext_modules=[ext])
>>>>>>> c627b7fdce5a7d3fb5a3cfac7f910c556c3573ae
