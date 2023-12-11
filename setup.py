from distutils.core import setup, Extension
import glob

_pymovex = Extension('_pymovex', sources = ['_pymovex.c'], libraries=['MvxSock'])

setup(name='pymovex3',
      version='1.1.4',
      description="Python (3) module for interacting with M3/Movex, implemented using the C-API",
      py_modules=['pymovex'],
      ext_modules=[_pymovex],
      author='Jean-Baptiste Quenot, Ludovico Maria Ottaviani',
      author_email='me@ludovicoottaviani.eu',
      url="https://github.com/Lyut/pymovex3"
    )
