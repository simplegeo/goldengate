# This is the version of this source code.

verstr = "1.0.__BUILD__"

try:
    from pyutil.version_class import Version
    Version # Placate pyflakes
except ImportError:
    # Maybe there is no pyutil installed.
    from distutils.version import LooseVersion as Version

__version__ = Version(verstr)
