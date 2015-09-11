__version__ = "0.6.13"

import os

from django.core.exceptions import ImproperlyConfigured

# load plugins
from django.conf import settings
try:
    for plugin in getattr(settings, "FASTAPP_PLUGINS", []):

        def my_import(name):
            # from http://effbot.org/zone/import-string.htm
            m = __import__(name)
            for n in name.split(".")[1:]:
                m = getattr(m, n)
            return m

        amod = my_import(plugin)
except ImproperlyConfigured, e:
    print e
    pass
