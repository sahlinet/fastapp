__version__ = "0.6.10"

import os

# load plugins
from django.conf import settings
for plugin in getattr(settings, "FASTAPP_PLUGINS", []):

    def my_import(name):
        # from http://effbot.org/zone/import-string.htm
        m = __import__(name)
        for n in name.split(".")[1:]:
            m = getattr(m, n)
        return m

    amod = my_import(plugin)
