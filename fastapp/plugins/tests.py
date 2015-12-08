from fastapp.plugins.datastore.tests import *

import unittest
import os

from django.conf import settings
from django.test import TestCase
from django.test.utils import override_settings

from fastapp.plugins import call_plugin_func
from fastapp.tests import BaseTestCase
from fastapp.plugins.models import PluginUserConfig

#@unittest.skipIf(hasattr(os.environ, "CIRCLECI"), "Running on CI")
#@unittest.skip
class PluginTests(BaseTestCase):

    #@override_settings(DATABASES=db_settings)
    #def setUp(self):
    #    super(BaseTestCase, self).setUp()

    def test_config(self):

        obj = self.base1
        config = {'password': "ASDF"}
        a = PluginUserConfig(plugin_name="DataStorePlugin", base=obj, config=config)
        a.save()

        success, failed = call_plugin_func(obj, "get_persistent_config")
        for k, v in success.iteritems():
            assert type(v) is dict, "type is: %s (%s)" % (type(v), str(v))
