import unittest
import os

from . import DataObject, PsqlDataStore, resultproxy_to_list

from django.conf import settings
from django.test import TestCase
from django.test.utils import override_settings

db_settings = {"store": {
    'ENGINE': "django.db.backends.postgresql_psycopg2",
    'HOST': "127.0.0.1",
    'PORT': "15432",
    'NAME': "store",
    'USER': "store",
    'PASSWORD': "store123",
    }
}

@unittest.skip
#@unittest.skipIf(hasattr(os.environ, "CIRCLECI"), "Running on CI")
class TestStringMethods(TestCase):

    @override_settings(DATABASES=db_settings)
    def setUp(self):

        #self.store = PsqlDataStore("user1", **settings.DATABASES['store'])
        self.datastore = PsqlDataStore(schema="test", **settings.DATABASES['store'])
        self.datastore.init_store()

        # write data
        data = {"function": "setUp"}
        obj_dict = DataObject(data=data)
        self.datastore.write_obj(obj_dict)


    @override_settings(DATABASES=db_settings)
    def test_save_json(self):

        # write data
        data = {"name": "Rolf"}
        obj_dict = DataObject(data=data)
        self.datastore.write_obj(obj_dict)
        data = {"name": "Markus"}
        obj_dict = DataObject(data=data)
        self.datastore.write_obj(obj_dict)

        data = {"name": "Philip",
                "address": {
                    "city": "Berne"
                    }
                }

        obj_dict = DataObject(data=data)
        self.datastore.write_obj(obj_dict)

        # count
        self.assertEqual(4, len(self.datastore.all()))

        # dumb check
        self.assertEqual("Rolf", self.datastore.all()[1].data['name'])
        self.assertEqual("Markus", self.datastore.all()[2].data['name'])

        result = self.datastore.filter("name", "Markus")
        self.assertIs(list, type(resultproxy_to_list(result)))

    @override_settings(DATABASES=db_settings)
    def test_update_json(self):
        result = self.datastore.filter("function", "setUp")
        self.assertEqual("setUp", result[0].data['function'])

        # update
        from copy import deepcopy
        obj = result[0]
        new_data = deepcopy(obj.data)
        new_data['function'] = "newFunction"
        obj.data = new_data
        self.datastore.save(obj)
        result = self.datastore.filter("function", "newFunction")
        self.assertEqual("newFunction", result[0].data['function'])

    @override_settings(DATABASES=db_settings)
    def test_update_json_with_api(self):
        result = self.datastore.get("function", "setUp")
        result.data['function'] = "newFunction"

        # update
        self.datastore.update(result)

        # force reload on attr access
        self.datastore.session.expire(result)
        self.assertEqual("newFunction", result.data['function'])


    @override_settings(DATABASES=db_settings)
    def test_get_row(self):
        result = self.datastore.get("function", "setUp")
        self.assertEqual("setUp", result.data['function'])

    @override_settings(DATABASES=db_settings)
    def test_get_multiple_row_throws_exception(self):
        with self.assertRaises(Exception):
            data = {"function": "setUp"}
            obj_dict = DataObject(data=data)
            self.datastore.write_obj(obj_dict)
            result = self.datastore.get("function", "setUp")

    @override_settings(DATABASES=db_settings)
    def test_delete_row(self):
        self.assertEqual(1, len(self.datastore.all()))
        result = self.datastore.get("function", "setUp")
        self.datastore.delete(result)
        self.assertEqual(0, len(self.datastore.all()))

    def tearDown(self):
        self.datastore.truncate()
