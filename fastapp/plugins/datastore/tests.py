import unittest

from . import DataObject, PsqlDataStore, resultproxy_to_list

from django.conf import settings
from django.test import TestCase
from django.test.utils import override_settings

db_settings = {"store": {
    'ENGINE': "django.db.backends.postgresql_psycopg2",
    'HOST': "localhost",
    'PORT': "5432",
    'NAME': "store",
    'USER': "store",
    'PASSWORD': "store123",
    }
}


#@unittest.skip
class TestStringMethods(TestCase):

    @override_settings(DATABASES=db_settings)
    def setUp(self):

        #self.store = PsqlDataStore("user1", **settings.DATABASES['store'])
        self.store = PsqlDataStore(schema="test", **settings.DATABASES['store'])
        self.store.init_store()

        # write data
        data = {"function": "setUp"}
        obj_dict = DataObject(data=data)
        self.store.write_obj(obj_dict)

    #@override_settings(DATABASES=db_settings)
    def test_save_json(self):

        # write data
        data = {"name": "Rolf"}
        obj_dict = DataObject(data=data)
        self.store.write_obj(obj_dict)
        data = {"name": "Markus"}
        obj_dict = DataObject(data=data)
        self.store.write_obj(obj_dict)

        data = {"name": "Philip",
                "address": {
                    "city": "Berne"
                    }
                }

        obj_dict = DataObject(data=data)
        self.store.write_obj(obj_dict)

        # count
        self.assertEqual(4, len(self.store.all()))

        # dumb check
        #print self.store.all()[0]
        #print self.store.all()
        #import pdb; pdb.set_trace()
        self.assertEqual("Rolf", self.store.all()[1].data['name'])
        self.assertEqual("Markus", self.store.all()[2].data['name'])

        result = self.store.filter("name", "Markus")
        self.assertIs(list, type(resultproxy_to_list(result)))

    @override_settings(DATABASES=db_settings)
    def test_update_json(self):
        result = self.store.filter("function", "setUp")
        self.assertEqual("setUp", result[0].data['function'])

        # update
        from copy import deepcopy
        obj = result[0]
        new_data = deepcopy(obj.data)
        new_data['function'] = "newFunction"
        obj.data = new_data
        self.store.save(obj)
        result = self.store.filter("function", "newFunction")
        self.assertEqual("newFunction", result[0].data['function'])

    @override_settings(DATABASES=db_settings)
    def test_get_row(self):
        result = self.store.get("function", "setUp")
        self.assertEqual("setUp", result.data['function'])

    @override_settings(DATABASES=db_settings)
    def test_get_multiple_row_throws_exception(self):
        with self.assertRaises(Exception):
            data = {"function": "setUp"}
            obj_dict = DataObject(data=data)
            self.store.write_obj(obj_dict)
            result = self.store.get("function", "setUp")

    @override_settings(DATABASES=db_settings)
    def test_delete_row(self):
        self.assertEqual(1, len(self.store.all()))
        result = self.store.get("function", "setUp")
        self.store.delete(result)
        self.assertEqual(0, len(self.store.all()))

    def tearDown(self):
        #pass
        #self.store._execute("TRUNCATE user1.data_table")
        #self.store._execute("TRUNCATE data_table")
        #self.store._execute("DROP TABLE user1.data_table")
        #self.store._execute("DROP TABLE data_table")
        self.store.truncate()
