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


@unittest.skip
class TestStringMethods(TestCase):

    @override_settings(DATABASES=db_settings)
    def test_save_json(self):

        #self.store = PsqlDataStore("user1", **settings.DATABASES['store'])
        self.store = PsqlDataStore(**settings.DATABASES['store'])
        self.store.init_for_base()

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
        #self.assertEqual(3, len(self.store.all()))

        # dumb check
        self.assertEqual("Rolf", self.store.all()[0].data['name'])
        self.assertEqual("Markus", self.store.all()[1].data['name'])

        result = self.store.filter("name", "Markus")
        self.assertIs(list, type(resultproxy_to_list(result)))

    def tearDown(self):
        #pass
        #self.store._execute("TRUNCATE user1.data_table")
        #self.store._execute("TRUNCATE data_table")
        #self.store._execute("DROP TABLE user1.data_table")
        #self.store._execute("DROP TABLE data_table")
        self.store.truncate()
