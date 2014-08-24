import json
import os
import logging
import StringIO
import zipfile
from mock import patch
from django.test import TransactionTestCase, Client
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from fastapp.models import AuthProfile
from django.db.models.signals import post_save

from fastapp.models import Base, Apy, Executor, Counter, synchronize_to_storage, initialize_on_storage, Transaction
from fastapp.utils import check_code
from pyflakes.messages import UnusedImport, Message


class BaseTestCase(TransactionTestCase):

	logging.disable(logging.DEBUG)

	@patch("fastapp.models.distribute")
	def setUp(self, distribute_mock):
		post_save.disconnect(synchronize_to_storage, sender=Apy)
		post_save.disconnect(initialize_on_storage, sender=Base)
		distribute_mock.return_value = True

		self.user1 = User.objects.create_user('user1', 'user1@example.com', 'pass')
		self.user1.save()

		auth, created = AuthProfile.objects.get_or_create(user=self.user1)
		auth.user = self.user1
		auth.save()
		
		self.user2 = User.objects.create_user('user2', 'user2@example.com', 'pass')
		self.user2.save()
		auth, created = AuthProfile.objects.get_or_create(user=self.user2)
		auth.user = self.user2
		auth.save()	

		self.base1 = Base.objects.create(name="base1", user=self.user1)
		self.base1_apy1 = Apy.objects.create(name="base1_apy1", base=self.base1)
		self.base1_apy1.save()

		self.base1_apy_xml = Apy.objects.create(name="base1_apy_xml", base=self.base1)
		self.base1_apy_xml.module = "def func(self):"\
		"	return 'bla'"

		# counter is done in disconnected signal
		counter = Counter(apy=self.base1_apy1)
		counter.save()

		self.client1 = Client()  # logged in with objects
		self.client2 = Client()  # logged in without objects
		self.client3 = Client()  # not logged in 
		self.client_csrf = Client(enforce_csrf_checks=True)  # not logged in 

	#def tearDown(self):
	#	try:
	#		self.base1_apy1.delete()
	#		self.base1.delete()
	#		self.user1.delete()
	#		self.user2.delete()
	#	except Exception:
	#		pass

class ApiTestCase(BaseTestCase):

	def test_base_get_403_when_not_logged_in(self):
		response = self.client3.get(reverse('base-list'))
		self.assertEqual(403, response.status_code)

	def test_base_empty_response_without_objects(self):
		self.client2.login(username='user2', password='pass')
		response = self.client2.get(reverse('base-list'))
		self.assertEqual(200, response.status_code)
		self.assertJSONEqual(response.content, [])

	def test_base_response_base_list(self):
		self.client1.login(username='user1', password='pass')
		response = self.client1.get(reverse('base-list'))
		self.assertEqual(200, response.status_code)
		assert json.loads(response.content)

	def test_get_all_apys_for_base(self):
		self.client1.login(username='user1', password='pass')
		response = self.client1.get("/fastapp/api/base/%s/apy/" % self.base1.id)
		self.assertEqual(200, response.status_code)
		assert json.loads(response.content)

	def test_get_one_apy_for_base(self):
		self.client1.login(username='user1', password='pass')
		response = self.client1.get("/fastapp/api/base/%s/apy/%s/" % (self.base1.id, self.base1_apy1.id))
		self.assertEqual(200, response.status_code)
		self.assertTrue(json.loads(response.content).has_key('id'))

	@patch("fastapp.models.distribute")
	def test_clone_apy_for_base_and_delete(self, distribute_mock):
		distribute_mock.return_value = True
		self.client1.login(username='user1', password='pass')
		response = self.client1.post("/fastapp/api/base/%s/apy/%s/clone/" % (self.base1.id, self.base1_apy1.id))
		self.assertEqual(200, response.status_code)
		assert json.loads(response.content)

		# delete
		# TODO: fix test
		#response = self.client1.delete("/fastapp/api/base/%s/apy/%s/" % (self.base1.id, json_response['id']))
		#self.assertEqual(204, response.status_code)

class BaseExecutorStateTestCase(BaseTestCase):

	def test_base_has_executor_instance(self):
		#pass
		#mock_distribute.return_value = True
		base = self.base1
		self.assertIs(base.executor.__class__, Executor)

		# mock fastapp.executors.remote import distribute
		# sync_to_storage

		# check if created second
		self.base1.save()
		self.base1.save()
		self.base1.save()
		self.assertIs(Executor.objects.count(), 1)

	def test_generate_vhost_configuration(self):
		from fastapp.queue import generate_vhost_configuration
		vhost = generate_vhost_configuration('username', 'base1')
		self.assertEquals(vhost, "/username-base1")

@patch("fastapp.views.send_client")
@patch("fastapp.views.call_rpc_client")
class ApyExecutionTestCase(BaseTestCase):

	def test_execute_apy_logged_in(self, call_rpc_client_mock, send_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': [{u'_encoding': u'utf-8', u'_mutable': False}, True], u'response_class': None, 'time_ms': '668', 'id': u'send_mail'})

		send_client_mock.return_value = True
		self.client1.login(username='user1', password='pass')
		response = self.client1.get(self.base1_apy1.get_exec_url())
		self.assertEqual(200, response.status_code)
		self.assertTrue(json.loads(response.content).has_key('status'))

	def test_execute_apy_with_shared_key(self, call_rpc_client_mock, send_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': [{u'_encoding': u'utf-8', u'_mutable': False}, True], u'response_class': None, 'time_ms': '668', 'id': u'send_mail'})
		send_client_mock.return_value = True
		url = self.base1_apy1.get_exec_url()+"&shared_key=%s" % (self.base1.uuid)
		response = self.client3.get(url)
		self.assertEqual(200, response.status_code)
		self.assertTrue(json.loads(response.content).has_key('status'))

	def test_execute_apy_logged_in_with_post(self, call_rpc_client_mock, send_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': [{u'_encoding': u'utf-8', u'_mutable': False}, True], u'response_class': None, 'time_ms': '668', 'id': u'send_mail'})
		send_client_mock.return_value = True
		self.client_csrf.login(username='user1', password='pass')
		response = self.client_csrf.post(self.base1_apy1.get_exec_url(), data={'a': 'b'})
		self.assertEqual(200, response.status_code)
		self.assertTrue(json.loads(response.content).has_key('status'))

	def test_receive_json_when_querystring_json(self, call_rpc_client_mock, send_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': [{u'_encoding': u'utf-8', u'_mutable': False}, True], u'response_class': None, 'time_ms': '668', 'id': u'send_mail'})
		send_client_mock.return_value = True
		self.client_csrf.login(username='user1', password='pass')
		response = self.client_csrf.get(self.base1_apy1.get_exec_url())
		self.assertEqual(200, response.status_code)
		self.assertTrue(json.loads(response.content).has_key('status'))
		self.assertEqual(response['Content-Type'], "application/json")

	def test_receive_xml_when_response_is_XMLResponse(self, call_rpc_client_mock, send_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': u'{"content": "<xml></xml>", "class": "XMLResponse", "content_type": "application/xml"}', u'response_class': u'XMLResponse', 'time_ms': '74', 'id': u'contenttype_test_receive'})
		send_client_mock.return_value = True
		self.client_csrf.login(username='user1', password='pass')
		response = self.client_csrf.get(self.base1_apy1.get_exec_url().replace("json=", ""))
		self.assertEqual(200, response.status_code)
		self.assertEqual(response['Content-Type'], "application/xml")
		from xml.dom import minidom
		assert minidom.parseString(response.content)

	def test_receive_json_when_response_is_JSONResponse(self, call_rpc_client_mock, send_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': u'{"content": "{\\"aaa\\": \\"aaa\\"}", "class": "XMLResponse", "content_type": "application/json"}', u'response_class': u'JSONResponse', 'time_ms': '74', 'id': u'contenttype_test_receive'})
		send_client_mock.return_value = True
		self.client_csrf.login(username='user1', password='pass')
		response = self.client_csrf.get(self.base1_apy1.get_exec_url().replace("json=", ""))
		self.assertEqual(200, response.status_code)
		self.assertEqual(response['Content-Type'], "application/json")
		assert json.loads(u''+response.content).has_key('aaa')

	def test_execute_async(self, call_rpc_client_mock, send_client_mock):
		call_rpc_client_mock.return_value = True
		send_client_mock.return_value = True
		self.client1.login(username='user1', password='pass')
		from urllib2 import urlparse

		# get redirect
		response = self.client1.get(self.base1_apy1.get_exec_url()+"&async")
		self.assertEqual(301, response.status_code)
		queries = urlparse.urlparse(response['Location'])[4]
		rid = int(urlparse.parse_qs(queries)['rid'][0])
		transaction = Transaction.objects.get(pk=rid)

		# get state (RUNNING)
		response = self.client1.get(self.base1_apy1.get_exec_url()+"&rid=%s" % rid)
		self.assertEqual(200, response.status_code)
		tout = json.dumps({u'status': u'RUNNING', "url": "/fastapp/base/base1/exec/base1_apy1/?json=&rid="+str(rid), 'rid': rid, 'id': u'base1_apy1'})
		self.assertEqual(response.content, tout)

		# get response
		tout = json.dumps({u'status': u'OK', u'exception': None, u'returned': u'{"content": "{\\"aaa\\": \\"aaa\\"}", "class": "XMLResponse", "content_type": "application/json"}', u'response_class': u'JSONResponse', 'time_ms': '74', 'rid': rid, 'id': u'base1_apy1'})
		transaction.tout = tout
		transaction.save()
		self.assertEqual(transaction.apy, self.base1_apy1)

		response = self.client1.get(self.base1_apy1.get_exec_url()+"&rid=%s" % rid)
		self.assertEqual(200, response.status_code)
		self.assertEqual(response.content, tout)

		# check transaction duration
		transaction = Transaction.objects.get(pk=rid)
		self.assertEqual(int, type(transaction.duration))



@patch("fastapp.models.distribute")
class SettingTestCase(BaseTestCase):

	def test_create_and_change_setting_for_base(self, distribute_mock):
		distribute_mock.return_value
		self.client1.login(username='user1', password='pass')
		json_data = {u'key': u'key', 'value': 'value'}
		response = self.client1.post("/fastapp/api/base/%s/setting/" % self.base1.id, json_data)
		self.assertEqual(201, response.status_code)
		json_data_response = {"id": 1, "key": "key", "value": "value"}
		self.assertJSONEqual(response.content, json_data_response)
		distribute_mock.assert_called

		# change
		setting_id = json_data_response['id']
		response = self.client1.put("/fastapp/api/base/%s/setting/%s/" % (self.base1.id, setting_id), json.dumps(json_data), content_type="application/json")
		self.assertEqual(200, response.status_code)

		# partial update
		response = self.client1.patch("/fastapp/api/base/%s/setting/%s/" % (self.base1.id, setting_id), json.dumps(json_data), content_type="application/json")
		self.assertEqual(200, response.status_code)

		# delete
		response = self.client1.delete("/fastapp/api/base/%s/setting/%s/" % (self.base1.id, setting_id), content_type="application/json")
		self.assertEqual(204, response.status_code)

#class CounterTestCase(BaseTestCase):
#	def test_create_counter_on_apy_save(self):
#		#counter = Counter(apy=self.base1_apy1)
#		#counter.save()
#		self.assertEqual(Apy.objects.get(id=self.base1_apy1.id).counter.executed, 0)
#		self.base1_apy1.mark_executed()
#		self.assertEqual(Apy.objects.get(id=self.base1_apy1.id).counter.executed, 1)
#		self.base1_apy1.mark_failed()
#		self.assertEqual(Apy.objects.get(id=self.base1_apy1.id).counter.failed, 1)

class ImportTestCase(BaseTestCase):

	@patch("fastapp.utils.Connection.metadata")
	@patch("fastapp.utils.Connection.get_file")
	def test_export_to_zip_testcase(self, mock_get_file, mock_metadata):
		mock_get_file.return_value = StringIO.StringIO("asdf")
		metadata = {u'hash': u'f9c342ee00e216e844d9a6c23980e19c', u'revision': 3330, u'bytes': 0, 
		u'thumb_exists': False, 
		u'rev': u'd0226669b01', 
		u'modified': u'Mon, 18 Aug 2014 16:46:50 +0000', 
		u'path': u'/transport/static', 
		u'is_dir': True, u'size': u'0 bytes', 
		u'root': u'app_folder', 
		u'contents': [{u'revision': 3331, u'bytes': 70, u'thumb_exists': False, u'rev': u'd0326669b01', u'modified': u'Mon, 18 Aug 2014 16:46:50 +0000', u'mime_type': u'text/html', u'path': u'/transport/static/index.html', u'is_dir': False, u'size': u'70 bytes', u'root': 'app_folder', u'client_mtime': u'Mon, 18 Aug 2014 16:42:47 +0000', u'icon': u'page_whitecode'}], u'icon': u'folder'}
		mock_metadata.return_value = metadata
		
		self.client1.login(username='user1', password='pass')
		response = self.client1.get("/fastapp/api/base/%s/export/" % self.base1.id)
		self.assertEqual(200, response.status_code)

		f = StringIO.StringIO()
		f.write(response.content)
		f.flush()
		zf = zipfile.ZipFile(f)
		self.assertEqual(None, zf.testzip())

		files = ['base1_apy1', 'base1_apy_xml']
		files = ['base1/base1_apy1.py', 'base1/base1_apy_xml.py', 'transport/static/index.html', 'base1/app.config']
		self.assertEqual(files, zf.namelist())
		self.assertEqual(self.base1_apy1.module, zf.read(files[0]))



	@patch("fastapp.utils.Connection.metadata")
	@patch("fastapp.utils.Connection.get_file")
	@patch("fastapp.utils.Connection.delete_file")
	@patch("fastapp.utils.Connection.put_file")
	def test_import_from_zip_testcase(self, mock_put_file, mock_delete_file, mock_get_file, mock_metadata):
		mock_get_file.return_value = StringIO.StringIO("asdf")
		metadata = {u'hash': u'f9c342ee00e216e844d9a6c23980e19c', u'revision': 3330, u'bytes': 0, 
		u'thumb_exists': False, 
		u'rev': u'd0226669b01', 
		u'modified': u'Mon, 18 Aug 2014 16:46:50 +0000', 
		u'path': u'/transport/static', 
		u'is_dir': True, u'size': u'0 bytes', 
		u'root': u'app_folder', 
		u'contents': [{u'revision': 3331, u'bytes': 70, u'thumb_exists': False, u'rev': u'd0326669b01', u'modified': u'Mon, 18 Aug 2014 16:46:50 +0000', u'mime_type': u'text/html', u'path': u'/transport/static/index.html', u'is_dir': False, u'size': u'70 bytes', u'root': 'app_folder', u'client_mtime': u'Mon, 18 Aug 2014 16:42:47 +0000', u'icon': u'page_whitecode'}], u'icon': u'folder'}
		mock_metadata.return_value = metadata

		# export
		zf = self.base1.export()
		# save to temp to omit name attribute error on stringio file
		import tempfile
		tempfile_name = tempfile.mkstemp(suffix=".zip")[1]
		tf = open(tempfile_name, 'w+')
		tf.write(zf.getvalue())
		tf.flush()
		tf.close()
		# delete
		self.base1.delete()

		# import
		mock_put_file.return_value = True
		mock_delete_file.return_value = True

		self.client1.login(username='user1', password='pass')
		new_base_name = self.base1.name+"-new"
		
		response = self.client1.post("/fastapp/api/base/import/", {'name': new_base_name, 'file': open(tempfile_name)})
		self.assertEqual(201, response.status_code)
		responsed_name = json.loads(response.content)['name']
		self.assertEqual(responsed_name, new_base_name)
		self.assertTrue(mock_put_file.call_count > 0)

		tf.close()
		os.remove(tempfile_name)



class SyntaxCheckerTestCase(BaseTestCase):

	#def setUp(self):

	@patch("fastapp.models.distribute")
	def setUp(self, distribute_mock):
		super(SyntaxCheckerTestCase, self).setUp()

	def test_module_syntax_ok(self):
		self.assertEqual((True, [], []), check_code(self.base1_apy1.module, self.base1_apy1.name))

	def test_module_unused_import(self):
		# unused import
		self.base1_apy1.module = "import asdf"
		ok, warnings, errors = check_code(self.base1_apy1.module, self.base1_apy1.name)
		self.assertFalse(ok)
		self.assertEqual(UnusedImport, warnings[0].__class__)

	def test_module_intendation_error(self):
		# intendation error
		self.base1_apy1.module = """
		def func(self):
    print "a"
import asdf
    print "b"
		"""
		ok, warnings, errors = check_code(self.base1_apy1.module, self.base1_apy1.name)
		self.assertFalse(ok)
		self.assertEqual(Message, errors[0].__class__)


	def test_save_invalid_module(self):
		self.base1_apy1.module = "import asdf, blublub"

		self.client1.login(username='user1', password='pass')
		response = self.client1.patch("/fastapp/api/base/%s/apy/%s/" % (self.base1.id, self.base1_apy1.id), 
				data = json.dumps({'module': self.base1_apy1.module}), content_type='application/json'
			)
		self.assertEqual(500, response.status_code)
		self.assertTrue(json.loads(response.content)['detail'].has_key('warnings'))

	def test_save_valid_module(self):
		self.base1_apy1.module = """import django
print django"""

		self.client1.login(username='user1', password='pass')
		response = self.client1.patch("/fastapp/api/base/%s/apy/%s/" % (self.base1.id, self.base1_apy1.id), 
				data = json.dumps({'module': self.base1_apy1.module}), content_type='application/json'
			)
		self.assertEqual(200, response.status_code)

	def test_save_unparsebla_module(self):
		self.base1_apy1.module = "def blu()"

		self.client1.login(username='user1', password='pass')
		response = self.client1.patch("/fastapp/api/base/%s/apy/%s/" % (self.base1.id, self.base1_apy1.id), 
				data = json.dumps({'module': self.base1_apy1.module}), content_type='application/json'
			)
		self.assertEqual(500, response.status_code)
		self.assertTrue(json.loads(response.content)['detail'].has_key('warnings'))
