from django.test import TransactionTestCase, Client
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from fastapp.models import AuthProfile
from django.db.models.signals import post_save

from fastapp.models import Base, Apy, Executor, Counter, synchronize_to_storage, initialize_on_storage
import json
from mock import patch
import logging

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

@patch("fastapp.views.call_rpc_client")
class ApyExecutionTestCase(BaseTestCase):

	def test_execute_apy_logged_in(self, call_rpc_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': [{u'_encoding': u'utf-8', u'_mutable': False}, True], u'response_class': None, 'time_ms': '668', 'id': u'send_mail'})
		self.client1.login(username='user1', password='pass')
		response = self.client1.get(self.base1_apy1.get_exec_url())
		self.assertEqual(200, response.status_code)
		self.assertTrue(json.loads(response.content).has_key('status'))

	def test_execute_apy_with_shared_key(self, call_rpc_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': [{u'_encoding': u'utf-8', u'_mutable': False}, True], u'response_class': None, 'time_ms': '668', 'id': u'send_mail'})
		url = self.base1_apy1.get_exec_url()+"&shared_key=%s" % (self.base1.uuid)
		response = self.client3.get(url)
		self.assertEqual(200, response.status_code)
		self.assertTrue(json.loads(response.content).has_key('status'))

	def test_execute_apy_logged_in_with_post(self, call_rpc_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': [{u'_encoding': u'utf-8', u'_mutable': False}, True], u'response_class': None, 'time_ms': '668', 'id': u'send_mail'})
		self.client_csrf.login(username='user1', password='pass')
		response = self.client_csrf.post(self.base1_apy1.get_exec_url(), data={'a': 'b'})
		self.assertEqual(200, response.status_code)
		self.assertTrue(json.loads(response.content).has_key('status'))

	def test_receive_json_when_querystring_json(self, call_rpc_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': [{u'_encoding': u'utf-8', u'_mutable': False}, True], u'response_class': None, 'time_ms': '668', 'id': u'send_mail'})
		self.client_csrf.login(username='user1', password='pass')
		response = self.client_csrf.get(self.base1_apy1.get_exec_url())
		self.assertEqual(200, response.status_code)
		self.assertTrue(json.loads(response.content).has_key('status'))
		self.assertEqual(response['Content-Type'], "application/json")

	def test_receive_xml_when_response_is_XMLResponse(self, call_rpc_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': u'{"content": "<xml></xml>", "class": "XMLResponse", "content_type": "application/xml"}', u'response_class': u'XMLResponse', 'time_ms': '74', 'id': u'contenttype_test_receive'})
		self.client_csrf.login(username='user1', password='pass')
		response = self.client_csrf.get(self.base1_apy1.get_exec_url().replace("json=", ""))
		self.assertEqual(200, response.status_code)
		self.assertEqual(response['Content-Type'], "application/xml")
		from xml.dom import minidom
		assert minidom.parseString(response.content)

	def test_receive_json_when_response_is_JSONResponse(self, call_rpc_client_mock):
		call_rpc_client_mock.return_value = json.dumps({u'status': u'OK', u'exception': None, u'returned': u'{"content": "{\\"aaa\\": \\"aaa\\"}", "class": "XMLResponse", "content_type": "application/json"}', u'response_class': u'JSONResponse', 'time_ms': '74', 'id': u'contenttype_test_receive'})
		self.client_csrf.login(username='user1', password='pass')
		response = self.client_csrf.get(self.base1_apy1.get_exec_url().replace("json=", ""))
		self.assertEqual(200, response.status_code)
		self.assertEqual(response['Content-Type'], "application/json")
		assert json.loads(u''+response.content).has_key('aaa')

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