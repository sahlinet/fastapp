import sys
import os
import signal
import subprocess
import logging
import tutum
import random

from docker import Client
from docker.tls import TLSConfig
from docker.utils import kwargs_from_env

from django.conf import settings
from django.contrib.sites.models import Site

from fastapp.utils import load_setting

logger = logging.getLogger(__name__)

class ContainerNotFound(Exception):
    pass

MEM_LIMIT = "128m"
CPU_SHARES = 512
DOCKER_IMAGE = "tutum.co/philipsahli/skyblue-planet-worker:develop"

class BaseExecutor(object):
	def __init__(self, *args, **kwargs):
		self.vhost = kwargs['vhost']
		self.base_name = kwargs['base_name']
		self.username = kwargs['username']
		self.password = kwargs['password']

		# container name, must be unique, therefore we use a mix from site's domain name and executor
		slug = "worker-%s-%i-%s" % (Site.objects.get_current().domain, random.randrange(1,900000), self.base_name)
		self.name = slug.replace("_", "-").replace(".", "-")

	@property
	def _start_command(self):
		start_command = "%s %smanage.py start_worker --vhost=%s --base=%s --username=%s --password=%s" % (
					"/home/planet/.virtualenvs/planet/bin/python",
					"/home/planet/code/app/",
					self.vhost,
					self.base_name,
					self.base_name, self.password
			)
		#return start_command.split(" ")
		return start_command

	def destroy(self, id):
		logger.info("Executor does not support 'destroy'")

	def _pre_start(self):
		pass


class TutumExecutor(BaseExecutor):

	TUTUM_TAGS = ["workers"]

	def __init__(self, *args, **kwargs):
		self.api = tutum
		self.api.user = settings.TUTUM_USERNAME
		self.api.apikey = settings.TUTUM_APIKEY

		logger.info("Using TUTUM_USERNAME: %s" % self.api.user)

		super(TutumExecutor, self).__init__(*args, **kwargs)

	def start(self, id):
		new = not self._container_exists(id)
		if new:

			# create the service
			service = self.api.Service.create(image=DOCKER_IMAGE, 
				name=self.name,
				target_num_containers=1,
				mem_limit = MEM_LIMIT,
				cpu_shares = CPU_SHARES,
				container_envvars = [
					{ 'key': "RABBITMQ_HOST", 'value': settings.WORKER_RABBITMQ_HOST},
					{ 'key': "RABBITMQ_PORT", 'value': settings.WORKER_RABBITMQ_PORT},
					{ 'key': "FASTAPP_WORKER_THREADCOUNT", 'value': settings.FASTAPP_WORKER_THREADCOUNT },
					{ 'key': "FASTAPP_PUBLISH_INTERVAL", 'value': settings.FASTAPP_PUBLISH_INTERVAL},
					{ 'key': "FASTAPP_CORE_SENDER_PASSWORD", 'value': settings.FASTAPP_CORE_SENDER_PASSWORD},
					{ 'key': "EXECUTOR", 'value': "Tutum"},
				],
				autorestart="ALWAYS",
				entrypoint = self._start_command
			)
			service.save()
		else:
			service = self._get_container(id)
		if new:
			tag = self.api.Tag.fetch(service)
			tag.add(TutumExecutor.TUTUM_TAGS)
			tag.save()
		service.start()

		while True:
			try:
				service = self._get_container(service.uuid)
				if service.state == "Running":
					break
			except ContainerNotFound:
				pass

		return service.uuid

	def _get_container(self, id):
		from tutum.api.exceptions import TutumApiError
		logger.debug("Get container (%s)" % id)
		if not id:
			raise ContainerNotFound()
		try:
			service = self.api.Service.fetch(id)
			if service.state == "Terminated":
				raise ContainerNotFound()
		except TutumApiError, e:
			#if e.response.status_code == 404:
			logger.warning("Container not found (%s)" % id)
			logger.exception(e)
			raise ContainerNotFound()
		logger.debug("Container found (%s)" % id)
		return service

	def _container_exists(self, id):
		logger.debug("Check if container exists (%s)" % id)
		if not id:
			return False
		try:
			self._get_container(id)
		except ContainerNotFound:
			return False
		return True

	def stop(self, id):
		service = self.api.Service.fetch(id)
		service.stop()
		while True:
			service = self._get_container(id)
			if service.state == "Stopped":
				break

	def destroy(self, id):
		if self._container_exists(id):
			service = self.api.Service.fetch(id)
			service.delete()
			while True:
				try:
					service = self._get_container(id)
				except ContainerNotFound, e:
					logger.exception(e)
					break
				if service.state == "Terminated":
					break

	def state(self, id):
		if not id:
			return False
		from tutum.api.exceptions import TutumApiError
		try:
			service = self.api.Service.fetch(id)
		except TutumApiError, e:
			logger.exception(e)
			return False
		return (service.state == "Running")


class DockerExecutor(BaseExecutor):

	DOCKER_IMAGE = "philipsahli/skyblue-planet-worker:develop"

	def __init__(self, *args, **kwargs):

		docker_kwargs = kwargs_from_env()
		docker_kwargs['tls'].assert_hostname = False

		self.api = Client(**docker_kwargs)

		super(DockerExecutor, self).__init__(*args, **kwargs)

	def start(self, id):

		self._pre_start()

		if not self._container_exists(id):
			logger.info("Create container for %s" % self.vhost)

			container = self.api.create_container(
				image = self.__class__.DOCKER_IMAGE,
				name=self.name, 
				detach = True,
				mem_limit = MEM_LIMIT,
				cpu_shares = CPU_SHARES,
				environment = {
					'RABBITMQ_HOST': settings.WORKER_RABBITMQ_HOST,
					'RABBITMQ_PORT': settings.WORKER_RABBITMQ_PORT,
					'FASTAPP_WORKER_THREADCOUNT': settings.FASTAPP_WORKER_THREADCOUNT,
					'FASTAPP_PUBLISH_INTERVAL': settings.FASTAPP_PUBLISH_INTERVAL,
					'FASTAPP_CORE_SENDER_PASSWORD': settings.FASTAPP_CORE_SENDER_PASSWORD,
					'EXECUTOR': "docker",
					'constraint:node!=fed*': "docker",
				},
				entrypoint = self._start_command
			)

		else:
			container = self._get_container(id)

		id = container.get('Id')
		logger.info("Start container (%s)" % id)
		self.api.start(container=id)
		return id

	def stop(self, id):
		logger.info("Stop container (%s)" % id)
		self.api.kill(id)

	def destroy(self, id):
		if self._container_exists(id):
			self.api.remove_container(id)

	def _get_container(self, id):
		from docker import errors
		logger.debug("Get container (%s)" % id)
		try:
			service = self.api.inspect_container(id)
		except errors.APIError, e:
			if e.response.status_code == 404:
				logger.debug("Container not found (%s)" % id)
				raise ContainerNotFound()
			logger.exception(e)
			raise e
		logger.debug("Container found (%s)" % id)
		return service

	def _container_exists(self, id):
		logger.debug("Check if container exists (%s)" % id)
		try:
			self._get_container(id)
		except ContainerNotFound:
			return False
		return True

	def state(self, id):
		try:
			container = self._get_container(id)
		except ContainerNotFound:
			return False
		return container['State']['Running']

	@property
	def _start_command(self):
		start_command = "%s %smanage.py start_worker --vhost=%s --base=%s --username=%s --password=%s" % (
					"/home/planet/.virtualenvs/planet/bin/python",
					"/home/planet/code/app/",
					self.vhost,
					self.base_name,
					self.base_name, self.password
			)
		return start_command.split(" ")
		#return start_command	

class RemoteDockerExecutor(DockerExecutor):

	DOCKER_IMAGE = "tutum.co/philipsahli/skyblue-planet-worker:develop"

	def __init__(self, *args, **kwargs):
		"""
		tls_config = docker.tls.TLSConfig(
		  client_cert=('/path/to/client-cert.pem', '/path/to/client-key.pem'),
		  ca_cert='/path/to/ca.pem'
		)
		client = docker.Client(base_url='<https_url>', tls=tls_config)
		"""

		client_cert = load_setting("DOCKER_CLIENT_CERT")
		client_key = load_setting("DOCKER_CLIENT_KEY")
		#client_ca = load_setting("DOCKER_CLIENT_CA")

		login_user = load_setting("DOCKER_LOGIN_USER")
		login_pass = load_setting("DOCKER_LOGIN_PASS")
		login_email = load_setting("DOCKER_LOGIN_EMAIL")
		login_host = load_setting("DOCKER_LOGIN_HOST")


		ssl_version = "TLSv1"

		tls_config = TLSConfig(
		  client_cert=(client_cert, client_key),
		  #ca_cert=client_ca,
		  ssl_version=ssl_version,
		  verify=False,
		  assert_hostname=False
		)

		base_url = load_setting("DOCKER_TLS_URL")
		self.api = Client(base_url, tls=tls_config)

		self.api.login(
			username=login_user,
			password=login_pass,
			email=login_email,
			registry=login_host,
			reauth=True,
			insecure_registry=True,
			)

		super(DockerExecutor, self).__init__(*args, **kwargs)

	def _pre_start(self):
			if ":" in DOCKER_IMAGE:
				out = self.api.pull(repository=DOCKER_IMAGE.split(":")[0], tag=DOCKER_IMAGE.split(":")[1])
			else:
				out = self.api.pull(repository=DOCKER_IMAGE)
			logger.info(out)

class SpawnExecutor(BaseExecutor):

	def start(self, pid=None):
		self.pid = pid

		python_path = sys.executable
		try:
		    MODELSPY = os.path.join(settings.PROJECT_ROOT, "../../app_worker")
		    env = os.environ.copy()
		    env['EXECUTOR'] = "Spawn"
		    env['FASTAPP_CORE_SENDER_PASSWORD'] = load_setting("FASTAPP_CORE_SENDER_PASSWORD")
		    env['FASTAPP_WORKER_THREADCOUNT'] = str(load_setting("FASTAPP_WORKER_THREADCOUNT"))
		    env['FASTAPP_PUBLISH_INTERVAL'] = str(load_setting("FASTAPP_PUBLISH_INTERVAL"))
		    env['RABBITMQ_HOST'] = str(load_setting("WORKER_RABBITMQ_HOST"))
		    settings.SETTINGS_MODULE = "app_worker.settings"
		    p = subprocess.Popen("%s %s/manage.py start_worker --settings=%s --vhost=%s --base=%s --username=%s --password=%s" % (
			    python_path, MODELSPY, settings.SETTINGS_MODULE, self.vhost, self.base_name, self.base_name, self.password),
			    cwd=settings.PROJECT_ROOT,
			    shell=True, stdin=None, stdout=None, stderr=None, preexec_fn=os.setsid, env=env
			)
		    self.pid = p.pid
		except Exception, e:
		    raise e
		    
		return self.pid

	def stop(self, pid):
		if not pid:
			return
		try:
			os.killpg(int(pid), signal.SIGTERM)
		except OSError, e:
			logger.exception(e)
		except ValueError, e:
			logger.exception(e)

	def state(self, pid):
		# if pid, check
		if not pid:
			return False
		return (subprocess.call("/bin/ps -p %s -o command|egrep -c %s 1>/dev/null" % (pid, self.base_name), shell=True)==0)
