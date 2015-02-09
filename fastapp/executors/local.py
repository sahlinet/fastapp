import sys
import os
import signal
import subprocess
import logging

from django.conf import settings

logger = logging.getLogger(__name__)

class ContainerNotFound(Exception):
    pass

class BaseExecutor(object):
	def __init__(self, *args, **kwargs):
		self.vhost = kwargs['vhost']
		self.base_name = kwargs['base_name']
		self.username = kwargs['username']
		self.password = kwargs['password']

		self.name = "worker-%s" % self.base_name

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

class TutumExecutor(BaseExecutor):

	DOCKER_IMAGE = "tutum.co/philipsahli/skyblue-planet-worker:develop"

	def __init__(self, *args, **kwargs):
		import tutum
		self.api = tutum
		self.api.user = settings.TUTUM_USERNAME
		self.api.apikey = settings.TUTUM_APIKEY

		logger.info("Using TUTUM_USERNAME: %s" % self.api.user)

		super(TutumExecutor, self).__init__(*args, **kwargs)

	def start(self, id):
		new = not self._container_exists(id)
		if new:
			service = self.api.Service.create(image=TutumExecutor.DOCKER_IMAGE, 
				name=self.name.replace("_", "_"), 
				target_num_containers=1,
				mem_limit = "128m",
				cpu_shares = 512,
				container_envvars = [
					{ 'key': "FASTAPP_WORKER_THREADCOUNT", 'value': settings.FASTAPP_WORKER_THREADCOUNT },
					{ 'key': "FASTAPP_PUBLISH_INTERVAL", 'value': settings.FASTAPP_PUBLISH_INTERVAL},
					{ 'key': "RABBITMQ_HOST", 'value': settings.WORKER_RABBITMQ_HOST},
					{ 'key': "RABBITMQ_PORT", 'value': settings.WORKER_RABBITMQ_PORT},
					{ 'key': "RABBITMQ_ADMIN_USER", 'value': settings.RABBITMQ_ADMIN_USER},
					{ 'key': "RABBITMQ_ADMIN_PASSWORD", 'value': settings.RABBITMQ_ADMIN_USER},
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
			tag.add(['workers'])
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
				except ContainerNotFound:
					pass
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

		from docker import Client
		from docker.utils import kwargs_from_env
		docker_kwargs = kwargs_from_env()
		docker_kwargs['tls'].assert_hostname = False

		self.docker = Client(**docker_kwargs)

		super(DockerExecutor, self).__init__(*args, **kwargs)

	def start(self, id):
		if not self._container_exists(id):
			logger.info("Create container for %s" % self.vhost)

			container = self.docker.create_container(
				image = DockerExecutor.DOCKER_IMAGE,
				detach = True,
				mem_limit = "128m",
				cpu_shares = 512,
				environment = {
					'FASTAPP_WORKER_THREADCOUNT': settings.FASTAPP_WORKER_THREADCOUNT,
					'FASTAPP_PUBLISH_INTERVAL': settings.FASTAPP_PUBLISH_INTERVAL,
					'RABBITMQ_HOST': settings.WORKER_RABBITMQ_HOST,
					'RABBITMQ_PORT': settings.WORKER_RABBITMQ_PORT,
					'RABBITMQ_ADMIN_USER': "guest",
					'RABBITMQ_ADMIN_PASSWORD': "guest",
					'EXECUTOR': "docker"
				},
				name=self.name, 
				entrypoint = self._start_command
			)

		else:
			container = self._get_container(id)

		id = container.get('Id')
		logger.info("Start container (%s)" % id)
		self.docker.start(container=id)
		return id

	def stop(self, id):
		logger.info("Stop container (%s)" % id)
		self.docker.kill(id)

	def destroy(self, id):
		if self._container_exists(id):
			self.docker.remove_container(id)

	def _get_container(self, id):
		from docker import errors
		logger.debug("Get container (%s)" % id)
		try:
			service = self.docker.inspect_container(id)
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

class SpawnExecutor(BaseExecutor):

	def start(self, pid=None):
		self.pid = pid

		python_path = sys.executable
		try:
		    MODELSPY = os.path.join(settings.PROJECT_ROOT, "..")
		    env = os.environ.copy()
		    env['EXECUTOR'] = "Spawn"
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
