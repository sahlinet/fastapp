import sys
import os
import signal
import subprocess
import logging
import tutum
import random
import atexit

from docker import Client
from docker.tls import TLSConfig
from docker.utils import kwargs_from_env
from docker.errors import APIError

from django.conf import settings
from django.contrib.sites.models import Site
from django.core.exceptions import ImproperlyConfigured

from fastapp.utils import load_setting, load_var_to_file
from fastapp.plugins import call_plugin_func

logger = logging.getLogger(__name__)


class ContainerNotFound(Exception):
    pass

MEM_LIMIT = "128m"
#CPU_SHARES = 512

DOCKER_IMAGE = getattr(settings, 'FASTAPP_DOCKER_IMAGE',
                            'philipsahli/skyblue-planet-lite-worker:develop')


class BaseExecutor(object):
    def __init__(self, *args, **kwargs):
        self.vhost = kwargs['vhost']
        self.base_name = kwargs['base_name']
        self.username = kwargs['username']
        self.password = kwargs['password']
        self.executor = kwargs['executor']

        # container name, must be unique, therefore we use a mix from site's domain name and executor
        slug = "worker-%s-%i-%s" % (Site.objects.get_current().domain,
            random.randrange(1,900000), self.base_name)
        self.name = slug.replace("_", "-").replace(".", "-")

    def addresses(self, id):

        return {
            'ip': None,
            'ip6': None
            }

    @property
    def _start_command(self):
        start_command = "%s %smanage.py start_worker --vhost=%s --base=%s --username=%s --password=%s" % (
                    "/home/planet/.virtualenvs/planet/bin/python",
                    "/home/planet/code/app/",
                    self.vhost,
                    self.base_name,
                    self.base_name, self.password
                    )
        return start_command

    def destroy(self, id):
        logger.info("Executor does not support 'destroy'")

    def _pre_start(self):
        success, failed = call_plugin_func(self.executor.base, "on_start_base")
        if len(failed.keys()) > 0:
            logger.warning("Problem with on_start_base for plugin (%s)" % str(failed))
        print success
        print failed

    def log(self, id):
        raise NotImplementedError()


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

            container_envvars = [
                {'key': "RABBITMQ_HOST",
                 'value': settings.WORKER_RABBITMQ_HOST},
                {'key': "RABBITMQ_PORT",
                 'value': settings.WORKER_RABBITMQ_PORT},
                {'key': "FASTAPP_WORKER_THREADCOUNT",
                 'value': settings.FASTAPP_WORKER_THREADCOUNT},
                {'key': "FASTAPP_PUBLISH_INTERVAL",
                 'value': settings.FASTAPP_PUBLISH_INTERVAL},
                {'key': "FASTAPP_CORE_SENDER_PASSWORD",
                 'value': settings.FASTAPP_CORE_SENDER_PASSWORD},
                {'key': "EXECUTOR", 'value': "Tutum"},
            ]
            # create the service
            service = self.api.Service.create(image=DOCKER_IMAGE,
                                              name=self.name,
                                              target_num_containers=1,
                                              mem_limit=MEM_LIMIT,
                                              #cpu_shares=CPU_SHARES,
                                              container_envvars=container_envvars,
                                              autorestart="ALWAYS",
                                              entrypoint=self._start_command
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

    def __init__(self, *args, **kwargs):

        docker_kwargs = kwargs_from_env()
        docker_kwargs['tls'].assert_hostname = False

        self.api = Client(**docker_kwargs)

        super(DockerExecutor, self).__init__(*args, **kwargs)

    def start(self, id, *args, **kwargs):

        self._pre_start()

        self.service_ports = []
        if kwargs.has_key('service_ports'):
            self.service_ports = kwargs.get('service_ports')
        self.port_bindings = {}
        for port in self.service_ports:
            self.port_bindings[port] = port
        logger.info(self.service_ports)
        logger.info(self.port_bindings)

        if not self._container_exists(id):
            logger.info("Create container for %s" % self.vhost)
            import docker

            env = {
                    'RABBITMQ_HOST': settings.WORKER_RABBITMQ_HOST,
                    'RABBITMQ_PORT': settings.WORKER_RABBITMQ_PORT,
                    'FASTAPP_WORKER_THREADCOUNT': settings.FASTAPP_WORKER_THREADCOUNT,
                    'FASTAPP_PUBLISH_INTERVAL': settings.FASTAPP_PUBLISH_INTERVAL,
                    'FASTAPP_CORE_SENDER_PASSWORD': settings.FASTAPP_CORE_SENDER_PASSWORD,
                    'EXECUTOR': "docker",
                    'SERVICE_PORT': self.executor.port,
                    'SERVICE_IP': self.executor.ip
                }
            if self.executor.ip6:
                env['SERVICE_IP6'] = self.executor.ip6

            # feed environment variables with vars from plugins
            success, failed = call_plugin_func(self.executor, "executor_context")
            if len(failed.keys()) > 0:
                logger.warning("Problem with executor_context for plugin (%s)" % str(failed))
            for plugin, context in success.items():
                logger.info("Set context for plugin %s" % plugin)
                env.update(context)

            container = self.api.create_container(
                image = DOCKER_IMAGE,
                name = self.name,
                detach = True,
                ports = self.service_ports,
                #mem_limit = MEM_LIMIT,
                #cpu_shares = CPU_SHARES,
                environment = env,
                host_config=docker.utils.create_host_config(
                    port_bindings=self.port_bindings
                    ),
                entrypoint = self._start_command
            )

        else:
            container = self._get_container(id)

        id = container.get('Id')
        logger.info("Start container (%s)" % id)
        self.api.start(container=id)
        return id

    def addresses(self, id):
        container = self._get_container(id)
        return {
            'ip': container['NetworkSettings']['IPAddress'],
            'ip6': container['NetworkSettings']['GlobalIPv6Address']
            }

    def stop(self, id):
        logger.info("Stop container (%s)" % id)
        self.api.kill(id)

    def destroy(self, id):
        if self._container_exists(id):
            self.api.remove_container(id)

    def _get_container(self, id):
        if not id:
            raise ContainerNotFound()
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

    def _login_repository(self):

        try:
            login_user = load_setting("DOCKER_LOGIN_USER", False)
            login_pass = load_setting("DOCKER_LOGIN_PASS", False)
            login_email = load_setting("DOCKER_LOGIN_EMAIL", False)
            login_host = load_setting("DOCKER_LOGIN_HOST", False)
        except ImproperlyConfigured, e:
            pass

        if login_user:
            self.api.login(
                username=login_user,
                password=login_pass,
                email=login_email,
                registry=login_host,
                reauth=True,
                insecure_registry=True,
            )

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

    def log(self, id):
        return self.api.logs(id,
                      stdout=True,
                      stderr=True,
                      stream=False,
                      timestamps=True,
                      tail=100,
        )

        # https://github.com/docker/docker-py/issues/656
        #return self.api.attach(id, logs=True, stream=True)


class DockerSocketExecutor(DockerExecutor):

    def __init__(self, *args, **kwargs):
        self.api = Client(base_url='unix://var/run/docker.sock')

        BaseExecutor.__init__(self, *args, **kwargs)


class RemoteDockerExecutor(DockerExecutor):

    def __init__(self, *args, **kwargs):
        """
        tls_config = docker.tls.TLSConfig(
          client_cert=('/path/to/client-cert.pem', '/path/to/client-key.pem'),
          ca_cert='/path/to/ca.pem'
        )
        client = docker.Client(base_url='<https_url>', tls=tls_config)
        """

        client_cert = load_var_to_file("DOCKER_CLIENT_CERT")
        client_key = load_var_to_file("DOCKER_CLIENT_KEY")

        ssl_version = "TLSv1"

        tls_config = TLSConfig(client_cert=(client_cert, client_key),
                               ssl_version=ssl_version,
                               verify=False,
                               assert_hostname=False
        )

        base_url = load_setting("DOCKER_TLS_URL")
        self.api = Client(base_url, tls=tls_config)

        self._login_repository()

        super(DockerExecutor, self).__init__(*args, **kwargs)


    def _pre_start(self):
        try:
            if ":" in DOCKER_IMAGE:
                out = self.api.pull(repository=DOCKER_IMAGE.split(":")[0], tag=DOCKER_IMAGE.split(":")[1])
            else:
                out = self.api.pull(repository=DOCKER_IMAGE)
            logger.info(out)
        except APIError, e:
            logger.warn("Not able to pull image")
            logger.warn(e)


class SpawnExecutor(BaseExecutor):

    def start(self, pid=None, **kwargs):
        self.pid = pid

        self._pre_start()

        python_path = sys.executable
        try:
            MODELSPY = os.path.join(settings.PROJECT_ROOT, "../../app_worker")
            env = os.environ.copy()
            env['EXECUTOR'] = "Spawn"
            env['FASTAPP_CORE_SENDER_PASSWORD'] = load_setting("FASTAPP_CORE_SENDER_PASSWORD")
            env['FASTAPP_WORKER_THREADCOUNT'] = str(load_setting("FASTAPP_WORKER_THREADCOUNT"))
            env['FASTAPP_PUBLISH_INTERVAL'] = str(load_setting("FASTAPP_PUBLISH_INTERVAL"))
            env['RABBITMQ_HOST'] = str(load_setting("WORKER_RABBITMQ_HOST"))
            env['RABBITMQ_PORT'] = str(load_setting("WORKER_RABBITMQ_PORT"))
            python_paths = ""
            try:
                for p in os.environ['PYTHONPATH'].split(":"):
                    logger.info(p)
                    python_paths += ":"+os.path.abspath(p)
            except KeyError:
                pass
            env['PYTHONPATH'] = python_paths
            logger.info(env['PYTHONPATH'])
            settings.SETTINGS_MODULE = "app_worker.settings"
            p = subprocess.Popen("%s %s/manage.py start_worker --settings=%s --vhost=%s --base=%s --username=%s --password=%s" % (
                python_path, MODELSPY, settings.SETTINGS_MODULE, self.vhost, self.base_name, self.base_name, self.password),
                cwd=settings.PROJECT_ROOT,
                shell=True, stdin=None, stdout=None, stderr=None, preexec_fn=os.setsid, env=env
            )
            atexit.register(p.terminate)
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
