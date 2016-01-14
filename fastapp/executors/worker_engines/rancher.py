import logging
import requests

from django.conf import settings

from fastapp.executors.worker_engines import BaseExecutor, ContainerNotFound

logger = logging.getLogger(__name__)


MEM_LIMIT = "96m"
#CPU_SHARES = 512

DOCKER_IMAGE = getattr(settings, 'FASTAPP_DOCKER_IMAGE',
                            'philipsahli/skyblue-planet-lite-worker:develop')


class RancherApiExecutor(BaseExecutor):

    def __init__(self, *args, **kwargs):
    	self.auth=requests.auth.HTTPBasicAuth(settings.RANCHER_ACCESS_KEY, settings.RANCHER_ACCESS_SECRET)
        self.environment_id = settings.RANCHER_ENVIRONMENT_ID

    	self.url = settings.RANCHER_URL + "/v1/services"
        logging.info("Using URL to rancher: %s" % self.url)

        super(RancherApiExecutor, self).__init__(*args, **kwargs)

    def _call_rancher(self, uri_appendix, data=None, force_post=False):
        url = self.url+"%s" % uri_appendix
    	if data or force_post:
            logger.info("POST to %s" % url)
            r = requests.post(url, json=data, auth=self.auth)
        else:
            logger.info("GET to %s" % url)
            r = requests.get(url, auth=self.auth)
        #logger.debug(r.text)
        try:
            json_response = r.json()
        except:
            json_response = None
        logger.debug(r.status_code)
        if r.status_code == 422:
            logger.error(r.text)
        return r.status_code, json_response

    def _get_container(self, id):
    	status_code, response = self._call_rancher("/%s" % id)
        if status_code == 404:
            logger.debug("Container not found (%s)" % id)
            raise ContainerNotFound()
        logger.debug("Container found (%s)" % id)


        return response

    def _container_exists(self, id):
        logger.debug("Check if container exists (%s)" % id)
        try:
            self._get_container(id)
        except ContainerNotFound:
            return False
        return True

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

    def start(self, id, *args, **kwargs):
        if not self._container_exists(id):

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
            json_data = {
                	"scale": 1,
                	"type": "service",
                	"environmentId": self.environment_id,
                	"launchConfig": {
                		"networkMode": "managed",
                		"privileged": False,
                		"publishAllPorts": False,
                		"readOnly": False,
                		"startOnCreate": True,
                		"stdinOpen": True,
                		"tty": True,
                		"type": "launchConfig",
                		"restartPolicy": {
                			"name": "always"
                		},
                		"imageUuid": "docker:"+DOCKER_IMAGE,
                		"dataVolumes": [

                		],
                		"dataVolumesFrom": [

                		],
                		"dns": [
                			"8.8.8.8"
                		],
                		"dnsSearch": [

                		],
                		"capAdd": [

                		],
                		"capDrop": [

                		],
                		"devices": [

                		],
                		"labels": {
                			#"io.rancher.scheduler.affinity:host_label": "nodelabel=nodelabel",
                			"io.rancher.container.pull_image":  "always",
                			"io.rancher.container.dns": False
                		},
                		"ports": [
                			#"10034:8080/tcp"
                		],
                		"command": self._start_command,
                		"environment": env,
                		"healthCheck": None,
                		"allocationState": None,
                		"count": None,
                		"cpuSet": None,
                		"cpuShares": 1024,
                		"createIndex": None,
                		"created": None,
                		"deploymentUnitUuid": None,
                		"description": None,
                		"domainName": None,
                		"externalId": None,
                		"firstRunning": None,
                		"healthState": None,
                		"hostname": None,
                		"kind": None,
                		#"memory": 100663296,
                		"memorySwap": None,
                		"pidMode": None,
                		"removeTime": None,
                		"removed": None,
                		"startCount": None,
                		"systemContainer": None,
                		"token": None,
                		"user": None,
                		"uuid": None,
                		"volumeDriver": None,
                		"workingDir": None,
                		"networkLaunchConfig": None
                	},
                	"secondaryLaunchConfigs": [

                	],
                	"name": self.name,
                	"createIndex": None,
                	"created": None,
                	"description": None,
                	"externalId": None,
                	"kind": None,
                	"removeTime": None,
                	"removed": None,
                	"selectorContainer": None,
                	"selectorLink": None,
                	"uuid": None,
                	"vip": None,
                	"fqdn": None
                }
            logger.debug(json_data)
            status_code, response = self._call_rancher("/", json_data)
            id = response['id']

        import time
        time.sleep(3)
        status_code, response = self._call_rancher("/%s?action=activate" % id, force_post=True)

        timeout = 30
        c = 0
        while c < timeout:
            c=c+1
            import time
            time.sleep(2)

            if self.state(id):
                logger.info("Started")
                return id

        logger.error("Timed out waiting for state 'active'")
        return id


    def stop(self, id, *args, **kwargs):
        if self._container_exists(id):
            status_code, response = self._call_rancher("/%s?action=deactivate" % id, force_post=True)
        return True

    def destroy(self, id, *args, **kwargs):
        if self._container_exists(id):
            status_code, response = self._call_rancher("/%s?action=remove" % id, force_post=True)
        return True

    def log(self, id, *args, **kwargs):
        pass

    #def addresses(self, id, *args, **kwargs):
    #    pass

    def state(self, id):
        try:
            container = self._get_container(id)
        except ContainerNotFound:
            return False
        logger.info("Worker is in state: "+container['state'])
        return (container['state'] == "active")
