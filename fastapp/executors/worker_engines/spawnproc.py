import sys
import os
import signal
import subprocess
import logging
import atexit

from django.conf import settings
from django.contrib.sites.models import Site
from django.core.exceptions import ImproperlyConfigured

from fastapp.executors.worker_engines import BaseExecutor, ContainerNotFound
from fastapp.utils import load_setting, load_var_to_file
from fastapp.plugins import call_plugin_func

logger = logging.getLogger(__name__)


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
