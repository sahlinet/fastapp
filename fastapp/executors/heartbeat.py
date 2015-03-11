import pika
import logging
import time
import json
import sys
import os
import subprocess
import pytz
from datetime import datetime, timedelta

from django.core.urlresolvers import reverse
from django.test import RequestFactory
from django.contrib.auth import get_user_model
from django.core import serializers
from django.conf import settings
from django.db import DatabaseError
from django.db import transaction

from fastapp.executors.remote import distribute
from fastapp.models import Base, Instance, Process, Thread, Transaction
from fastapp.queue import CommunicationThread

from fastapp.models import FINISHED
from fastapp.utils import load_setting

logger = logging.getLogger(__name__)

HEARTBEAT_VHOST = load_setting('CORE_VHOST')
HEARTBEAT_QUEUE = load_setting('HEARTBEAT_QUEUE')
CONFIGURATION_QUEUE = "configuration"
SETTING_QUEUE = "setting"


def inactivate():

    transaction.set_autocommit(False)
    try:
        while True:
            time.sleep(0.1)
            now=datetime.now().replace(tzinfo=pytz.UTC)
            for instance in Instance.objects.filter(last_beat__lte=now-timedelta(minutes=1), is_alive=True):
                logger.info("inactive instance '%s' detected, mark stopped" % instance)
                instance.mark_down()
                instance.save()

            # start if is_started and not running
            try:
                  for base in Base.objects.select_for_update(nowait=True).filter(executor__started=True):
                #for executor in Executor.objects.select_for_update(nowait=True).filter(started=True):
                    if not base.executor.is_running():
                        # log start with last beat datetime
                        logger.warn("start worker for not running base: %s" % base.name)
                        base.executor.start()
            except DatabaseError, e:
                logger.warning("Executor was locked with select_for_update")
                #logger.exception(e)
                transaction.rollback()
            transaction.commit()
            time.sleep(10)
    except Exception, e:
        logger.exception(e)
        transaction.rollback()

def update_status(parent_name, thread_count, threads):
    try:
        while True:
            time.sleep(0.1)
            alive_thread_count = 0
            
            pid = os.getpid()
            args = ["ps", "-p", str(pid), "-o", "rss="]
            proc = subprocess.Popen(args, stdout=subprocess.PIPE)
            (out, err) = proc.communicate()
            rss = str(out).rstrip().strip().lstrip()
            #logger.debug("MEM-Usage of '%s': %s" % (parent_name, rss))
            process, created = Process.objects.get_or_create(name=parent_name)
            process.rss = int(rss)
            process.save()

            # threads
            for t in threads:
                #logger.debug(t.name+": "+str(t.isAlive()))

                # store in db
                thread_model, created = Thread.objects.get_or_create(name=t.name, parent=process)
                if t.isAlive() and t.health():
                    #logger.debug("Thread '%s' is healthy." % t.name)
                    thread_model.started()
                    alive_thread_count=alive_thread_count+1
                else:
                    logger.warn("Thread '%s' is not healthy." % t.name)
                    thread_model.not_connected()
                thread_model.save()

            # process functionality
            if thread_count == alive_thread_count:
                process.up()
                process.save()
                #logger.debug("Process '%s' is healthy." % parent_name)
            else:
                logger.error("Process '%s' is not healthy. Threads: %s / %s" % (parent_name, alive_thread_count, thread_count))
            time.sleep(10)

    except Exception, e:
        logger.exception(e)



class HeartbeatThread(CommunicationThread):

    def send_message(self):
	"""
	Client functionality for heartbeating and sending statistics.
	"""
        logger.debug("send heartbeat to %s:%s" % (self.vhost, HEARTBEAT_QUEUE))
        pid = os.getpid()
        args = ["ps", "-p", str(pid), "-o", "rss="]
        proc = subprocess.Popen(args, stdout=subprocess.PIPE)
        (out, err) = proc.communicate()
        rss = str(out).rstrip().strip().lstrip()
        #logger.debug("MEM-Usage of '%s': %s" % (pid, rss))

        thread_list_status = [ thread.state for thread in self.thread_list]

        if self.ready_for_init:
            self.ready_for_init = False

        if self.on_next_ready_for_init:
            self.ready_for_init = True
            self.on_next_ready_for_init = False

        if not self.in_sync:
            self.ready_for_init = False
        import fastapp
        payload = {
    		'in_sync': self.in_sync,
            'ready_for_init': self.ready_for_init,
            'threads': {
                'count': len(self.thread_list),
                'list': thread_list_status
            },
    		'rss': rss,
            'version': fastapp.__version__,
	    }
        payload.update(self.additional_payload)
        self.channel.basic_publish(exchange='',
                routing_key=HEARTBEAT_QUEUE,
                properties=pika.BasicProperties(
                    expiration = str(2000)
                ),
                body=json.dumps(payload)
            )

        if not self.in_sync:
            print "Set to true ready_for_init"
            self.on_next_ready_for_init = True

        self.in_sync = True

        self.schedule_next_message()

    def on_message(self, ch, method, props, body):
	"""
	Server functionality for storing status and statistics.
	"""

        try:
            data = json.loads(body)
            vhost = data['vhost']
            base = vhost.split("-", 1)[1]
            logger.info("** '%s' Heartbeat received from '%s'" % (self.name, vhost))

            # store timestamp in DB
            from fastapp.models import Instance
            try:
                instance = Instance.objects.get(executor__base__name=base)
            except Instance.DoesNotExist, e:
                logger.error("Instance does not exist")
                raise Exception()
            instance.is_alive = True
            instance.last_beat = datetime.now().replace(tzinfo=pytz.UTC)
            instance.save()

            process, created = Process.objects.get_or_create(name=vhost)
            process.rss = int(data['rss'])
            if data.has_key('version'):
                process.version = data['version']
            process.save()

            #logger.info(data['ready_for_init'], data['in_sync'])

            # verify and warn for incomplete threads
            base_obj = Base.objects.get(name=base)
            for thread in data['threads']['list']:
                try: 
                    thread_obj, created = Thread.objects.get_or_create(name=thread['name'], parent=process)
                    if thread['connected']:
                        thread_obj.health = Thread.STARTED
                    else:
                        thread_obj.health = Thread.STOPPED
                    thread_obj.save()
                    if thread['count_settings'] != len(base_obj.setting.all()):
                        pass
                        #logger.debug("%s is incomplete" % thread['name'])
                        #print("%s is incomplete" % thread['name'])
                    else:
                        pass
                        #logger.debug("%s is complete" % thread['name'])
                        #print("%s is complete" % thread['name'])
                except Exception, e:
                    #logger.exception(e)
                    pass

            if not data['in_sync']:
                from fastapp.models import Apy, Setting
                for instance in Apy.objects.filter(base__name=base):
                    distribute(CONFIGURATION_QUEUE, serializers.serialize("json", [instance,]), 
                        vhost,
                        instance.base.name,
                        instance.base.executor.password
                        )

                for instance in Setting.objects.filter(base__name=base):
                    distribute(SETTING_QUEUE, json.dumps({
                        instance.key: instance.value
                        }), 
                        vhost,
                        instance.base.name,
                        instance.base.executor.password
                    )

            if data.has_key('ready_for_init') and data['ready_for_init']:

                ## execute init exec
                try:
                    init = base_obj.apys.get(name='init')
                    url = reverse('exec', kwargs={'base': base_obj.name, 'id': init.name})

                    request_factory = RequestFactory()
                    request = request_factory.get(url, data={'base': base_obj.name, 'id': init.name}) 
                    # TODO: fails if user admin is not created
                    request.user = get_user_model().objects.get(username='admin')

                    from fastapp.views import DjendExecView
                    view = DjendExecView()
                    response = view.get(request, base=base_obj.name, id=init.name)
                    logger.info("Init method called for base %s, response_code: %s" % (base_obj.name, response.status_code))

                except Exception, e:
                    logger.exception(e)
                    print e



        except Exception, e:
            logger.exception(e)
        time.sleep(0.1)        



    def schedule_next_message(self):
        #logger.info('Next beat in %0.1f seconds',
                    #self.PUBLISH_INTERVAL)
        self._connection.add_timeout(settings.FASTAPP_PUBLISH_INTERVAL,
                                     self.send_message)


class AsyncResponseThread(CommunicationThread):

    def on_message(self, ch, method, props, body):
        try:
            logger.debug(self.name+": "+sys._getframe().f_code.co_name)
            data = json.loads(body)

            logger.info("Async response received for rid '%s'" % data['rid'])
            logger.info(data)

            transaction = Transaction.objects.get(pk=data['rid'])
            transaction.tout = data
            transaction.status = FINISHED
            transaction.save()

        except Exception, e:
            logger.exception(e)
        time.sleep(0.1)        
