import pika
import logging
import time
import json
import sys
import os
import subprocess
import pytz
from datetime import datetime, timedelta


from django.core import serializers
from django.conf import settings
from django.db import DatabaseError
from django.db import transaction
from fastapp.executors.remote import distribute
from fastapp.models import Executor, Instance, Process, Thread, Transaction
from fastapp.queue import CommunicationThread

from fastapp.models import FINISHED

logger = logging.getLogger(__name__)

HEARTBEAT_QUEUE = "heartbeat_queue"
CONFIGURATION_QUEUE = "configuration"
SETTING_QUEUE = "setting"


def inactivate():

    transaction.set_autocommit(False)
    try:
        while True:
            time.sleep(0.1)
            now=datetime.now().replace(tzinfo=pytz.UTC)
            for instance in Instance.objects.filter(last_beat__lte=now-timedelta(minutes=1), is_alive=True):
                logger.warn("inactive instance '%s' detected" % instance)
                instance.mark_down()
                instance.save()

            # start if is_started and not running    
            try:
                for executor in Executor.objects.select_for_update(nowait=True).filter(started=True):
                    if not executor.is_running():
                        # log start with last beat datetime
                        executor.start()
            except DatabaseError, e:
                logger.error("Executor was locked with select_for_update")
                logger.exception(e)
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
            logger.debug("MEM-Usage of '%s': %s" % (parent_name, rss))
            process, created = Process.objects.get_or_create(name=parent_name)
            process.rss = int(rss)
            process.save()

            # threads
            for t in threads:
                logger.debug(t.name+": "+str(t.isAlive()))

                # store in db
                thread_model, created = Thread.objects.get_or_create(name=t.name, parent=process)
                if t.isAlive() and t.health():
                    logger.debug("Thread '%s' is healthy." % t.name)
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
                logger.debug("Process '%s' is healthy." % parent_name)
            else:
                logger.error("Process '%s' is not healthy. Threads: %s / %s" % (parent_name, alive_thread_count, thread_count))
            time.sleep(10)

    except Exception, e:
        logger.exception(e)



class HeartbeatThread(CommunicationThread):


    def send_message(self):
        logger.debug("send message to vhost: %s:%s" % (self.vhost, HEARTBEAT_QUEUE))
        payload = {'in_sync': self.in_sync}
        payload.update(self.additional_payload)
        self.channel.basic_publish(exchange='',
                routing_key=HEARTBEAT_QUEUE,
                properties=pika.BasicProperties(
                    expiration = str(2000)
                ),
                body=json.dumps(payload)
            )
        self.in_sync = True
        self.schedule_next_message()

    def on_message(self, ch, method, props, body):
        try:
            logger.debug(self.name+": "+sys._getframe().f_code.co_name)
            data = json.loads(body)
            vhost = data['vhost']
            base = vhost.split("-", 1)[1]

            logger.info("Heartbeat received from '%s'" % vhost)

            # store timestamp in DB
            from fastapp.models import Instance
            try:
                instance = Instance.objects.get(executor__base__name=base)
            except Instance.DoesNotExist, e:
                logger.error("instance does not exist")
                raise Exception()
            instance.is_alive = True
            instance.last_beat = datetime.now().replace(tzinfo=pytz.UTC)
            instance.save()

            if not data['in_sync']:
                logger.info("Run sync to vhost: "+vhost)
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
            logger.info("tout saved")


        except Exception, e:
            logger.exception(e)
        time.sleep(0.1)        