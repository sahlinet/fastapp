import logging 
import pika
import sys
import subprocess
import traceback
import threading
import time
import requests
import json
import urllib
from django.conf import settings

logger = logging.getLogger(__name__)


def generate_vhost_configuration(*args):
    separator = "-"
    vhost = "/"+separator.join(list(args))
    logger.debug("generate_vhost_configuration: %s" % vhost)
    traceback.print_exc()
    return vhost

def create_vhosts():
	from models import Base 
    # create the vhosts, users and permissions
	for base in Base.objects.all():
		create_vhost(base)

def create_broker_url(username, password, host, port, vhost):
	return "amqp://%s:%s@%s:%s/%s" % (username, password, host, port, vhost)

RABBITMQ_ADMIN = ["CTL", "HTTP_API"]

class RabbitmqAdmin(object):

    @staticmethod
    def factory(impl):
        if impl == "CTL":
            return RabbitmqAdminCtl()
        elif impl == "HTTP_API":
            return RabbitmqHttpApi()
        else:
            raise Exception("Set RABBITMQ_ADMIN to one of these values: "+str(RABBITMQ_ADMIN))

class RabbitmqAdminCtl(RabbitmqAdmin):

    def __init__(self):
        if sys.platform == "darwin":
            self.rabbitmqctl = "/usr/local/sbin/rabbitmqctl"
        else:
            self.rabbitmqctl = "sudo /usr/sbin/rabbitmqctl"

    def add_vhost(self, name):
        subprocess.Popen("%s add_vhost %s" % (self.rabbitmqctl, name), shell=True)
    def add_user(self, username, password):
        subprocess.Popen("%s add_user %s %s" % (self.rabbitmqctl, username, password), shell=True)
    def set_perms(self, vhost, username):
        subprocess.Popen("%s set_permissions -p %s %s \"^.*\" \".*\" \".*\" " % (self.rabbitmqctl, vhost, username), shell=True)

class RabbitmqHttpApi(RabbitmqAdmin):

    API_URI = "/api/"

    def _call(self, uri, data=None):
        logger.info(uri)
        logger.info(str(data))

        user = getattr(settings, "RABBITMQ_ADMIN_USER", "guest")
        password = getattr(settings, "RABBITMQ_ADMIN_PASSWORD", "guest")

        host = getattr(settings, "RABBITMQ_HOST", "localhost")
        port = getattr(settings, "RABBITMQ_HTTP_API_PORT", "15672")

        logger.debug(user)
        logger.debug(password)

        logger.debug(host)
        logger.debug(port)

        if data:
            data=json.dumps(data)
        url = "http://%s:%s" % (host, port)
        r = requests.put(url+uri, data=data, headers={'content-type': "application/json"}, auth=(user, password))
        if r.status_code != 204:
            logger.error(str((r.url, r.status_code, r.content)))
            sys.exit(1)
            raise Exception()

    def add_vhost(self, name):
        logger.info(name)
        self._call("/api/vhosts/%s" % urllib.quote_plus(name))

    def add_user(self, name, password):
        self._call("/api/users/%s" % name, data={'password': password, 'tags': "" })

    def set_perms(self, vhost, username):
        self._call("/api/permissions/%s/%s" % (urllib.quote_plus(vhost), username), data={"scope":"client","configure":".*","write":".*","read":".*"})

def create_vhost(base):
    # create the vhosts, users and permissions
    vhost = base.executor.vhost
    logger.info("Create vhost configuration: %s" % vhost)

    #service = RabbitmqAdmin.factory("CTL")
    service = RabbitmqAdmin.factory("HTTP_API")
    try:
        service.add_vhost(vhost)
        service.add_user(base.name, base.executor.password)
        service.set_perms(vhost, base.name)
    except Exception, e:
        logger.exception(e)
        sys.exit(1)
        raise e

def connect_to_queuemanager(host="localhost", vhost="/", username="guest", password="guest"):
    credentials = pika.PlainCredentials(username, password)
    logger.debug("Trying to connect to: %s, %s, %s, %s" % (host, vhost, username, password))
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=host, virtual_host=vhost, heartbeat_interval=20, credentials=credentials))
    except Exception, e:
        logger.exception(e)
        raise e
    return connection

def connect_to_queue(host, queue, vhost="/", username="guest", password="guest"):
    logger.debug("Connect to %s" % queue)
    try:
        #connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost', virtual_host=vhost, heartbeat_interval=20))
        connection = connect_to_queuemanager(host, vhost, username, password)
        channel = connection.channel()
        #d = channel.queue_declare(queue, durable=True)
        d = channel.queue_declare(queue)
        if d.method.__dict__['consumer_count']:
            logger.error("No consumer on queue %s" % queue)
    except Exception, e:
        logger.exception(e)
    return channel

class CommunicationThread(threading.Thread):

    def __init__(self, name, host, vhost, queues_produce=[], queues_consume=[], topic_receiver=[], username="guest", password="guest", additional_payload={}):
        threading.Thread.__init__(self)
        self.name = name
        self.additional_payload=additional_payload

        self.host = host
        self.vhost = vhost

        self.credentials = pika.PlainCredentials(username, password)

        self.in_sync = False

        self.is_connected = False

        self.queues_consume =  queues_consume
        self.queues_produce =  queues_produce
        self.topic_receiver = topic_receiver 

        self.exchange_count = len(self.topic_receiver)

    def run(self):
        self.parameters = pika.ConnectionParameters(
            host=self.host, 
            virtual_host=self.vhost, 
            heartbeat_interval=3, 
            credentials=self.credentials
            )
        logger.info("Starting " + self.name)

        #if self.receiver:
        #    self.on_queue_declared = self.consume_on_queue_declared
        #else:
        #    self.on_queue_declared = self.produce_on_queue_declared
        #print self.on_queue_declared

        self._run = True
        while self._run:
            try:
                self._connection = pika.SelectConnection(self.parameters, self.on_connected, on_close_callback=self.on_close)
                logger.info("'%s' connected" % self.name)
                self.is_connected = True 
            except Exception:
                self.is_connected = False
                #logger.warning('cannot connect', exc_info=True)
                logger.warning('cannot connect to %s' % str(self.parameters))
                time.sleep(3)
                continue

            try:
                self._connection.ioloop.start()
            except KeyboardInterrupt:
                self.stop()
            finally:
                pass
                try:
                    self._connection.close()
                    self._connection.ioloop.start() # allow connection to close
                except Exception, e:
                    logger.error("Heartbeat thread lost connection")
                    logger.exception(e)

    def stop(self):
        logger.info(self.name+": "+sys._getframe().f_code.co_name)
        self._run = False
        logger.info('Stopping')
        self._stopping = True
        self._connection.ioloop.start()
        logger.info('Stopped')

    def health(self):
        return self.is_connected

    def on_close(self, connection, reply_code, reply_text):
        self.connected = False
        logger.debug(self.name+": "+sys._getframe().f_code.co_name)

    def consume_on_queue_declared(self, frame):
        logger.debug(self.name+": "+sys._getframe().f_code.co_name)
        logger.debug(frame)

        for queue in self.queues_consume:
            #self.channel.basic_consume(self.on_message, queue=queue[0], no_ack=True)
            ack = False
            if len(queue) == 2:
                ack = queue[1]
            self.channel.basic_consume(self.on_message, queue=queue[0], no_ack=ack)

    def on_queue_declared_for_exchange(self, frame):
        logger.debug(self.name+": "+sys._getframe().f_code.co_name)
        logger.debug(frame.method.queue)
        logger.debug(frame)
        self.channel.queue_bind(exchange="configuration", queue=frame.method.queue, callback=None)
        self.channel.basic_consume(self.on_message, queue=frame.method.queue, no_ack=True)

    def on_exchange_declare(self, frame):
        logger.debug(self.name+": "+sys._getframe().f_code.co_name)

        self.exchange_count -= 1
        if self.exchange_count == 0:
            self.channel.queue_declare(exclusive=True, callback=self.on_queue_declared_for_exchange)

    def produce_on_queue_declared(self, frame):
        logger.debug(self.name+": "+sys._getframe().f_code.co_name)
        logger.debug("Sending message from %s" % self.name)
        self.send_message()

    def on_connected(self, connection):
        logger.debug(self.name+": "+sys._getframe().f_code.co_name)
        self.is_connected = True
        self._connection.channel(self.on_channel_open)

    def on_channel_open(self, channel):
        logger.debug(self.name+": "+sys._getframe().f_code.co_name)
        logger.debug("channel opened: "+str(channel))

        # queue consumer
        for queue in self.queues_consume:
            channel.queue_declare(queue=queue[0], callback=self.consume_on_queue_declared)

        # queue producer
        for queue in self.queues_produce:
            channel.queue_declare(queue=queue[0], callback=self.produce_on_queue_declared)

        # topic receiver
        for topic in self.topic_receiver:
            logger.info("Topic: "+str(topic[0]))
            #channel.exchange_declare(exchange=topic[0], type='fanout')
            channel.exchange_declare(exchange="configuration", type='fanout', callback=self.on_exchange_declare)
            #result = channel.queue_declare(exclusive=True)
            #channel.queue_bind(exchange="configuration", queue=result.method.queue)

        self.channel = channel



