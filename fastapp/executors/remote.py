import pika
import uuid
import os
import json
import copy
import logging
import sys
import traceback
import base64
from bunch import Bunch

from django.conf import settings

from fastapp.queue import connect_to_queuemanager, CommunicationThread
from fastapp.utils import load_setting


logger = logging.getLogger(__name__)

RESPONSE_TIMEOUT = 30
CONFIGURATION_QUEUE = "configuration"
CONFIGURATION_EVENT = CONFIGURATION_QUEUE
SETTINGS_EVENT = "setting"

CONFIGURATION_QUEUE = "configuration"
SETTING_QUEUE = "setting"
RPC_QUEUE = "rpc_queue"
STATIC_QUEUE = "static_queue"

class Worker():

    def start(self):
        pass

    def stop(self):
        pass

    def is_running(self):
        pass

    def running(self):
        pass

    def update(self):
        pass

    def execute(self):
        pass

def distribute(event, body, vhost, username, password):
    logger.debug("distribute called")

    class ExecutorClient(object):
        """
        Gets the apy (id, name, module) and sets them on the _do function.__add__ .
        Then the client is ready to response for execution requests.

        """
        def __init__(self, vhost, event, username, password):
            # get needed stuff
            self.vhost = vhost
            self.event = event 
            self.username = username
            self.password = password
            logger.debug("exchanging message to vhost : %s" % self.vhost)
            logger.debug("exchanging message to vhost username: %s" % self.username)
            logger.debug("exchanging message to vhost password: %s" % self.password)
            self.connection = connect_to_queuemanager(
            		host=settings.RABBITMQ_HOST,
                    vhost=vhost,
                    username=username,
                    password=password,
            		port=settings.RABBITMQ_PORT,
                )

            self.channel = self.connection.channel()
            self.channel.exchange_declare(exchange=CONFIGURATION_QUEUE, type='fanout')


        def call(self, body):
            self.channel.basic_publish(exchange=CONFIGURATION_QUEUE,
                                       routing_key='',
                                       body=body,
                                       properties=pika.BasicProperties(app_id=event))

            self.connection.close()

    executor = ExecutorClient(vhost, event, username, password)
    executor.call(body)

    return  True

def call_rpc_client(apy, vhost, username, password, async=False):

    class ExecutorClient(object):
        """
        Gets the apy (id, name, module) and sets them on the _do function.__add__ .
        Then the client is ready to response for execution requests.

        """
        def __init__(self, vhost, username, password, async=False):
            # get needed stuff
            self.vhost = vhost
            self.connection = connect_to_queuemanager(
    		        host=settings.RABBITMQ_HOST,
                    vhost=vhost,
                    username=username,
                    password=password,
		            port=settings.RABBITMQ_PORT
                ) 

            logger.debug("exchanging message to vhost: %s" % self.vhost)

            self.channel = self.connection.channel()

            self.async = async

            self._set_callback_queue()


        def _set_callback_queue(self):

            if not self.async:
                result = self.channel.queue_declare(exclusive=True)
                self.callback_queue = result.method.queue
            else:
                self.callback_queue = "async_callback"
                result = self.channel.queue_declare(queue=self.callback_queue)

            self.channel.basic_consume(self.on_response, no_ack=True,
                                       queue=self.callback_queue)

        def on_timeout(self):
            logger.error("timeout in waiting for response")
            raise Exception("Timeout")

        def on_response(self, ch, method, props, body):
            if self.corr_id == props.correlation_id:
                self.response = body
                logger.debug("from rpc queue: "+body)

        def call(self, n):
            if not self.async:
                self.connection.add_timeout(RESPONSE_TIMEOUT, self.on_timeout)
            self.response = None
            self.corr_id = str(uuid.uuid4())
            expire = 5000
            logger.debug("Message expiration set to %s ms" % str(expire))
            self.channel.basic_publish(exchange='',
                                       routing_key=RPC_QUEUE,
                                       properties=pika.BasicProperties(
                                             reply_to = self.callback_queue,
                                             delivery_mode=1,
                                             correlation_id = self.corr_id,
                                             expiration=str(expire)
                                             ),
                                       body=str(n))
            logger.info("Message published to: %s:%s" % (self.vhost, RPC_QUEUE))
            while self.response is None and not self.async:
                self.connection.process_data_events()
            return self.response

        def end(self):
            self.channel.close()
            self.connection.close()
            del self.channel
            del self.connection

    if not async:
        executor = ExecutorClient(vhost, username, password)
    else:
        executor = ExecutorClient(vhost, load_setting("CORE_RECEIVER_USERNAME"), load_setting("FASTAPP_CORE_RECEIVER_PASSWORD"), async=async)


    try:
        response = executor.call(apy)
        #import pdb; pdb.set_trace()
    except Exception, e:
        logger.warn(e)
        response = json.dumps({u'status': u'TIMEOUT', u'exception': None, u'returned': None, 'id': u'cannot_import'})
    finally:
        executor.end()
    return response


STATE_OK = "OK"
STATE_NOK = "NOK"
STATE_NOT_FOUND = "NOT_FOUND"

threads = []




class ExecutorServerThread(CommunicationThread):
    def __init__(self, *args, **kwargs ):
        self.functions = {}
        self.settings = {}

        return super(ExecutorServerThread, self).__init__(*args, **kwargs)

    @property
    def state(self):
        return {'name': self.name, 
           'count_settings': len(self.settings), 
           'count_functions': len(self.functions), 
           'settings': self.settings.keys(),
           'functions': self.functions.keys(),
           'connected': self.is_connected
        }

    def on_message(self, ch, method, props, body):
        logger.debug(self.name+": "+sys._getframe().f_code.co_name)
        try:
            if method.exchange == "configuration":
                if props.app_id == "configuration":
                    fields = json.loads(body)[0]['fields']
                    try:
                        exec fields['module'] in globals(), locals()
                        self.functions.update({
                            fields['name']: func,
                            })
                        logger.info("Configuration '%s' received in %s" % (fields['name'], self.name))
                    except Exception, e:
                        traceback.print_exc()

                elif props.app_id == "setting":
                    json_body = json.loads(body)
                    key = json_body.keys()[0]
                    self.settings.update(json_body)
                    logger.info("Setting '%s' received in %s" % (key, self.name))
                else:
                    logger.error("Invalid event arrived (%s)" % props.app_id)  

            if method.routing_key == RPC_QUEUE:
                logger.info("Request received in %s (%s)" % (self.name, str(props.reply_to)))
                try:
                    response_data = {}
                    response_data = _do(json.loads(body), self.functions, self.settings)
                except Exception, e:
                    logger.exception(e)
                finally:
                    if props.reply_to == "async_callback":
                        # TODO: should be a user with less permissions
                        connection = connect_to_queuemanager(
                                self.host,
                                load_setting("CORE_VHOST"),
                                load_setting("CORE_SENDER_USERNAME"),
                                load_setting("FASTAPP_CORE_SENDER_PASSWORD"),
                                self.port
                            )
                        channel = connection.channel()
                        response_data.update({'rid': json.loads(body)['rid']})
                        channel.basic_publish(exchange='',
                            routing_key="async_callback",
                            properties=pika.BasicProperties(
                                #expiration = str(2000)
                            ),
                            body=json.dumps(response_data)
                        )
                        connection.close()

                    else:
                        ch.basic_publish(exchange='',
                                         routing_key=props.reply_to,
                                         properties=pika.BasicProperties(
                                            correlation_id = props.correlation_id,
                                            delivery_mode=1,
                                            ),
                                         body=json.dumps(response_data))
                    logger.debug("ack message")
                    ch.basic_ack(delivery_tag = method.delivery_tag)
                logger.info("Response sent %s (%s)" % (self.name, str(props.reply_to)))
        except Exception, e:
            logger.exception(e)


    #def __repr__(self):
    #    return self.__dict__

class ApyNotFound(Exception):
    pass

class ApyError(Exception):
    pass

from fastapp.queue import connect_to_queue
def log_to_queue(tid, level, msg):
    host = settings.RABBITMQ_HOST
    port = settings.RABBITMQ_PORT
    user = getattr(settings, "RABBITMQ_ADMIN_USER", "guest")
    password = getattr(settings, "RABBITMQ_ADMIN_PASSWORD", "guest")

    #channel = pusher
    channel = connect_to_queue(host, 'pusher_events', "/", username=user, password=password, port=port)
    payload = {
        #'channel': "logentries", 
        'rid': tid, 
        'level': level, 
        'msg': msg, 
    }

    channel.basic_publish(exchange='',
                          routing_key='logentries',
                          body=json.dumps(payload),
                          properties=pika.BasicProperties(
                            delivery_mode=1,
                         ),
                        )
    channel.close()
    channel.connection.close()
    del channel.connection 
    del channel

def info(tid, msg):
    log_to_queue(tid, logging.INFO, msg)

def warning(tid, msg):
    log_to_queue(tid, logging.WARNING, msg)

def debug(tid, msg):
    log_to_queue(tid, logging.DEBUG, msg)

def error(tid, msg):
    log_to_queue(tid, logging.ERROR, msg)


def _do(data, functions=None, settings=None):
        exception = None;  exception_message = None; returned = None
        status = STATE_OK

        logger.info("DATA: "+str(data))

        request = Bunch(data['request'])
        base_name = data['base_name']
        model = json.loads(data['model'])

        response_class = None

        # worker does not know apy
        if not functions.has_key(model['fields']['name']):
            status = STATE_NOT_FOUND
            logger.warn("method %s not found in functions, known: %s" % (model['fields']['name'], str(functions.keys())))
        # go ahead
        else:
            func = functions[model['fields']['name']]
            logger.debug("do %s" % request)
            username = copy.copy(request['user']['username'])

            # debug incoming request
            if request['method'] == "GET":
                query_string = copy.copy(request['GET'])
            else:
                query_string = copy.copy(request['POST'])

            logger.debug("START DO")
            try:

                func.username=username
                func.request=request

                func.rid=data['rid']

                func.name = model['fields']['name']

                # attach GET and POST data
                func.GET=copy.deepcopy(request['GET'])
                func.POST=copy.deepcopy(request['POST'])

                # attach Responses classes
                from fastapp import responses
                func.responses = responses

                # attach log functions
                func.info = info 
                func.debug = debug 
                func.warn = warning 
                func.error = error 

                # attatch settings
                setting_dict = settings
                setting_dict1 = Bunch()
                for key, value in setting_dict.iteritems():
                    setting_dict1.update({key: value})
                setting_dict1.update({'STATIC_DIR': "/%s/%s/static" % ("fastapp", base_name)})
                func.settings = setting_dict1

                # execution
                returned = func(func)
                if isinstance(returned, responses.Response):
                    # serialize 
                    response_class = returned.__class__.__name__
                    returned = str(returned)

            except Exception, e:
                logger.exception(e)
                exception = "%s" % type(e).__name__
                exception_message = e.message
                status = STATE_NOK
            logger.debug("END DO")
        return_data = {"status": status, "returned": returned, "exception": exception, "exception_message" : exception_message, "response_class": response_class}
        if exception_message:
            return_data['exception_message'] = exception_message
        return return_data

def get_static(path, vhost, username, password, async=False):

    class StaticClient(object):
        """
        Gets the apy (id, name, module) and sets them on the _do function.__add__ .
        Then the client is ready to response for execution requests.

        """
        def __init__(self, vhost, username, password, async=False):
            # get needed stuff
            self.vhost = vhost
            self.connection = connect_to_queuemanager(
                    host=settings.RABBITMQ_HOST,
                    vhost=vhost,
                    username=username,
                    password=password,
                    port=settings.RABBITMQ_PORT
                ) 

            logger.debug("exchanging message to vhost: %s" % self.vhost)

            self.channel = self.connection.channel()

            result = self.channel.queue_declare(exclusive=True)

            #if not async:
            self.callback_queue = result.method.queue
            self.channel.basic_consume(self.on_response, no_ack=True,
                                       queue=self.callback_queue)

        def on_timeout(self):
            logger.error("timeout in waiting for response")
            raise Exception("Timeout")

        def on_response(self, ch, method, props, body):
            logger.debug("StaticClient.on_message")
            if self.corr_id == props.correlation_id:
                self.response = body
                logger.debug("from static queue: "+body)
            else:
                logger.warn("correlation_id did not match (%s!=%s)" % (self.corr_id, props.correlation_id))

        def call(self, n):
            if self.callback_queue != "/static_callback":
                async = False
                self.connection.add_timeout(RESPONSE_TIMEOUT, self.on_timeout)
            self.response = None
            self.corr_id = str(uuid.uuid4())
            expire = 10000
            logger.debug("Message expiration set to %s ms" % str(expire))
            logger.debug("Wait for corr_id %s" % self.corr_id)
            self.channel.basic_publish(exchange='',
                                       routing_key=STATIC_QUEUE,
                                       properties=pika.BasicProperties(
                                             reply_to = self.callback_queue,
                                             delivery_mode=1,
                                             correlation_id = self.corr_id,
                                             expiration=str(expire)
                                             ),
                                       body=str(n))
            while self.response is None and not async:
                self.connection.process_data_events()
            return self.response

        def end(self):
            self.channel.close()
            self.connection.close()
            del self.channel
            del self.connection

    executor = StaticClient(vhost, username, password, async=async)

    try:
        response = executor.call(path)
    except Exception, e:
        logger.exception(e)
        response = json.dumps({u'status': u'TIMEOUT', u'exception': None, u'returned': None, 'id': u'cannot_import'})
    finally:
        executor.end()
    return response


class StaticServerThread(CommunicationThread):
    def __init__(self, *args, **kwargs ):
        self.functions = {}
        self.settings = {}

        return super(StaticServerThread, self).__init__(*args, **kwargs)

    def on_message(self, ch, method, props, body):
        logger.debug(self.name+": "+sys._getframe().f_code.co_name)
        logger.debug(body)
        body = json.loads(body)
        logger.info(body)

        try:
            if method.routing_key == STATIC_QUEUE:
                logger.info("Static-Request %s received in %s" % (body['path'], self.name))
                try:
                    path = body['path']
                    response_data = {}
                    base_name = body['base_name']
                    f=None
                    for p in sys.path:
                        if base_name in p:
                            logger.info(p+" found")
                            full_path = os.path.join(p, path.replace(base_name+"/", ""))
                            logger.info(full_path)
                            try:
                                f = open(full_path, 'r')
                            except Exception, e:
                                logger.warning(e)
                                logger.warning("Could not open file %s" % full_path)
                            rc="OK"
                            response_data.update({
                                'file': base64.b64encode(f.read())
                                })
                            f.close()
                    if not f:
                        logger.warning("not found")
                        rc="NOT_FOUND"

                except Exception, e:
                    rc="NOT_FOUND"
                    logger.exception(e)
                finally:
                    response_data.update({'status': rc})
                    logger.info(props.reply_to)
                    ch.basic_publish(exchange='',
                                     routing_key=props.reply_to,
                                     properties=pika.BasicProperties(
                                        correlation_id = props.correlation_id,
                                        delivery_mode=1,
                                        ),
                                     body=json.dumps(response_data))
                    logger.info("ack message")
                    ch.basic_ack(delivery_tag = method.delivery_tag)
        except Exception, e:
            logger.exception(e) 