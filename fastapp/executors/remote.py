import pika
import uuid
import json
import copy
import logging
import sys
import traceback
from bunch import Bunch
from fastapp.queue import connect_to_queuemanager, CommunicationThread

from django.conf import settings

logger = logging.getLogger(__name__)

RESPONSE_TIMEOUT = 10
CONFIGURATION_QUEUE = "configuration"
CONFIGURATION_EVENT = "configuration"
SETTINGS_EVENT = "settings"

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

def call_rpc_client(apy, vhost, username, password):

    class ExecutorClient(object):
        """
        Gets the apy (id, name, module) and sets them on the _do function.__add__ .
        Then the client is ready to response for execution requests.

        """
        def __init__(self, vhost, username, password):
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
            self.callback_queue = result.method.queue

            self.channel.basic_consume(self.on_response, no_ack=True,
                                       queue=self.callback_queue)


        #def _get_base():
        #    apys = requests.get("http://localhost:8000/fastapp/api/base/23/apy/")
        def on_timeout(self):
            logger.error("timeout in waiting for response")
            raise Exception("Timeout")

        def on_response(self, ch, method, props, body):
            if self.corr_id == props.correlation_id:
                self.response = body
                logger.debug("from rpc queue: "+body)

        def call(self, n):
            self.connection.add_timeout(RESPONSE_TIMEOUT, self.on_timeout)
            self.response = None
            self.corr_id = str(uuid.uuid4())
            self.channel.basic_publish(exchange='',
                                       routing_key='rpc_queue',
                                       properties=pika.BasicProperties(
                                             reply_to = self.callback_queue,
                                             delivery_mode=1,
                                             correlation_id = self.corr_id,
                                             ),
                                       body=str(n))
            while self.response is None:
                self.connection.process_data_events()
            return self.response

    executor = ExecutorClient(vhost, username, password)

    try:
        response = executor.call(apy)
    except Exception, e:
        response = json.dumps({u'status': u'TIMEOUT', u'exception': None, u'returned': None, 'id': u'cannot_import'})
    return response


STATE_OK = "OK"
STATE_NOK = "NOK"
STATE_NOT_FOUND = "NOT_FOUND"

threads = []

CONFIGURATION_QUEUE = "configuration"
SETTING_QUEUE = "setting"
RPC_QUEUE = "rpc_queue"

class ExecutorServerThread(CommunicationThread):
    def __init__(self, *args, **kwargs ):
        # adds
        #self.vhost = vhost
        #self.username = username
        #self.password = password

        #logger.info("exchanging message to vhost: %s" % self.vhost)
        #logger.info("exchanging message to vhost username: %s" % self.username)
        #logger.info("exchanging message to vhost password: %s" % self.password)
        # container for functions
        self.functions = {}
        # container for settings
        self.settings = {}

        return super(ExecutorServerThread, self).__init__(*args, **kwargs)

    #def run(self):
    #    print "Starting " + self.name
    #    self.listen()

    #def listen(self):
    #    # open connection and channel
    #    try:
    #        connection = connect_to_queuemanager(
    #                vhost=self.vhost,
    #                username=self.username,
    #                password=self.password
    #                )
    #        channel = connection.channel()
#
#
#            # configuration
#            channel.exchange_declare(exchange=CONFIGURATION_QUEUE, type='fanout')
#            result = channel.queue_declare(exclusive=True)
#            self.queue_name = result.method.queue
#            channel.queue_bind(exchange=CONFIGURATION_QUEUE, queue=self.queue_name)
#
#            # setting
#            channel.exchange_declare(exchange=SETTING_QUEUE, type='fanout')
#            result = channel.queue_declare(exclusive=True)
#            self.setting_queue_name = result.method.queue
#            channel.queue_bind(exchange=SETTING_QUEUE, queue=self.setting_queue_name)
#
#            # listen for rpc events
#            channel.queue_declare(queue=RPC_QUEUE)

    def on_message(self, ch, method, props, body):
        logger.debug(self.name+": "+sys._getframe().f_code.co_name)
        logger.debug(ch)
        logger.debug(method)
        logger.debug(props.app_id)
        logger.debug(body)
        try:
            if method.exchange == "configuration":
                print "EVENT ARRIVED"
                if props.app_id == "configuration":
                    fields = json.loads(body)[0]['fields']
                    try:
                        exec fields['module'] in globals(), locals()
                        self.functions.update({
                            fields['name']: func,
                            })
                        logger.info("Configuration '%s' received in %s" % (fields['name'], self.name))
                    except Exception, e:
                        logger.exception(e)

                elif props.app_id == "setting":
                    json_body = json.loads(body)
                    key = json_body.keys()[0]
                    self.settings.update(json_body)
                    logger.info("Setting '%s' received in %s" % (key, self.name))
                else:
                    logger.error("invalid event arrived")
	            logger.warn(props.app_id)	   
    #
            if method.routing_key == RPC_QUEUE:
    #            def on_message(ch, method, props, body):
                logger.info("Request received in %s" % self.name)
                try:
                    response_data = {}
                    response_data = _do(json.loads(body), self.functions, self.settings)

                except Exception, e:
                    logger.exception(e)
                finally:
                    ch.basic_publish(exchange='',
                                     routing_key=props.reply_to,
                                     properties=pika.BasicProperties(
                                        correlation_id = props.correlation_id,
                                        delivery_mode=1,
                                        ),
                                     body=json.dumps(response_data))
                    ch.basic_ack(delivery_tag = method.delivery_tag)
        except Exception, e:
            logger.exception(e)

#
#            channel.basic_qos(prefetch_count=3)
#            channel.basic_consume(on_message, queue=RPC_QUEUE)
#            channel.basic_consume(on_configuration_request, queue=self.queue_name, no_ack=True)
#            channel.basic_consume(on_setting_request, queue=self.setting_queue_name, no_ack=True)
#
#            logger.info("Waiting for events")
#            channel.start_consuming()
#        except Exception, e:
#            logger.error("Connection closed")
#            logger.exception(e)




class ApyNotFound(Exception):
    pass

class ApyError(Exception):
    pass

def _do(data, functions=None, settings=None):
        exception = None;  returned = None
        status = STATE_OK

        request = Bunch(data['request'])
        logger.info("REQUEST")
        logger.info(request)
        base_name = data['base_name']
        model = json.loads(data['model'])

        response_class = None

        # worker does not know apy
        if not functions.has_key(model['fields']['name']):
            status = STATE_NOT_FOUND
        # go ahead
        else:
            func = functions[model['fields']['name']]
            #print "REQUEST ARRIVED"
            logger.debug("do %s" % request)
            username = copy.copy(request['user']['username'])

            # debug incoming request
            if request['method'] == "GET":
                query_string = copy.copy(request['GET'])
            else:
                query_string = copy.copy(request['POST'])

            logger.debug("START DO")
            try:

                #exec model['fields']['module']
                func.username=username
                func.request=request
                #func.session=session

                func.name = model['fields']['name']

                # attach GET and POST data
                func.GET=copy.deepcopy(request['GET'])
                func.POST=copy.deepcopy(request['POST'])

                # attach Responses classes
                from fastapp import responses
                func.responses = responses

                # attach log functions
                #func.info=info
                #func.debug=debug
                #func.warn=warn
                #func.error=error

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
                exception = "%s: %s" % (type(e).__name__, e.message)
                traceback.print_exc()
                logger.exception(e)
                status = STATE_NOK
            logger.debug("END DO")
        return_data = {"status": status, "returned": returned, "exception": exception, "response_class": response_class}
        return return_data
