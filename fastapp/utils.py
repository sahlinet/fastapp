import datetime
import logging
import dropbox
import json
import StringIO
import hashlib
import pika
import os
from django.contrib import messages
from django.conf import settings
from dropbox.rest import ErrorResponse

from queue import connect_to_queue


class UnAuthorized(Exception):
    pass

class NotFound(Exception):
    pass

class NoBasesFound(Exception):
    pass

logger = logging.getLogger(__name__)


class Connection(object):

    def __init__(self, access_token):
        self.client = dropbox.client.DropboxClient(access_token)
        super(Connection, self).__init__()

    def info(self):
        account_info = self.client.account_info()
        email = account_info['email']
        name = account_info['display_name']
        return email, name

    def listing(self):
        bases = []
        for base in self._call('metadata', '/')['contents']:
            bases.append(base['path'].lstrip('/'))
        if len(bases) == 0:
            raise NoBasesFound()
        return bases

    def get_file(self, path):
        logger.debug("get file %s" % path)
        return self._call('get_file', path)

    def get_file_content(self, path):
        logger.debug("return content %s" % path)
        return self.get_file(path).read()

    def put_file(self, path, content):
        f = StringIO.StringIO(content)
        return self._call('put_file', path, f, True)

    def delete_file(self, path):
        return self._call('file_delete', path)

    def create_folder(self, path):
        return self._call('file_create_folder', path)

    def _call(self, ms, *args):
        try:
            m = getattr(self.client, ms)
            return m(*args)
        except ErrorResponse, e:
            if e.__dict__['status'] == 401:
                raise UnAuthorized(e.__dict__['body']['error'])
            if e.__dict__['status'] == 404:
                raise NotFound(e.__dict__['body']['error'])
            raise e
        except Exception, e:
            raise e

    def metadata(self, path):
        return self._call('metadata', path)

    def directory_zip(self, path, zf):

        logger.info("download "+path)
        try:
            f_metadata = self.metadata(path)

            if f_metadata['is_dir']:
                for content in f_metadata['contents']:
                    import time; time.sleep(0.1)
                    logger.info("download "+content['path'])

                    if content['is_dir'] == True:
                        self.directory_zip(content['path'], zf)
                    else:
                        # get the file
                        filepath = content['path']
                        try:
                            file = self.get_file(filepath)
                            zf.writestr(os.path.relpath(filepath, "/"), file.read())
                            file.close()
                        except ErrorResponse, e:
                            logger.error(e)

        except ErrorResponse, e:
            logger.error(e)

        return zf


def message(request, level, message):
    dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if level == logging.ERROR:
        tag = "alert-danger"
    elif level == logging.INFO:
        tag = "alert-info"
    elif level == logging.WARN:
        tag = "alert-info"
    messages.error(request, dt + " " + str(message)[:1000], extra_tags="%s safe" % tag)

def sign(data):
    m = hashlib.md5()
    m.update(data)
    m.update(settings.SECRET_KEY)
    return "%s-%s" % (data, m.hexdigest()[:10])

def channel_name_for_user(request):
    if request.user.is_authenticated():
        channel_name = "%s-%s" % (request.user.username, sign(request.user.username))
    else:
        #channel_name = "anon-%s" % sign(request.session.session_key)
        # TODO: find a way to identify anonymous user
        #     problem on initial
        channel_name = "anon-%s" % sign(request.META['REMOTE_ADDR'])
    logger.debug("channel_name: %s" % channel_name)
    return channel_name

def channel_name_for_user_by_user(user):
    channel_name = "%s-%s" % (user.username, sign(user.username))
    logger.debug("channel_name: %s" % channel_name)
    return channel_name

def send_client(channel_name, event, data):
    logger.debug("START EVENT_TO_QUEUE %s"   % event)

    host = settings.RABBITMQ_HOST
    port = settings.RABBITMQ_PORT
    user = getattr(settings, "RABBITMQ_ADMIN_USER", "guest")
    password = getattr(settings, "RABBITMQ_ADMIN_PASSWORD", "guest")

    #channel = pusher
    channel = connect_to_queue(host, 'pusher_events', "/", username=user, password=password, port=port)
    payload = {
        'channel': channel_name, 
        'event': event, 
        'data': data, 
    }

    channel.basic_publish(exchange='',
                          routing_key='pusher_events',
                          body=json.dumps(payload),
                          properties=pika.BasicProperties(
                            delivery_mode=1,
                         ),
                        )
    logger.debug("END EVENT_TO_QUEUE %s" % event)
    channel.close()
    channel.connection.close()
    del channel.connection 
    del channel

def user_message(level, channel_name, message):

    #channel = username
    # TODO: strip message to max 10KB
    # http://pusher.com/docs/server_api_guide/server_publishing_events

    #p = get_pusher()

    now = datetime.datetime.now()
    if level == logging.INFO:
        class_level = "info"        
    elif level == logging.DEBUG:
        class_level = "debug"        
    elif level == logging.WARNING:
        class_level = "warn"        
    elif level == logging.ERROR:
        class_level = "error"        
    logger.log(level, "to pusher: "+message)
    data = {'datetime': str(now), 'message': str(message), 'class': class_level}
    send_client(channel_name, "console_msg", data)


def info(username, gmessage): 
        return user_message(logging.INFO, username, gmessage)
def debug(username, gmessage): 
        return user_message(logging.DEBUG, username, gmessage)
def error(username, gmessage): 
        return user_message(logging.ERROR, username, gmessage)
def warn(username, gmessage): 
        return user_message(logging.WARN, username, gmessage)
