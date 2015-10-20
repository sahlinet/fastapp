import logging
import sys
import threading

from django.core.management.base import BaseCommand

from fastapp.executors.heartbeat import HeartbeatThread, inactivate, update_status, HEARTBEAT_QUEUE, AsyncResponseThread
from fastapp.log import LogReceiverThread
from django.conf import settings
from fastapp.queue import RabbitmqAdmin

from fastapp.utils import load_setting

logger = logging.getLogger("fastapp.executors.remote")

class Command(BaseCommand):
    args = '<poll_id poll_id ...>'
    help = 'Closes the specified poll for voting'


    def handle(self, *args, **options):

        threads = []
        async_threads = []

        # start cleanup thread
        inactivate_thread = threading.Thread(target=inactivate)
        inactivate_thread.daemon = True
        inactivate_thread.start()

        host = load_setting("RABBITMQ_HOST")
        port = int(load_setting("RABBITMQ_PORT"))

        SENDER_PASSWORD = load_setting("FASTAPP_CORE_SENDER_PASSWORD")
        RECEIVER_PASSWORD = load_setting("FASTAPP_CORE_RECEIVER_PASSWORD")

        # create core vhost
        CORE_SENDER_USERNAME = load_setting("CORE_SENDER_USERNAME")
        CORE_RECEIVER_USERNAME = load_setting("CORE_RECEIVER_USERNAME")
        SENDER_PERMISSIONS  = load_setting("SENDER_PERMISSIONS")
        RECEIVER_PERMISSIONS = load_setting("RECEIVER_PERMISSIONS")

        service = RabbitmqAdmin.factory("HTTP_API")
        CORE_VHOST = load_setting("CORE_VHOST")
        service.add_vhost(CORE_VHOST)
        service.add_user(CORE_SENDER_USERNAME, SENDER_PASSWORD)
        service.add_user(CORE_RECEIVER_USERNAME, RECEIVER_PASSWORD)
        service.set_perms(CORE_VHOST, CORE_SENDER_USERNAME, SENDER_PERMISSIONS)
        service.set_perms(CORE_VHOST, CORE_RECEIVER_USERNAME, RECEIVER_PERMISSIONS)

        # heartbeat
        queues_consume = [[HEARTBEAT_QUEUE, True]]
        HEARTBEAT_THREAD_COUNT = settings.FASTAPP_HEARTBEAT_LISTENER_THREADCOUNT
        for c in range(0, HEARTBEAT_THREAD_COUNT):
            name = "HeartbeatThread-%s" % c

            thread = HeartbeatThread(name, host, port, CORE_VHOST, CORE_RECEIVER_USERNAME, RECEIVER_PASSWORD, queues_consume=queues_consume, ttl=3000)
            threads.append(thread)
            thread.daemon = True
            thread.start()

        update_status_thread = threading.Thread(target=update_status, args=["HeartbeatThread", HEARTBEAT_THREAD_COUNT, threads])
        update_status_thread.daemon = True
        update_status_thread.start()

        # async response thread
        ASYNC_THREAD_COUNT = settings.FASTAPP_ASYNC_LISTENER_THREADCOUNT
        async_queue_name = load_setting("ASYNC_RESPONSE_QUEUE")
        queues_consume_async = [[async_queue_name, True]]
        for c in range(0, ASYNC_THREAD_COUNT):
            name = "AsyncResponseThread-%s" % c
            thread = AsyncResponseThread(name, host, port, CORE_VHOST, CORE_RECEIVER_USERNAME, RECEIVER_PASSWORD, queues_consume=queues_consume_async, ttl=3000)
            async_threads.append(thread)
            thread.daemon = True
            thread.start()

        async_status_thread = threading.Thread(target=update_status, args=["AsyncResponseThread", ASYNC_THREAD_COUNT, async_threads])
        async_status_thread.daemon = True
        async_status_thread.start()

        # log receiver
        LOG_THREAD_COUNT = settings.FASTAPP_LOG_LISTENER_THREADCOUNT
        log_queue_name = load_setting("LOGS_QUEUE")
        queues_consume_log = [[log_queue_name, True]]
        log_threads = []
        for c in range(0, LOG_THREAD_COUNT):
            name = "LogReceiverThread-%s" % c
            thread = LogReceiverThread(name, host, port, CORE_VHOST, CORE_RECEIVER_USERNAME, RECEIVER_PASSWORD, queues_consume=queues_consume_log, ttl=10000)
            log_threads.append(thread)
            thread.daemon = True
            thread.start()

        log_status_thread = threading.Thread(target=update_status, args=["LogReceiverThread", LOG_THREAD_COUNT, log_threads])
        log_status_thread.daemon = True
        log_status_thread.start()

        for t in [inactivate_thread]+threads+async_threads:
            try:
                logger.info("Thread started")
                t.join(1000)
            except KeyboardInterrupt:
                logger.info("KeyBoardInterrupt received")
                print "Ctrl-c received."
                sys.exit(0)
