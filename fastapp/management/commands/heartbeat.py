import logging
import sys
import threading

from django.core.management.base import BaseCommand

from fastapp.executors.heartbeat import HeartbeatThread, inactivate, update_status, HEARTBEAT_QUEUE

from django.conf import settings

logger = logging.getLogger("fastapp.executors.remote")

class Command(BaseCommand):
    args = '<poll_id poll_id ...>'
    help = 'Closes the specified poll for voting'


    def handle(self, *args, **options):
        THREAD_COUNT = settings.FASTAPP_HEARTBEAT_LISTENER_THREADCOUNT
        threads = []

        inactivate_thread = threading.Thread(target=inactivate)
        inactivate_thread.daemon = True
        inactivate_thread.start()


        queues_consume = [[HEARTBEAT_QUEUE, True]]

        host = getattr(settings, "RABBITMQ_HOST", "localhost")            
        port = getattr(settings, "RABBITMQ_PORT", 5672)
        username = getattr(settings, "RABBITMQ_ADMIN_USER", "guest")            
        password = getattr(settings, "RABBITMQ_ADMIN_PASSWORD", "guest")

        for c in range(0, THREAD_COUNT):
            name = "HeartbeatThread-%s" % c

            thread = HeartbeatThread(name, host, port, "/", username, password, queues_consume=queues_consume, ttl=3000)
            threads.append(thread)
            thread.daemon = True
            thread.start()

        update_status_thread = threading.Thread(target=update_status, args=["Heartbeat", THREAD_COUNT, threads])
        update_status_thread.daemon = True
        update_status_thread.start()

        for t in threads:
            #print "join %s " % t
            try:
                logger.info("%s Thread started" % THREAD_COUNT)
                t.join(1000)
            except KeyboardInterrupt:
                print "Ctrl-c received."
                sys.exit(0)
