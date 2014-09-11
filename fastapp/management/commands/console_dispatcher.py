import logging
import sys

from django.core.management.base import BaseCommand
from django.conf import settings

from fastapp.console import PusherSenderThread
from fastapp.utils import LogReceiverThread


logger = logging.getLogger("fastapp.executors.console")

class Command(BaseCommand):
    args = '<poll_id poll_id ...>'
    help = 'Closes the specified poll for voting'


    def handle(self, *args, **options):
        THREAD_COUNT = settings.FASTAPP_HEARTBEAT_LISTENER_THREADCOUNT
        threads = []
        # create connection to pusher_queue

        logger.info("Start sending events to pusher")
        for c in range(1, 3):
            name = "PusherSenderThread-%s" % c
            thread = PusherSenderThread(c, name, c, "/")
            logger.info("Start '%s'" % name)
            threads.append(thread)
            thread.daemon = True
            thread.start()


        #update_status_thread = threading.Thread(target=update_status, args=["Heartbeat", THREAD_COUNT, threads])
        #update_status_thread.daemon = True
        #update_status_thread.start()

        for t in threads:
            #print "join %s " % t
            try:
                logger.info("%s Thread started" % THREAD_COUNT)
                t.join(1000)
            except KeyboardInterrupt:
                print "Ctrl-c received."
                sys.exit(0)


