import logging
import sys
import json
from fastapp.queue import CommunicationThread
from fastapp.models import Transaction

logger = logging.getLogger(__name__)

class LogReceiverThread(CommunicationThread):

    def on_message(self, ch, method, props, body):
        try:
            logger.debug(self.name+": "+sys._getframe().f_code.co_name)
            data = json.loads(body)
            logger.info(data)
            transaction = Transaction.objects.get(rid=data['rid'])
            transaction.log(data['level'], data['msg'])
            #vhost = data['vhost']
            #base = vhost.split("-")[1]

            #logger.debug("Heartbeat received from '%s'" % vhost)

            # store timestamp in DB
            #from fastapp.models import Instance
            #instance = Instance.objects.get(executor__base__name=base)
            #instance.is_alive = True
            #instance.last_beat = datetime.now().replace(tzinfo=pytz.UTC)
            #instance.save()
        except Exception, e:
            logger.exception(e)