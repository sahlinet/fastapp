from swampdragon import route_handler
from swampdragon.route_handler import BaseModelPublisherRouter
from serializers import TransactionSerializer, ApySocketSerializer, LogEntrySerializer
from models import Transaction, LogEntry

from swampdragon.permissions import login_required

import logging
logger = logging.getLogger(__name__)


class PrivateBaseModelPublisherRouter(BaseModelPublisherRouter):

    @login_required
    def subscribe(self, **kwargs):
        super(BaseModelPublisherRouter, self).subscribe(**kwargs)


class TransactionRouter(PrivateBaseModelPublisherRouter):
    serializer_class = TransactionSerializer
    model = Transaction
    route_name = 'transaction-router'
    include_related = [ApySocketSerializer]

    def get_object(self, **kwargs):
        logger.info(kwargs)
        return self.model.objects.get(pk=kwargs['pk'])

    def get_query_set(self, **kwargs):
        logger.info(kwargs)
        return self.model.all()

    def get_subscription_contexts(self, **kwargs):
        return {'apy__base__user_id': self.connection.user.pk}


class LogRouter(PrivateBaseModelPublisherRouter):
    serializer_class = LogEntrySerializer
    model = LogEntry
    route_name = 'logentry-router'

    def get_object(self, **kwargs):
        logger.info(kwargs)
        return self.model.objects.get(pk=kwargs['pk'])

    def get_query_set(self, **kwargs):
        logger.info(kwargs)
        return self.model.all()

#    def get_subscription_contexts(self, **kwargs):
#        return {'transaction__apy__base__user_id': self.connection.user.pk}

route_handler.register(TransactionRouter)
route_handler.register(LogRouter)
