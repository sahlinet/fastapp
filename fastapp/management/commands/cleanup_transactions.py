import logging
import datetime
import pytz

from django.core.management.base import BaseCommand

from fastapp.models import Transaction, LogEntry

logger = logging.getLogger("fastapp.executors.remote")

class Command(BaseCommand):
    help = 'Cleanup old transactions and logs'

    def handle(self, *args, **options):
        older_than = datetime.datetime.now()-datetime.timedelta(hours=48)
        older_than_aware = older_than.replace(tzinfo=pytz.UTC)
        transactions = Transaction.objects.filter(created__lte=older_than_aware)
        logger.info("Deleting %s transactions" % transactions.count())
        transactions.delete()
        logs = LogEntry.objects.filter(created__lte=older_than_aware)
        logger.info("Deleting %s logentries" % logs.count())
