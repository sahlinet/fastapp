import logging
import sys
import gevent
from optparse import make_option

from django.db import transaction
from django.core.management.base import BaseCommand
from django.conf import settings

from fastapp.models import Base

logger = logging.getLogger("fastapp.executors.remote")

class Command(BaseCommand):
    args = '<poll_id poll_id ...>'
    help = 'Closes the specified poll for voting'

    option_list = BaseCommand.option_list + (
        #make_option('--username',
        #    action='store',
        #    dest='username',
        #    default=None,
        #    help='Username for the worker'),
        )

 
    def handle(self, *args, **options):
	def _handle_base(base):
		base.stop()
		base.destroy()


	greenlets = []

        transaction.set_autocommit(False)
	for base in Base.objects.filter(executor__pid__isnull=False).select_for_update(nowait=False):
		g = gevent.spawn(_handle_base, base)
		greenlets.append(g)

	gevent.wait(greenlets)
        transaction.commit()
