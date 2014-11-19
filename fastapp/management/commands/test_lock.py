from django.core.management.base import BaseCommand

from fastapp.models import Executor
from django.db import transaction
import time

class Command(BaseCommand):
    args = '<poll_id poll_id ...>'
    help = 'Closes the specified poll for voting'

    def handle(self, *args, **options):

    	transaction.set_autocommit(False)
    	#executors = Executor.objects.select_for_update(nowait=True)
    	for executor in Executor.objects.select_for_update(nowait=True).filter(started=True):
    		print executor
    	time.sleep(3000)
