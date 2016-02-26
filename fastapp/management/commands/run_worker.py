import logging
from optparse import make_option

from django.core.management.base import BaseCommand

from fastapp.models import Base

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    args = '<poll_id poll_id ...>'
    help = 'Closes the specified poll for voting'

    option_list = BaseCommand.option_list + (
        make_option('--username',
                    action='store',
                    dest='username',
                    default=None,
                    help='Username for the worker'),
        make_option('--password',
                    action='store',
                    dest='password',
                    default=None,
                    help='Password for the worker'),
        make_option('--base',
                    action='store',
                    dest='base',
                    default=None,
                    help='Base for the worker'),
        make_option('--vhost',
                    action='store',
                    dest='vhost',
                    default=None,
                    help='VHost on Queue system'),
        )

    def handle(self, *args, **options):

        base = options['base']
        #base_obj = Base.objects.get(name=base)
        #if not base_obj.state:
        #    logger.info("Starting base %s" % base)
        #    base_obj.start()
        #else:
        #    logger.info("Base %s already running" % base)

        import requests


        from requests.auth import HTTPBasicAuth
        r = requests.post("http://localhost:8000/fastapp/api-token-auth/", data={'username': "admin", 'password': "admin"})
        print r.status_code
        print r.text
        print r.json()
