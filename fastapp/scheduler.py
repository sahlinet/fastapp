import logging
import time
from django.conf import settings

from pytz import utc

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

from django.core.management import call_command

from fastapp.models import Apy

logger = logging.getLogger(__name__)


from fastapp.utils import call_apy



def cron_to_dict(cronexpr):
    """
    See https://apscheduler.readthedocs.org/en/latest/modules/triggers/cron.html?highlight=cron#module-apscheduler.triggers.cron
    """
    expr_list = cronexpr.split(" ")
    cron_dict = {}
    cron_dict['second'] = expr_list[0]
    cron_dict['minute'] = expr_list[1]
    cron_dict['hour'] = expr_list[2]
    cron_dict['day_of_week'] = expr_list[3]
    return cron_dict


def update_job(apy, scheduler):
    job_id = "%s-%s-%s" % (apy.base.user.username, apy.base.name, apy.name)
    if apy.schedule:
        time.sleep(0.1)
        kwargs = cron_to_dict(apy.schedule)
        if scheduler.get_job(job_id):
            scheduler.reschedule_job(job_id, trigger='cron', **kwargs)
            logger.info("Job '%s' rescheduled" % job_id)
        else:
            job_id = scheduler.add_job(call_apy, 'cron', args=[apy.base.name, apy.name], id=job_id, **kwargs)
            logger.info("Job '%s' added" % job_id)
    else:
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
            logger.info("Job '%s' removed" % job_id)


def start_scheduler():

    jobstores = {
        #'default': MemoryJobStore(),
        'default': SQLAlchemyJobStore(url=settings.FASTAPP_SCHEDULE_JOBSTORE)
    }

    executors1 = {
        'default': ThreadPoolExecutor(20),
        'processpool': ProcessPoolExecutor(5)
    }
    job_defaults = {
        'coalesce': False,
        'max_instances': 2
    }

    scheduler = BackgroundScheduler(executors=executors1, jobstores=jobstores, job_defaults=job_defaults, timezone=utc)

    from pytz import timezone

    # Cleanup
    if hasattr(settings, "FASTAPP_CLEANUP_INTERVAL_MINUTES"):
        job_id = scheduler.add_job(call_command, 'interval', minutes=int(settings.FASTAPP_CLEANUP_INTERVAL_MINUTES), args=["cleanup_transactions"])
        logger.info(job_id)

    time.sleep(1)
    scheduler.start()

    while True:
        logger.info("START rescheduling call_apy")
        for apy in Apy.objects.all():
            try:
                update_job(apy, scheduler)
            except Exception, e:
                logger.warn("Problem with schdule config for %s: %s" % (apy.name, apy.schedule))
        logger.info("END rescheduling call_apy")
        time.sleep(60)

    logger.info("Done scheduling jobs")
