import logging
logger = logging.getLogger(__name__)


class Singleton(type):
	def __init__(cls, name, bases, dict):
		super(Singleton, cls).__init__(name, bases, dict)
		cls.instance = None

	def __call__(cls, *args, **kwargs):
		if cls.instance is None:
			logger.info("Create singleton instance for %s with args: %s, %s" % (cls, args, kwargs))
			cls.instance = super(Singleton, cls).__call__(*args, **kwargs)
		else:
			logger.info("Return singleton instance for %s with args: %s, %s" % (cls, args, kwargs))
		return cls.instance
