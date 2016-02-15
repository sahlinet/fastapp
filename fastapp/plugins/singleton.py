import sys
import logging
logger = logging.getLogger(__name__)


class Singleton(type):
    def __init__(cls, name, bases, dict):
        super(Singleton, cls).__init__(name, bases, dict)
        cls.instance = None

    def __call__(cls, keep=True, *args, **kwargs):
        caller_method = sys._getframe().f_back.f_code.co_name
        if cls.instance is None:
            logger.debug("Create singleton instance to '%s' for %s with args (keep=%s): %s, %s" % (caller_method, cls, keep, args, kwargs))
            if keep:
                cls.instance = super(Singleton, cls).__call__(*args, **kwargs)
            else:
                return super(Singleton, cls).__call__(*args, **kwargs)
        else:
            logger.debug("Return singleton instance to '%s' for %s with args: %s, %s" % (caller_method, cls, args, kwargs))
        return cls.instance
