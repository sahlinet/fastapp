import logging
logger = logging.getLogger(__name__)


class Singleton(type):
    def __init__(cls, name, bases, dict):
        super(Singleton, cls).__init__(name, bases, dict)
        cls.instance = None

    def __call__(cls,*args,**kw):
        if cls.instance is None:
            logger.info("Create singleton instance for %s" % cls)
            cls.instance = super(Singleton, cls).__call__(*args, **kw)
        else:
            logger.info("Return singleton instance for %s" % cls)
        return cls.instance


class PluginRegistry(object):
    __metaclass__ = Singleton

    def __init__(self):
        self.plugins = []

    def __iter__(self):
        return iter(self.plugins)

    def add(self, cls):
        if cls not in self.plugins:
            logger.info("Register: %s" % cls)
            cls.init()
            self.plugins.append(cls)
        else:
            logger.debug("Already registered: %s" % cls)

    def get(self):
        return self.plugins


def register_plugin(cls):
    """Class decorator for adding plugins to the registry"""
    PluginRegistry().add(cls())
    return cls


class Plugin(object):

	__metaclass__ = Singleton

	@property
	def name(self):
		return self.__class__.__name__

	def init(self):
		pass

	def on_create_user(self):
		pass

	def on_create_base(self):
		pass

	def on_delete_base(self):
		pass

	def on_start_base(self):
		pass

	def on_stop_base(self):
		pass

	def on_restart_base(self):
		pass
