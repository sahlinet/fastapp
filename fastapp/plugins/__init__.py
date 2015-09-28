import os
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


def call_plugin_func(obj, func):
	r_success = {}
	r_failed = {}
	registry = PluginRegistry()
	for plugin in registry.get():
		logger.info("Handling plugin %s for %s" % (plugin, func))
		try:
			plugin_func = getattr(plugin, func)
			r = plugin_func(obj)
			r_success[plugin.name] = r
		except Exception, e:
			logger.exception(e)
			r_failed[plugin.name] = e
	return r_success, r_failed


class Plugin(object):

	__metaclass__ = Singleton

	def __init__(self, *args, **kwargs):
		self.kwargs = kwargs
		super(Plugin, self ).__init__()

	@property
	def name(self):
		return self.__class__.__name__

	def attach_worker(self, **kwargs):
		pass

	def config_for_workers(self, base):
		# send dictionary with config to workers for the plugin
		#    the dictionary is available in self.config(base)
		config = {}
		config.update(self.config(base))
		logger.info("Config to worker for plugin %s" % self.name)
		return config

	@property
	def shortname(self):
		return self.__class__.__module__.split(".")[-1]

	def init(self):
		pass

	def on_create_user(self, user):
		pass

	def on_create_base(self, base):
		pass

	def on_delete_base(self, base):
		pass

	def on_start_base(self, base):
		pass

	def on_stop_base(self, base):
		pass

	def on_restart_base(self, base):
		pass

	def on_destroy_base(self, base):
		pass

	def cockpit_context(self):
		return {}

	def executor_context(self, executor):
		return {}

	def executor_context_kv(self, executor):
		context = self.executor_context(self, executor)
		new_context = []
		for k, v in context.items():
			new_context.append({
				'key': k,
				'value': k,
			})
		return new_context
