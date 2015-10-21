import os
import logging

from django.conf import settings

logger = logging.getLogger(__name__)


class Singleton(type):
	def __init__(cls, name, bases, dict):
		super(Singleton, cls).__init__(name, bases, dict)
		cls.instance = None

	def __call__(cls,*args,**kw):
		if cls.instance is None:
			logger.debug("Create singleton instance for %s" % cls)
			cls.instance = super(Singleton, cls).__call__(*args, **kw)
		else:
			logger.debug("Return singleton instance for %s" % cls)
		return cls.instance


class PluginRegistry(object):
	__metaclass__ = Singleton

	def __init__(self):
		self.plugins = []
		self.all_plugins = []

	def __iter__(self):
		return iter(self.plugins)

	def add(self, cls):
		if cls not in self.plugins:
			logger.info("Register: %s" % cls)
			logger.info("Check if plugin '%s' must be activated..." % cls.shortname)
			plugins_config = getattr(settings, "FASTAPP_PLUGINS_CONFIG", {})
			if cls.fullname in plugins_config.keys():
				cls.init()
				self.plugins.append(cls)
				logger.info("Plugin '%s' activated with settings: %s" % (cls.fullname, str(plugins_config[cls.fullname].keys())))
			else:
				logger.info("Plugin '%s' not activated" % cls.fullname)
			self.all_plugins.append(cls)
		else:
			logger.debug("Already registered: %s" % cls)

	@property
	def all(self):
		"""
		Used for worker process, where plugin is not in registry, because of missing configuration.
		-> Configuration arrives from server over heartbeating mechanism.
		"""
		return self.all_plugins

	def get(self):
		return self.plugins


def register_plugin(cls):
	""" Class decorator for adding plugins to the registry """
	PluginRegistry().add(cls())
	return cls


def call_plugin_func(obj, func):
	r_success = {}
	r_failed = {}
	registry = PluginRegistry()
	for plugin in registry.get():
		logger.info("Handling plugin %s for %s starting" % (plugin.fullname, func))
		try:
			plugin_func = getattr(plugin, func)
			r = plugin_func(obj)
			r_success[plugin.name] = r
		except Exception, e:
			logger.exception(e)
			r_failed[plugin.name] = e
		logger.info("Handling plugin %s for %s ended" % (plugin, func))
	logger.info("Loaded %s with success, %s with errors" % (len(r_success), len(r_failed)))
	return r_success, r_failed


class Plugin(object):

	__metaclass__ = Singleton

	def __init__(self, *args, **kwargs):
		self.kwargs = kwargs
		logger.info("Init %s" % self.name)
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
		try:
			config.update(self.config(base))
		except AttributeError, e:
			pass

		logger.info("Config to worker for plugin %s" % self.name)
		return config

	@property
	def shortname(self):
		return self.__class__.__module__.split(".")[-1]

	@property
	def fullname(self):
		return self.__class__.__module__

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
