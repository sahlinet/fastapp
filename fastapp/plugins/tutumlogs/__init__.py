
from fastapp.plugins import register_plugin, Plugin

@register_plugin
class DataStorePlugin(Plugin):

	def attach_worker(self, **kwargs):
		logger.info("Attach to worker")
		return PsqlDataStore(schema=kwargs['USER'], **kwargs)

	@classmethod
	def init(cls):
		logger.info("Init %s" % cls)
		plugin_path = os.path.dirname(inspect.getfile(cls))
		template_path = os.path.join(plugin_path, "templates")
		settings.TEMPLATE_DIRS = settings.TEMPLATE_DIRS + (template_path,)

	def config(self, base):
		plugin_settings = settings.FASTAPP_PLUGINS_CONFIG['fastapp.plugins.datastore']
		plugin_settings['USER'] = base.name.replace("-", "_")
		plugin_settings['PASSWORD'] = base.name
		return plugin_settings

	def cockpit_context(self):

        try:
    		plugin_settings = settings.FASTAPP_PLUGINS_CONFIG[self.fullname]

            import tutum
            #tutum.user = plugin_settings['USER']
            #tutum.apikey = plugin_settings['API_KEY']

            service_uuid = os.environ['TUTUM_SERVICE_API_URI'].split("/")[-2]

            logs = []

            def log_handler(message):
                logs.append(message)

            container = tutum.Container.fetch(service_uuid)
            container.logs(tail=200, follow=False, log_handler=log_handler)
            msg = "Well done..."
        except Exception, e:
            msg = repr(e)

		return {
			'logs': logs,
            'message': msg
		}
