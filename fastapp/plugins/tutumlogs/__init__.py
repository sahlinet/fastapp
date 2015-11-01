import os
import logging
import inspect

from django.conf import settings

from fastapp.plugins import register_plugin, Plugin

logger = logging.getLogger(__name__)

@register_plugin
class TutumLogsPlugin(Plugin):

	@classmethod
	def init(cls):
		logger.info("Init %s" % cls)
		plugin_path = os.path.dirname(inspect.getfile(cls))
		template_path = os.path.join(plugin_path, "templates")
		settings.TEMPLATE_DIRS = settings.TEMPLATE_DIRS + (template_path,)

	def config(self, base):
		plugin_settings = settings.FASTAPP_PLUGINS_CONFIG[self.fullname]
		return plugin_settings

	def cockpit_context(self):
		logs = []
		try:
			plugin_settings = settings.FASTAPP_PLUGINS_CONFIG[self.fullname]

			import tutum
			#tutum.user = plugin_settings['USER']
			#tutum.apikey = plugin_settings['API_KEY']

			service_uuid = os.environ['TUTUM_SERVICE_API_URI'].split("/")[-2]


			def log_handler(message):
				logs.append(message)

			container = tutum.Container.fetch(service_uuid)
			container.logs(tail=200, follow=False, log_handler=log_handler)
			msg = "Well done..."
		except Exception, e:
			msg = repr(e)
			logger.exception(e)

		return {
			'logs': logs,
			'message': msg
		}
