import os
import logging
import requests
import inspect
from django.conf import settings

from fastapp.plugins import register_plugin, Plugin

logger = logging.getLogger(__name__)


class DigitaloceanDns():

	def __init__(self, token, domain):
		# update dns record
		self.URL = "https://api.digitalocean.com/v2/domains/%s/records" % domain
		self.headers = {'Authorization': "Bearer %s" % token}


	def update(self, hostname, ip, type="A"):

		self.data = {
				'type': type,
				'name': hostname,
				'data': ip
		}
		self.r = requests.get(self.URL, data={'per_page': 200}, headers=self.headers)
		self.records = self.r.json()

		id = self._get_record(hostname)
		if id:
			r = requests.put(self.URL+"/%s" % id, self.data, headers=self.headers)
		else:
			r = requests.post(self.URL, self.data, headers=self.headers)
		logger.info((hostname, ip, r.status_code, r.text))
		return hostname, ip, r.status_code

	def delete(self, hostname):
		id = self._get_record(hostname)
		r = requests.delete(self.URL+"/%s" % id,headers=self.headers)
		return r.status_code

	def _get_record(self, hostname):
				# update dns record
		#URL = "https://api.digitalocean.com/v2/domains/%s/records" % domain

		r = requests.get(self.URL, data={'per_page': 200}, headers=self.headers)
		records = r.json()

		found = False
		for record in records['domain_records']:
				if record['name'] == hostname:
						id = record['id']
						return id
		return None

import inspect

@register_plugin
class DNSNamePlugin(Plugin):

	@classmethod
	def init(cls):
		logger.info(str(cls.name) + "  " + inspect.stack()[0][3])
		logger.info("Init %s" % cls)
		plugin_path = os.path.dirname(inspect.getfile(cls))
		template_path = os.path.join(plugin_path, "templates")
		settings.TEMPLATE_DIRS = settings.TEMPLATE_DIRS + (template_path,)

	def on_start_base(self, base, **kwargs):
		logger.info(str(self.__class__.name) + " " + inspect.stack()[0][3])

		plugin_settings = settings.FASTAPP_PLUGINS_CONFIG['fastapp.plugins.dnsname']
		token = plugin_settings['token']
		domain = plugin_settings['zone']
		dns = DigitaloceanDns(token, domain)

		for counter, executor in enumerate(base.executors):
			dns_name = self._make_dns_name(base, counter)
			logger.info(executor)
			logger.info("Add '%s' to DNS zone %s" % (dns_name, domain))
			dns.update(dns_name, executor['ip'])
			if executor['ip6']:
				dns.update(dns_name, executor['ip6'], type="AAAA")

	def on_destroy_base(self, base):
		logger.info(str(self.__class__.name) + " " + inspect.stack()[0][3])

		plugin_settings = settings.FASTAPP_PLUGINS_CONFIG['fastapp.plugins.dnsname']
		token = plugin_settings['token']
		domain = plugin_settings['zone']
		dns = DigitaloceanDns(token, domain)

		for counter, executor in enumerate(base.executors):
			logger.info(executor)
			dns_name = self._make_dns_name(base, counter)
			logger.info("Delete '%s' from DNS zone %s" % (dns_name, domain))
			dns.delete(dns_name)

	def executor_context(self, executor):
		context = {}
		#for counter, executor in enumerate(base.executors):
		#	k = "%s_executor_%s" % (base, counter)
		#	v =  self._make_dns_name(base, executor)
		#	context[k] = v

		#k = "%s_executor" % (executor.base)
		k = "SERVICE_DNS"
		v =  self._make_dns_name(executor.base, 0)
		plugin_settings = settings.FASTAPP_PLUGINS_CONFIG['fastapp.plugins.dnsname']
		domain = plugin_settings['zone']
		v = v + "." + domain
		context[k] = v

		return context

	def _make_dns_name(self, base, counter):
		dns_name = "%s-%s-%i" % (base.user.username, base.name, counter)
		logger.info(dns_name)
		return dns_name.replace("_", "-").lower()
