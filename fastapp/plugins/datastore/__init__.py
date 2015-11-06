"""
needs SQLAlchemy==1.0.8
PSQL >9.3

ADD Quota "https://gist.github.com/javisantana/1277714"

"""

import os
import logging
import datetime
import inspect

from copy import deepcopy

from sqlalchemy import create_engine, text
from sqlalchemy import func
from sqlalchemy.orm import sessionmaker

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, DateTime
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.schema import CreateSchema
from sqlalchemy.pool import NullPool

from django.conf import settings

from fastapp.plugins import register_plugin, Plugin

import psycopg2

logger = logging.getLogger(__name__)

Base = declarative_base()


class DataObject(Base):

	__tablename__ = 'data_table'

	id = Column(Integer, primary_key=True)
	created_on = Column(DateTime, default=datetime.datetime.now)
	data = Column(JSON)


class DataStore(object):

	ENGINE = 'sqlite:///:memory:'

	def __init__(self, schema=None, *args, **kwargs):
		if schema:
			self.schema = schema.replace("-", "_")
		else:
			self.schema = schema
		self.kwargs = kwargs
		logger.info("Working with schema: %s" % schema)
		logger.info("Working with config: %s" % str(kwargs))

		# set schema for table creation
		DataObject.__table__.schema = self.schema

		# create session with engine
		self.engine = create_engine(self.__class__.ENGINE % kwargs, echo=True, poolclass=NullPool)
		Session = sessionmaker(bind=self.engine)
		self.session = Session()

		# set schema for sql executions
		self._execute("SET search_path TO %s" % self.schema)
		self.session.commit()

	def _activate_plpythonu(self):
		"""As from link http://stackoverflow.com/questions/18209625/how-do-i-modify-fields-inside-the-new-postgresql-json-datatype"""

		self._execute("CREATE EXTENSION IF NOT EXISTS plpythonu;")
		self.session.commit()
		self._execute("CREATE LANGUAGE plpythonu;")
		self.session.commit()

	def _json_update(self):

		self._execute("""CREATE OR REPLACE FUNCTION json_update(data json, key text, value text)
		 RETURNS json
		 AS $$
		    import json
		    json_data = json.loads(data)
		    json_data[key] = value
		    return json.dumps(json_data, indent=4)
		 $$ LANGUAGE plpythonu;""")
		self.session.commit()

	def init_store(self):
		"""
		Runs on server with super user privileges
		"""
		if self.schema:
			# User
			try:
				self._execute("CREATE USER %s WITH PASSWORD '%s'" % (self.schema,
					self.schema))
			except Exception, e:
				logger.error(repr(e))
				self.session.rollback()
				logger.info("Could not create user '%s', does already exist?" % self.schema)

			# Schema
			try:
				self.engine.execute(CreateSchema(self.schema))
				logger.info("Schema created")
			except Exception, e:
				logger.error(repr(e))
				logger.info("Could not create schema '%s', probably it already exists" % self.schema)
				self.session.rollback()

			# Permissions
			self._execute("GRANT USAGE ON SCHEMA %s to %s;" % (self.schema, self.schema))
			self._execute("GRANT ALL ON ALL TABLES IN  SCHEMA %s to %s;" % (self.schema, self.schema))
			self._execute("GRANT ALL ON ALL SEQUENCES IN  SCHEMA %s to %s;" % (self.schema, self.schema))
			self.session.commit()

		self._prepare()
		return "init_store '%s' done" % self.schema

	def _prepare(self):
		Base.metadata.create_all(self.engine)
		self.session.commit()

	def write_obj(self, obj):
		self.session.add(obj)
		self.session.commit()

	def write_dict(self, data_dict):
		obj_dict = DataObject(data=data_dict)
		return self.write_obj(obj_dict)

	def all(self):
		return self.session.query(DataObject).all()

	def filter(self, k, v):
		return self.session.query(DataObject).filter(text("data->>'"+k+"' = '"+v+"';")).all()

	def delete(self, obj):
		self.session.delete(obj)
		return self.session.commit()

	def save(self, obj):
		#self.session.add(obj)
		return self.session.commit()

	def get(self, k, v):
		result = self.filter(k, v)
		if len(result) > 1:
			raise Exception("More than one row returned!")
		return result[0]

	def _execute(self, sql, result=None):
		result = self.session.execute(sql)
		self.session.commit()
		return result

	def truncate(self):
		self._execute("TRUNCATE %s.data_table" % self.schema)


def resultproxy_to_list(proxy):
	l = []
	for row in proxy:
		l.append(row.__dict__)
	return l


class PsqlDataStore(DataStore):

	ENGINE = 'postgresql+psycopg2://%(USER)s:%(PASSWORD)s@%(HOST)s:%(PORT)s/%(NAME)s'

	def query(self, k, v):
		q = """SELECT id, json_string(data,'%s'
				FROM things
				WHERE json_string(data,'%s')
				LIKE '%s%';""" % (k, v)


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
		plugin_settings['PASSWORD'] = base.name.replace("-", "_")
		return plugin_settings

	def on_start_base(self, base):
		plugin_settings = settings.FASTAPP_PLUGINS_CONFIG['fastapp.plugins.datastore']
		store = PsqlDataStore(schema=base.name, **plugin_settings)
		return store.init_store()

	def cockpit_context(self):
		plugin_settings = settings.FASTAPP_PLUGINS_CONFIG['fastapp.plugins.datastore']
		#self.store = PsqlDataStore(**plugin_settings)
		SCHEMAS = "SELECT schema_name FROM information_schema.schemata;"
		TABLESPACES = """SELECT array_to_json(array_agg(row_to_json(t))) FROM (
				SELECT *, pg_tablespace_size(spcname) FROM pg_tablespace
			) t;"""
		CONNECTIONS = "SELECT * FROM pg_stat_activity;"

		return {
			#'SCHEMAS': [row for row in PsqlDataStore(**plugin_settings)._execute(SCHEMAS)],
			#'TABLESPACES': [row for row in PsqlDataStore(**plugin_settings)._execute(TABLESPACES)][0],
			#'CONNECTIONS': [row for row in PsqlDataStore(**plugin_settings)._execute(CONNECTIONS)],
		}
