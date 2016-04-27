import logging
import errno
import io
import os
import warnings

from django.template import TemplateDoesNotExist
from django.template.loader import BaseLoader
from dropbox.rest import ErrorResponse
from fastapp.utils import Connection
from django.core.exceptions import SuspiciousFileOperation
from django.template import Origin, TemplateDoesNotExist
from django.utils._os import safe_join

from django.conf import settings

from fastapp.models import Base
from fastapp.views.static import DjendStaticView

logger = logging.getLogger(__name__)



class FastappBaseLoader(BaseLoader):
    is_usable = True
    
    def get_file(self, template_name, short_name, base_model):
        raise NotImplementedError("get_file method is missing on " % self.__class__.name)

    def load_template_source(self, template_name, template_dirs=None):
        logger.debug("Trying to load template %s" % str(template_name.split(":")))
        if ":" in template_name:
            username, base, short_name = template_name.split(":")
            try:
                base_model = Base.objects.get(name=base)
                f, template_name = self.get_file(template_name, short_name, base_model)
                return f, template_name
            #except ErrorResponse, e:
            #    logging.warning("get_file_content error response %s" % str(e.__dict__))
            #    if e.__dict__['status'] == 404:
            #        raise TemplateDoesNotExist(short_template_name)
            except Exception, e:
                logger.exception("Could not load template")
                
                #raise TemplateDoesNotExist(short_name)
        raise TemplateDoesNotExist()
        

    load_template_source.is_usable = True
"""
Wrapper for loading templates from the filesystem.
"""

class RemoteWorkerLoader(FastappBaseLoader):

  def get_file(self, template_name, short_name, base_model):
        logger.info("%s: load from module in worker" % template_name)
        response_data = get_static(
            json.dumps({"base_name": base_model.name, "path": template_name}),
            generate_vhost_configuration(
                base_model.user.username,
                base_model.name
                ),
            base_model.name,
            base_model.executor.password
            )
        data = json.loads(response_data)
        return data, template_name

      
class DropboxAppFolderLoader(FastappBaseLoader):
  
  def get_file(self, template_name, short_name, base_model):
        connection = Connection(base_model.user.authprofile.access_token)
        logging.info("get_file_content %s" % template_name)
        f = connection.get_file_content(base+"/"+template_name)
        logging.info("get_file_content %s done" % template_name)
        return f, template_name

      
class DevLocalRepositoryPathLoader(FastappBaseLoader):
  
  def get_file(self, template_name, short_name, base_model):
        REPOSITORIES_PATH = getattr(settings, "FASTAPP_REPOSITORIES_PATH", None)
        logger.debug("in DevLocalRepositoryPathLoader")
        try:
          filepath = os.path.join(REPOSITORIES_PATH, os.path.join(base_model.name, short_name))
          file = open(filepath, 'r')
          #size = os.path.getsize(filepath)
          logger.debug("%s: load from local filesystem (repositories) (%s)" % (template_name, filepath))
          #last_modified = datetime.fromtimestamp(os.stat(filepath).st_mtime)
        except Exception, e:
          logger.exception("Could not load template")
          raise TemplateDoesNotExist()
        
        return file.read(), template_name
  

