import logging
from django.template import TemplateDoesNotExist
from django.template.loader import BaseLoader
from dropbox.rest import ErrorResponse
from fastapp.utils import Connection


class Loader(BaseLoader):
    is_usable = True

    def load_template_source(self, template_name, template_dirs=None):
        if ":" in template_name:
            username, template_name = template_name.split(":")
            connection = Connection(username)
            try:
                logging.debug("get_file %s" % template_name)
                f = connection.get_file(template_name)
                return f, template_name
            except ErrorResponse, e:
                if e.__dict__['status'] == 404:
                    raise TemplateDoesNotExist(template_name)
            except Exception, e:
                raise e
        raise TemplateDoesNotExist()

    load_template_source.is_usable = True
