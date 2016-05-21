import os
import sys
import base64
import logging
import json
import dropbox

from datetime import datetime

from django.contrib.auth import get_user_model

from django.views.generic import View

from django.http import HttpResponseNotFound, HttpResponse, HttpResponseServerError, HttpResponseNotModified

from django.conf import settings
from dropbox.rest import ErrorResponse
from django.core.cache import cache
from django.template import Context, Template, RequestContext

from fastapp.utils import totimestamp, fromtimestamp

from fastapp.queue import generate_vhost_configuration
from fastapp.models import Base

from fastapp.executors.remote import get_static
from fastapp.plugins.datastore import PsqlDataStore

from fastapp.views import ResponseUnavailableViewMixing


User = get_user_model()

logger = logging.getLogger(__name__)


class DjendStaticView(ResponseUnavailableViewMixing, View):

    def _render_html(self, request, t, **kwargs):
        if type(t) == str:
            t = Template(t)
        else:
            t = Template(t.read())
        c = RequestContext(request, kwargs)
        return t.render(c)


    def get(self, request, **kwargs):
        static_path = "%s/%s/%s" % (kwargs['base'], "static", kwargs['name'])
        logger.debug("%s GET" % static_path)

        base_model = Base.objects.get(name=kwargs['base'])

        last_modified = None

        response = self.verify(request, base_model)
        if response:
            return response

        cache_key = "%s-%s-%s" % (base_model.user.username, base_model.name, static_path)
        cache_obj = cache.get(cache_key)

        file = None
        if cache_obj:
            file = cache_obj.get('f', None)

        if not file:
            try:
                logger.info("%s: not in cache" % static_path)

                REPOSITORIES_PATH = getattr(settings, "FASTAPP_REPOSITORIES_PATH", None)
                if "runserver" in sys.argv and REPOSITORIES_PATH:
                    # for debugging with local runserver not loading from repository or dropbox directory
                    # but from local filesystem
                    try:
                        filepath = os.path.join(REPOSITORIES_PATH, static_path)
                        file = open(filepath, 'r')
                        size = os.path.getsize(filepath)
                        logger.debug("%s: load from local filesystem (repositories) (%s) (%s)" % (static_path, filepath, size))
                        last_modified = datetime.fromtimestamp(os.stat(filepath).st_mtime)
                    except IOError, e:
                        logger.warning(e)
                    if not file:
                        try:
                            DEV_STORAGE_DROPBOX_PATH = getattr(settings, "FASTAPP_DEV_STORAGE_DROPBOX_PATH")
                            filepath = os.path.join(DEV_STORAGE_DROPBOX_PATH, static_path)
                            file = open(filepath, 'r')
                            size = os.path.getsize(filepath)
                            logger.debug("%s: load from local filesystem (dropbox app) (%s) (%s)" % (static_path, filepath, size))
                            last_modified = datetime.fromtimestamp(os.stat(filepath).st_mtime)
                        except IOError, e:
                            logger.warning(e)
                            #warn(channel, static_path + " not found in %s" (filepath))
                            return HttpResponseNotFound(static_path + " not found")
                else:
                    # try to load from installed module in worker
                    logger.info("%s: load from module in worker" % static_path)
                    response_data = get_static(
                        json.dumps({"base_name": base_model.name, "path": static_path}),
                        generate_vhost_configuration(
                            base_model.user.username,
                            base_model.name
                            ),
                        base_model.name,
                        base_model.executor.password
                        )
                    data = json.loads(response_data)

                    if data['status'] == "ERROR":
                        logger.error("%s: ERROR response from worker" % static_path)
                        raise Exception(response_data)
                    elif data['status'] == "TIMEOUT":
                        return HttpResponseServerError("Timeout")
                    elif data['status'] == "OK":
                        file = base64.b64decode(data['file'])
                        last_modified = datetime.fromtimestamp(data['LM'])
                        logger.info("%s: file received from worker with timestamp: %s" % (static_path, str(last_modified)))
                    # get from dropbox
                    elif data['status'] == "NOT_FOUND":
                        logger.info(data)
                        logger.info("%s: file not found on worker, try to load from dropbox" % static_path)
                        # get file from dropbox
                        auth_token = base_model.user.authprofile.access_token
                        client = dropbox.client.DropboxClient(auth_token)
                        try:
                            # TODO: read file only when necessary
                            dropbox_path = os.path.join(base_model.user.username, static_path)
                            file, metadata = client.get_file_and_metadata(dropbox_path)
                            file = file.read()

                            # "modified": "Tue, 19 Jul 2011 21:55:38 +0000",
                            dropbox_frmt = "%a, %d %b %Y %H:%M:%S +0000"
                            last_modified = datetime.strptime(metadata['modified'], dropbox_frmt)
                            logger.info("%s: file loaded from dropbox (lm: %s)" % (dropbox_path, last_modified))
                        except Exception, e:
                            logger.warning("File '%s'not found on dropbox" % dropbox_path)
                            raise e
                    if 'content="no-cache"' in file:
                         logger.info("Not caching because no-cache present in HTML")
                    else:
                         cache.set(cache_key, {
                               'f': file,
                               'lm': totimestamp(last_modified)
                               }, int(settings.FASTAPP_STATIC_CACHE_SECONDS))
            except (ErrorResponse, IOError), e:
                logger.exception(e)
                logger.warning("%s: not found" % static_path)
                logger.info("%s: 404" % file)
                return HttpResponseNotFound("Not Found: "+static_path)
        else:
            logger.info("%s: found in cache" % static_path)
            logger.info("%s: last_modified in cache" % cache_obj['lm'])
            try:
                last_modified = fromtimestamp(cache_obj['lm'])
            except Exception, e:
                logger.exception(e)
                last_modified = None

        # default
        mimetype = "text/plain"
        if static_path.endswith('.js'):
            mimetype = "text/javascript"
        elif static_path.endswith('.css'):
            mimetype = "text/css"
        elif static_path.endswith('.json'):
            mimetype = "application/json"
        elif static_path.endswith('.png'):
            mimetype = "image/png"
        elif static_path.endswith('.woff'):
            mimetype = "application/x-font-woff"
        elif static_path.endswith('.svg'):
            mimetype = "image/svg+xml"
        elif static_path.endswith('.ttf'):
            mimetype = "application/x-font-ttf"
        elif static_path.lower().endswith('.jpg'):
            mimetype = "image/jpeg"
        elif static_path.lower().endswith('.ico'):
            mimetype = "image/x-icon"
        elif static_path.lower().endswith('.html'):
            mimetype = "text/html"
            context_data = self._setup_context(request, base_model)
            file = self._render_html(request, file, **context_data)
            context_data['datastore'] = None
            context_data = None
        elif static_path.lower().endswith('.map'):
            mimetype = "application/json"
        elif static_path.lower().endswith('.gif'):
            mimetype = "image/gif"
        elif static_path.lower().endswith('.swf'):
            mimetype = "application/x-shockwave-flash"
        else:
            logger.warning("%s: suffix not recognized" % static_path)
            logger.info("%s: 500" % file)
            return HttpResponseServerError("Staticfile suffix not recognized")
        logger.info("%s: with '%s'" % (static_path, mimetype))

        return self._handle_cache(static_path, request, mimetype, last_modified, file)

    def _handle_cache(self, static_path, request, mimetype, last_modified, file):
        if 'content="no-cache"' in file:
            logger.info("Not caching because no-cache present in HTML")
            response = HttpResponse(file, content_type=mimetype)
        else:
            # handle browser caching
            frmt = "%d %b %Y %H:%M:%S"
            try:
                file.seek(0)
            except AttributeError:
                pass
            if_modified_since = request.META.get('HTTP_IF_MODIFIED_SINCE', None)
            if last_modified and if_modified_since:
                if_modified_since_dt = datetime.strptime(if_modified_since, frmt)
                last_modified = last_modified.replace(microsecond=0)
                logger.debug("%s: checking if last_modified '%s' or smaller/equal of if_modified_since '%s'" % (static_path, last_modified, if_modified_since_dt))
                if (last_modified <= if_modified_since_dt):
                    logger.info("%s: 304" % static_path)
                    return HttpResponseNotModified()
            response = HttpResponse(file, content_type=mimetype)
            if last_modified:
                response['Cache-Control'] = "public"
                response['Last-Modified'] = last_modified.strftime(frmt)
            if static_path.endswith("png") or static_path.endswith("css") or static_path.endswith("js") \
                    or static_path.endswith("woff"):
                response['Cache-Control'] = "max-age=120"
            logger.info("%s: 200" % static_path)
        return response


    def _setup_context(self, request, base_model):
        data = dict((s.key, s.value) for s in base_model.setting.all())

        data['FASTAPP_STATIC_URL'] = "/%s/%s/static/" % ("fastapp", base_model.name)

        try:
            logger.debug("Setup datastore for context starting")
            plugin_settings = settings.FASTAPP_PLUGINS_CONFIG['fastapp.plugins.datastore']
            data['datastore'] = PsqlDataStore(schema=base_model.name, keep=False, **plugin_settings)
            logger.debug("Setup datastore for context done")
            logger.debug("Datastore-Size: %s" % data['datastore'].count())
        except KeyError, e:
            logger.error("Setup datastore for context failed")
        updated = request.GET.copy()
        query_params = {}
        for k, v in updated.iteritems():
            query_params[k] = v
        data['QUERY_PARAMS'] = query_params

        return data
