import os
import base64
import logging
import json
import dropbox
import time
import copy
import sys
import threading
import re

from datetime import datetime, timedelta

from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.template import RequestContext
from django.template.loader import render_to_string
from django.views.generic import View, TemplateView
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseNotFound, HttpResponse, HttpResponseRedirect, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseServerError, HttpResponsePermanentRedirect
from django.views.generic.base import ContextMixin
from django.conf import settings
from django.views.decorators.cache import never_cache
from django.core import serializers
from dropbox.rest import ErrorResponse
from django.core.cache import cache
from django.template import Context, Template

from fastapp import __version__ as version
from fastapp.utils import UnAuthorized, Connection, NoBasesFound, message, info, warn, channel_name_for_user, send_client

from fastapp.queue import generate_vhost_configuration
from fastapp.models import AuthProfile, Base, Apy, Setting, Executor, Process, Thread, Transaction
from fastapp.models import RUNNING, FINISHED
from fastapp import responses
from fastapp.executors.remote import call_rpc_client, get_static

User = get_user_model()

logger = logging.getLogger(__name__)

use_plans = True
try:
    from plans.quota import get_user_quota
except ImportError:
    use_plans = False


class CockpitView(TemplateView):

    def get_context_data(self, **kwargs):
        context = super(CockpitView, self).get_context_data(**kwargs)
        qs = Executor.objects.all().order_by('base__name')
        if not self.request.user.is_superuser:
            qs = qs.filter(base__user=self.request.user)
        context['executors'] = qs.order_by('base__name')
        context['process_list'] = Process.objects.all().order_by('-running')
        context['threads'] = Thread.objects.all().order_by('parent__name', 'name')
        return context

    def dispatch(self, *args, **kwargs):
        if not self.request.user.is_superuser:
            return HttpResponseNotFound()
        return super(CockpitView, self).dispatch(*args, **kwargs)

class ResponseUnavailableViewMixing():
    def verify(self, request, base_model):
        if not base_model.state:
            response = HttpResponse()
            if "html" in request.META['HTTP_ACCEPT']:
                response.content_type = "text/html"
                response.content = "Base is not available"
            response.status_code = 503
            return response
        else:
            return None


class DjendStaticView(ResponseUnavailableViewMixing, View):

    def _render_html(self, t, **kwargs):
        if type(t) == str:
            t = Template(t)
        else:
            t = Template(t.read())
        c = Context(kwargs)
        return t.render(c)

    @never_cache
    def get(self, request, *args, **kwargs):
        static_path = "%s/%s/%s" % (kwargs['base'], "static", kwargs['name'])
        logger.debug("get %s" % static_path)
        channel = channel_name_for_user(request)
        info(channel, "get %s" % static_path)

        base_model = Base.objects.get(name=kwargs['base'])

        # if not base_model.state:
        #    response = HttpResponse()
        #    if "html" in request.META['HTTP_ACCEPT']:
        #        response.content_type = "text/html"
        #        response.content = "Base is not available"
        #    response.status_code=503
        #    return response
        response = self.verify(request, base_model)
        if response:
            return response

        f = cache.get(base_model.name+"-"+static_path)
        if not f:
            try:
                logger.debug("not in cache: %s" % static_path)

                REPOSITORIES_PATH = getattr(settings, "FASTAPP_REPOSITORIES_PATH", None)
                if "runserver" in sys.argv and REPOSITORIES_PATH:
                    # for debugging with local runserver not loading from repository or dropbox directory
                    # but from local filesystem
                    try:
                        logger.debug("load %s from local filesystem (repositories)" % static_path)
                        full_path = os.path.join(REPOSITORIES_PATH, static_path)
                        logger.debug(full_path)
                        f = open(full_path, 'r')
                    except IOError, e:
                        logger.warning(e)
                    if not f:
                        try:
                            DEV_STORAGE_DROPBOX_PATH = getattr(settings, "FASTAPP_DEV_STORAGE_DROPBOX_PATH")
                            logger.debug("load %s from local filesystem (dropbox app)" % static_path)
                            filepath = os.path.join(DEV_STORAGE_DROPBOX_PATH, static_path)
                            f = open(filepath, 'r')
                        except IOError, e:
                            logger.warning(e)
                            warn(channel, static_path + " not found")
                            return HttpResponseNotFound(static_path + " not found")
                else:
                    # try to load from installed module in worker
                    logger.debug("load %s from module in worker" % static_path)
                    response_data = get_static(
                        json.dumps({"base_name": base_model.name, "path": static_path}),
                        generate_vhost_configuration(
                            base_model.user.username,
                            base_model.name),
                            base_model.name,
                            base_model.executor.password
                        )
                    data = json.loads(response_data)

                    if data['status'] == "ERROR":
                        logger.error("ERROR response from worker")
                        raise Exception(response_data)
                    elif data['status'] == "TIMEOUT":
                        return HttpResponseServerError("Timeout")
                    elif data['status'] == "OK":
                        logger.debug("File received from worker")
                        f = base64.b64decode(data['file'])
                    # get from dropbox
                    elif data['status'] == "NOT_FOUND":
                        logger.debug("File not found from worker")
                        # get file from dropbox
                        auth_token = base_model.user.authprofile.access_token
                        client = dropbox.client.DropboxClient(auth_token)
                        try:
                            f = client.get_file(static_path).read()
                        except Exception, e:
                            logger.warning("File not found on dropbox")
                            raise e
                    cache.set(base_model.name+"-"+static_path, f, 60)
                    logger.debug("cache it: '%s'" % static_path)
            except (ErrorResponse, IOError), e:
                logger.warning("not found: '%s'" % static_path)
                return HttpResponseNotFound("Not found: "+static_path)
        else:
            logger.debug("found in cache: '%s'" % static_path)

        # default
        mimetype = "text/plain"
        if static_path.endswith('.js'):
            mimetype = "text/javascript"
        elif static_path.endswith('.css'):
            mimetype = "text/css"
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
            f = self._render_html(f, **dict((s.key, s.value) for s in base_model.setting.all()))
        elif static_path.lower().endswith('.map'):
            mimetype = "application/json"
        elif static_path.lower().endswith('.gif'):
            mimetype = "image/gif"
        elif static_path.lower().endswith('.swf'):
            mimetype = "application/x-shockwave-flash"
        else:
            logger.warning("suffix not recognized in '%s'" % static_path)
            return HttpResponseServerError("Static file suffix not recognized")
        logger.debug("deliver '%s' with '%s'" % (static_path, mimetype))
        return HttpResponse(f, content_type=mimetype)

class DjendMixin(object):

    def connection(self, request):
        logger.debug("Creating connection for %s" % request.user)
        return Connection(request.user.authprofile.access_token)


class DjendExecView(View, ResponseUnavailableViewMixing, DjendMixin):
    STATE_OK = "OK"
    STATE_NOK = "NOK"
    STATE_NOT_FOUND = "NOT_FOUND"
    STATE_TIMEOUT = "TIMEOUT"

    def _prepare_request(self, request, exec_model):
        apy_data = serializers.serialize("json", [exec_model],
                                         fields=('base_id', 'name'))
        struct = json.loads(apy_data)
        apy_data = json.dumps(struct[0])

        request_data = {}
        request_data.update({'model': apy_data,
                             'base_name': exec_model.base.name})
        get_dict = copy.deepcopy(request.GET)
        post_dict = copy.deepcopy(request.POST)
        for key in ["json", "shared_key"]:
            if request.method == "GET":
                if key in get_dict:
                    del get_dict[key]
            if request.method == "POST":
                if key in post_dict:
                    del get_dict[key]
        request_data.update({'request': {
                'method': request.method,
                'content_type': request.META.get('Content-Type'),
                'GET': get_dict.dict(),
                'POST': post_dict.dict(),
                'user': {'username': request.user.username},
                'UUID': exec_model.base.uuid,
                'REMOTE_ADDR': request.META.get('REMOTE_ADDR')
            }
            })
        logger.debug("REQUEST-data: %s" % request_data)
        return request_data

    def _execute(self, request, request_data, base_model, rid):
        try:
            # _do on remote
            start = int(round(time.time() * 1000))
            request_data.update({'rid': rid})
            response_data = call_rpc_client(json.dumps(request_data),
                generate_vhost_configuration(
                    base_model.user.username,
                    base_model.name),
                    base_model.name,
                    base_model.executor.password
                    )
            end = int(round(time.time() * 1000))
            ms=str(end-start)

            logger.debug("RESPONSE-time: %sms" %  str(ms))
            logger.debug("RESPONSE-data: %s" % response_data[:120])
            data = json.loads(response_data)
            data.update({
                #"id": kwargs['id'],
                "time_ms": ms,
            })
        except Exception, e:
            logger.exception(e)
            raise Exception("Could not execute request")
        return data

    def _execute_async(self, request, request_data, base_model, rid):
        try:
            # _do on remote
            request_data.update({'rid': rid})
            call_rpc_client(json.dumps(request_data),
                generate_vhost_configuration(
                    base_model.user.username,
                    base_model.name),
                    base_model.name,
                    base_model.executor.password,
                    async=True
                    )
        except Exception, e:
            logger.exception(e)
            raise e
        return True

    #@memory_profile
    def _handle_response(self, request, data, exec_model):
        response_class = data.get("response_class", None)
        default_status_code = 200
        logger.debug(data)
        if not data.has_key('returned'):
            response_status_code = default_status_code
        else:
            if response_class:
                response_status_code = json.loads(data['returned']).get('status_code', default_status_code)
            else:
                response_status_code = default_status_code

        # respond with json
        if request.GET.has_key(u'json') or request.GET.has_key('callback'):

            user = channel_name_for_user(request)

            if data["status"] == "OK":
                exec_model.mark_executed()
            else:
                #error(user, str(data))
                exec_model.mark_failed()

            if data["status"] in [self.STATE_NOK]:
                response_status_code = 500
            elif data["status"] in [self.STATE_NOT_FOUND]:
                response_status_code = 404
            elif data["status"] in [self.STATE_TIMEOUT]:
                response_status_code = 502

            # send counter to client
            cdata = {
                'counter':
                    {
                    'executed': str(Apy.objects.get(id=exec_model.id).counter.executed),
                    'failed': str(Apy.objects.get(id=exec_model.id).counter.failed)
                    },
                'apy_id': exec_model.id
            }
            user = channel_name_for_user(request)
            send_client(user, "counter", cdata)

            if request.GET.has_key('callback'):
                data = '%s(%s);' % (request.REQUEST['callback'], json.dumps(data))
                return HttpResponse(data, "application/javascript")
            return HttpResponse(json.dumps(data), content_type="application/json", status=response_status_code)

        # real response
        elif response_class:
            if response_class == u''+responses.XMLResponse.__name__:
                content_type = json.loads(data['returned'])['content_type']
                content = json.loads(data['returned'])['content']
            elif response_class == u''+responses.HTMLResponse.__name__:
                content_type = json.loads(data['returned'])['content_type']
                content = json.loads(data['returned'])['content']
            elif response_class == u''+responses.JSONResponse.__name__:
                content_type = json.loads(data['returned'])['content_type']
                content = json.loads(data['returned'])['content']
            elif response_class == u''+responses.RedirectResponse.__name__:
                location = json.loads(data['returned'])['content']
                return HttpResponseRedirect(location)
            else:
                logger.warning("Wrong response")
                return HttpResponseServerError("You're apy did not return any allowed response-class or is not called with 'json' or 'callback' as querystring.")


            return HttpResponse(content, content_type, status=response_status_code)

        else:
            msg = "Not received json or callback query string nor response_class from response."
            logger.error("Not received json or callback query string nor response_class from response.")
            return HttpResponseServerError(msg)

    #@profile
    @never_cache
    def get(self, request, *args, **kwargs):
        # get base
        base_model = get_object_or_404(Base, name=kwargs['base'])

        response = self.verify(request, base_model)
        if response:
            return response

        # get exec from database
        try:
            exec_model = base_model.apys.get(name=kwargs['id'])
        except Apy.DoesNotExist:
            #warning(channel_name_for_user(request), "404 on %s" % request.META['PATH_INFO'])
            return HttpResponseNotFound("404 on %s"     % request.META['PATH_INFO'])

        rid = request.GET.get('rid', None)
        if rid:
            # look for transaction
            transaction = Transaction.objects.get(pk=rid)
            if transaction.tout:
                data = json.loads(transaction.tout)
                #data.update({'logs':
                #        json.loads(serializers.serialize("json", transaction.logs.all()))
                #    })
            else:
                data = {'status': transaction.get_status_display()}
                redirect_to = request.get_full_path()
                data.update({'url': redirect_to})
        else:
            request_data = self._prepare_request(request, exec_model)
            transaction = Transaction(apy=exec_model)
            transaction.tin = json.dumps(request_data)
            transaction.status = RUNNING
            transaction.save()

            if request.GET.has_key('async') or request.POST.has_key('async'):
                transaction.async = True
                transaction.save()
                # execute async
                data = self._execute_async(request, request_data, base_model, transaction.rid)
                redirect_to = request.get_full_path()+"&rid=%s" % transaction.rid
                return HttpResponsePermanentRedirect(redirect_to)
            else:
                # execute
                data = self._execute(request, request_data, base_model, transaction.rid)
                transaction.tout = json.dumps(data)
                transaction.status = FINISHED
                transaction.save()

        # add exec's id to the response dict
        data.update({
            "id": kwargs['id'],
            "rid": transaction.rid
            })

        # response
        response = self._handle_response(request, data, exec_model)
        return response


    @method_decorator(csrf_exempt)
    def post(self, request, *args, **kwargs):
        return DjendExecView.get(self, request, *args, **kwargs)

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(DjendExecView, self).dispatch(*args, **kwargs)

class DjendSharedView(View, ContextMixin):

    def get(self, request, *args, **kwargs):
        context = RequestContext(request)
        base_name = kwargs.get('base')
        shared_key = request.GET.get('shared_key')

        if not shared_key:
            shared_key = request.session.get('shared_key')

        base_model = get_object_or_404(Base, name=base_name, uuid=shared_key)
        # store it in session list
        if not request.session.__contains__('shared_bases'):
            request.session['shared_bases'] = {}
        request.session['shared_bases'][base_name] = shared_key
        request.session.modified = True

        # context
        context['VERSION'] = version
        context['shared_bases'] = request.session['shared_bases']
        context['FASTAPP_EXECS'] = base_model.apys.all().order_by('name')
        context['LAST_EXEC'] = request.GET.get('done')
        context['active_base'] = base_model
        context['username'] = request.user.username
        context['FASTAPP_NAME'] = base_model.name
        #context['DROPBOX_REDIRECT_URL'] = settings.DROPBOX_REDIRECT_URL
        #context['PUSHER_KEY'] = settings.PUSHER_KEY
        context['CHANNEL'] = channel_name_for_user(request)
        context['FASTAPP_STATIC_URL'] = "/%s/%s/static/" % ("fastapp", base_model.name)

        rs = base_model.template(context)
        return HttpResponse(rs)

class DjendBaseCreateView(View):

    def post(self, request, *args, **kwargs):

        # TODO: should be in planet project and not fastapp
        if use_plans:
            if get_user_quota(request.user).get('MAX_BASES_PER_USER') <= request.user.bases.count():
                return HttpResponseForbidden("Too many bases for your plan.")

        base, created = Base.objects.get_or_create(name=request.POST.get('new_base_name'), user=User.objects.get(username=request.user.username))
        if not created:
            return HttpResponseBadRequest("A base with this name does already exist.")
        base.save()
        from fastapp.api_serializers import BaseSerializer
        base_data = BaseSerializer(base)
        response_data = base_data.data
        return HttpResponse(json.dumps(response_data), content_type="application/json")

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super(DjendBaseCreateView, self).dispatch(*args, **kwargs)

class DjendBaseDeleteView(View):

    def post(self, request, *args, **kwargs):
        base = Base.objects.get(name=kwargs['base'], user=User.objects.get(username=request.user.username))
        base.delete()
        response_data = {"redirect": "/fastapp/"}
        return HttpResponse(json.dumps(response_data), content_type="application/json")

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super(DjendBaseDeleteView, self).dispatch(*args, **kwargs)


class DjendBaseSettingsView(View):

    def get(self, request, *args, **kwargs):
        base = Base.objects.get(name=kwargs['base'])
        base_settings = base.setting.all().extra(\
            select={'lower_key':'lower(key)'}).order_by('lower_key').values('key', 'value', 'id')
        return HttpResponse(json.dumps(list(base_settings)), content_type="application/json")

    def delete(self, request, *args, **kwargs):
        base = Base.objects.get(name=kwargs['base'])
        base_setting = base.setting.get(id=kwargs['id'])
        base_setting.delete()
        return HttpResponse(content_type="application/json")

    def post(self, request, *args, **kwargs):
        base_settings = json.loads(request.POST.get('settings'))
        try:
            for setting in base_settings:
                base = Base.objects.get(name=kwargs['base'])
                if setting.has_key('id'):
                    setting_obj = Setting.objects.get(base=base, id=setting['id'])
                    setting_obj.key = setting['key']
                else:
                    setting_obj = Setting(key=setting['key'], base=base)
                setting_obj.value = setting['value']
                setting_obj.save()
        except Exception:
            logger.exception()
        return HttpResponse({}, content_type="application/json")

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super(DjendBaseSettingsView, self).dispatch(*args, **kwargs)


class DjendExecDeleteView(View):

    def post(self, request, *args, **kwargs):
        base = get_object_or_404(Base, name=kwargs['base'], user=User.objects.get(username=request.user.username))

        # syncing to storage provider
        # exec
        e = base.apys.get(name=kwargs['id'])
        try:
            e.delete()
            #info(request.user.username, "Exec '%s' deleted" % e.exec_name)
        except Exception, e:
            pass
            #error(request.user.username, "Error deleting(%s)" % e)
        return HttpResponse('{"redirect": %s}' % request.META['HTTP_REFERER'])

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super(DjendExecDeleteView, self).dispatch(*args, **kwargs)


    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super(DjendExecRenameView, self).dispatch(*args, **kwargs)

class DjendBaseRenameView(View):

    def post(self, request, *args, **kwargs):
        base = get_object_or_404(Base, name=kwargs['base'], user=User.objects.get(username=request.user.username))
        base.name = request.POST.get('new_name')
        base.save()
        response_data = {"redirect": request.META['HTTP_REFERER'].replace(kwargs['base'], base.name)}
        return HttpResponse(json.dumps(response_data), content_type="application/json")

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super(DjendBaseRenameView, self).dispatch(*args, **kwargs)

class DjendBaseSaveView(View):

    def post(self, request, *args, **kwargs):
        base = get_object_or_404(Base, name=kwargs['base'], user=User.objects.get(username=request.user.username))
        content = request.POST.get('content', None)

        # exec
        if request.POST.has_key('exec_name'):
            exec_name = request.POST.get('exec_name')
            # save in database
            e = base.apys.get(name=exec_name)
            if len(content) > 8200:
                pass
                #error(channel_name_for_user(request), "Exec '%s' is to big." % exec_name)
            else:
                e.module = content
                e.description = request.POST.get('exec_description')
                e.save()
                info(channel_name_for_user(request), "Exec '%s' saved" % exec_name)
        # base
        else:
            logger.info("Save base")
            base.content = content
            base.save()
            # save in database
            #info(channel_name_for_user(request), "Base index '%s' saved" % base.name)

        return HttpResponse()

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super(DjendBaseSaveView, self).dispatch(*args, **kwargs)

class DjendBaseView(TemplateView, ContextMixin):

    def _refresh_single_base(self, base):
        base = Base.objects.get(name=base)
        base.refresh()
        base.save()

    def get(self, request, *args, **kwargs):
        rs = None
        context = RequestContext(request)

        # redirect to shared view
        if not request.user.is_authenticated():
            if request.GET.has_key('shared_key') or request.session.__contains__("shared_key"):
                return DjendSharedView.as_view()(request, *args, **kwargs)

        try:
            # refresh bases from dropbox
            refresh = "refresh" in request.GET

            base = kwargs.get('base')

            if refresh and base:
                self._refresh_single_base(base)

            base_model = None
            if base:
                base_model = get_object_or_404(Base, name=base, user=request.user.id)
                #base_model.save()
                #if refresh:
                #    base_model.refresh_execs()

                # execs
                try:
                    context['FASTAPP_EXECS'] = base_model.apys.all().order_by('name')
                except ErrorResponse, e:
                    messages.warning(request, "No app.json found", extra_tags="alert-warning")
                    logging.debug(e)

            # context
            try:
                context['bases'] = Base.objects.filter(user=request.user.id).order_by('name')
                context['FASTAPP_NAME'] = base
                #context['DROPBOX_REDIRECT_URL'] = settings.DROPBOX_REDIRECT_URL
                #context['PUSHER_KEY'] = settings.PUSHER_KEY
                context['CHANNEL'] = channel_name_for_user(request)
                context['FASTAPP_STATIC_URL'] = "/%s/%s/static/" % ("fastapp", base)
                context['active_base'] = base_model
                context['username'] = request.user.username
                context['LAST_EXEC'] = request.GET.get('done')
                context['transaction_list'] = Transaction.objects.filter(apy__base__name=base).filter(created__gte=datetime.now()-timedelta(minutes=30)).order_by('created')
                #rs = base_model.template(context)

            except ErrorResponse, e:
                if e.__dict__['status'] == 404:
                    logging.debug(base)
                    logging.debug("Template not found")
                    messages.error(request, "Template %s not found" % template_name, extra_tags="alert-danger")

        # error handling
        except (UnAuthorized, AuthProfile.DoesNotExist), e:
            return HttpResponseRedirect("/fastapp/dropbox_auth_start")
        except NoBasesFound, e:
            message(request, logging.WARNING, "No bases found")

        rs = render_to_string("fastapp/base.html", context_instance=context)
        #rs = render_to_string("fastapp/base.html", context_instance=context)

        return HttpResponse(rs)


class DjendView(TemplateView):

    def get_context_data(self, **kwargs):
        context = super(DjendView, self).get_context_data(**kwargs)
        context['bases'] = Base.objects.filter(user=self.request.user).order_by('name')
        context['public_bases'] = Base.objects.filter(public=True).order_by('name')

        context['FASTAPP_VERSION'] = version
        import planet
        context['PLANET_VERSION'] = planet.__VERSION__
        #try:
        #    token = self.request.user.auth_token
        #except Token.DoesNotExist:
        #    token = Token.objects.create(user=self.request.user)
        #context['TOKEN'] = token
        return context

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(DjendView, self).dispatch(*args, **kwargs)


def get_dropbox_auth_flow(web_app_session):
    redirect_uri = "%s/fastapp/dropbox_auth_finish" % settings.DROPBOX_REDIRECT_URL
    dropbox_consumer_key = settings.DROPBOX_CONSUMER_KEY
    dropbox_consumer_secret = settings.DROPBOX_CONSUMER_SECRET
    return dropbox.client.DropboxOAuth2Flow(dropbox_consumer_key, dropbox_consumer_secret, redirect_uri, web_app_session, "dropbox-auth-csrf-token")


# URL handler for /dropbox-auth-start
def dropbox_auth_start(request):
    authorize_url = get_dropbox_auth_flow(request.session).start()
    return HttpResponseRedirect(authorize_url)


# URL handler for /dropbox-auth-finish
def dropbox_auth_finish(request):
    try:
        access_token, user_id, url_state = get_dropbox_auth_flow(request.session).finish(request.GET)
        auth, created = AuthProfile.objects.get_or_create(user=request.user)
        # store access_token
        auth.access_token = access_token
        auth.dropbox_userid = user_id
        auth.user = request.user
        auth.save()

        return HttpResponseRedirect("/fastapp/")
    except dropbox.client.DropboxOAuth2Flow.BadRequestException, e:
        return HttpResponseBadRequest(e)
    except dropbox.client.DropboxOAuth2Flow.BadStateException, e:
        # Start the auth flow again.
        return HttpResponseRedirect("http://www.mydomain.com/dropbox_auth_start")
    except dropbox.client.DropboxOAuth2Flow.CsrfException, e:
        return HttpResponseForbidden()
    except dropbox.client.DropboxOAuth2Flow.NotApprovedException, e:
        raise e
    except dropbox.client.DropboxOAuth2Flow.ProviderException, e:
        raise e

# URL handler for /dropbox-auth-start
def dropbox_auth_disconnect(request):
    request.user.authprofile.access_token = ""
    request.user.authprofile.save()
    return HttpResponseRedirect("/profile/")


def process_user(uid):
    auth_profile = AuthProfile.objects.filter(dropbox_userid=uid)[0]
    token = auth_profile.access_token
    user = auth_profile.user
    logger.info("Process change notfication for user: %s" % user.username)
    cursor = cache.get("cursor-%s" % uid)

    client = Connection(token)

    has_more = True

    while has_more:
        result = client.delta(cursor)

        for path, metadata in result['entries']:

            # Handle only files ending with ".py"
            if not path.endswith("py") or not metadata or "/." in path:
                logger.debug("Ignore path: %s" % path)
                continue

            regex = re.compile("/(.*)/([a-zA-Z-_0-9]*).py")
            r = regex.search(path)
            if not r:
                logger.warn("regex '/(.*)/(.*).py' no results in '%s'" % path)
                continue
            names = r.groups()
            base_name = names[0]
            apy_name = names[1]
            logger.info("notification for: base_name: %s, apy_name: %s, user: %s" % (base_name, apy_name, user))

            try:
                apy = Apy.objects.get(name=apy_name, base__name=base_name)
            except Apy.DoesNotExist, e:
                logger.warn(e.message)
                continue

            new_rev = metadata['rev']
            logger.debug("local rev: %s, remote rev: %s" % (apy.rev, new_rev))
            if apy.rev == new_rev:
                logger.debug("no changes")
            else:
                logger.info("load changes for %s" % path)

                content, rev = client.get_file_content_and_rev("%s" % path)
                apy.module = content
                apy.rev = rev
                apy.save()
                logger.debug("Apy %s saved" % apy.name)

        # Update cursor
        cursor = result['cursor']
        cursor = cache.set("cursor-%s" % uid, cursor)

        # Repeat only if there's more to do
        has_more = result['has_more']


class DropboxNotifyView(View):

    def get(self, request):
        challenge = request.GET['challenge']
        return HttpResponse(challenge)

    def post(self, request):
        logger.debug(request.body)

        # get delta for user
        for uid in json.loads(request.body)['delta']['users']:
            threading.Thread(target=process_user, args=(uid,)).start()

        return HttpResponse()

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super(DropboxNotifyView, self).dispatch(*args, **kwargs)


@csrf_exempt
def login_or_sharedkey(function):
    def wrapper(request, *args, **kwargs):
        logger.debug("authenticate %s" % request.user)
        user=request.user

        # if logged in
        if user.is_authenticated():
            return function(request, *args, **kwargs)

        # if shared key in query string
        base_name = kwargs.get('base')
        if request.GET.has_key('shared_key'):
            shared_key = request.GET.get('shared_key')
            get_object_or_404(Base, name=base_name, uuid=shared_key)
            request.session['shared_key'] = shared_key
            return function(request, *args, **kwargs)
        # if shared key in session and corresponds to base
        #has_shared_key = request.session.__contains__('shared_key')
        #if has_shared_key:
        #    shared_key = request.session['shared_key']
        #    logger.info("authenticate on base '%s' with shared_key '%s'" % (base, shared_key))
        #    get_object_or_404(Base, name=base_name, uuid=shared_key)
        #    return function(request, *args, **kwargs)
        # don't redirect when access a exec withoud secret key
        if kwargs.has_key('id'):
            return HttpResponseNotFound('Ups, wrong URL?')
        return HttpResponseRedirect("/admin/")
    return wrapper
