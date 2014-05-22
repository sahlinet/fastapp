import logging
import traceback
import json
import dropbox
import time
import copy

from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib import messages
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.template import RequestContext
from django.template.loader import render_to_string
from django.views.generic import View, TemplateView
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseNotFound, HttpResponse, HttpResponseRedirect, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseServerError
from django.views.generic.base import ContextMixin
from django.conf import settings
from django.views.generic import TemplateView
from django.views.decorators.cache import never_cache
from django.core import serializers
from dropbox.rest import ErrorResponse
from fastapp.utils import message
from fastapp import __version__ as version

from utils import UnAuthorized, Connection, NoBasesFound
from utils import info, error, warn, channel_name_for_user, debug, send_client
from fastapp.queue import generate_vhost_configuration
from fastapp.models import AuthProfile, Base, Apy, Setting, Executor, Process, Thread
from fastapp import responses

from django.core.cache import cache

from fastapp.executors.remote import call_rpc_client

logger = logging.getLogger(__name__)


class CockpitView(TemplateView):

    def get_context_data(self, **kwargs):
        context = super(CockpitView, self).get_context_data(**kwargs)
        context['executors'] = Executor.objects.all().order_by('base__name')
        context['process_list'] = Process.objects.all()
        context['threads'] = Thread.objects.all().order_by('parent__name', 'name')
        return context

class DjendStaticView(View):

    @never_cache
    def get(self, request, *args, **kwargs):
        static_path = "%s/%s/%s" % (kwargs['base'], "static", kwargs['name'])
        logger.info("get %s" % static_path)

        f = cache.get(static_path)
        if not f:
            logger.info("not in cache: %s" % static_path)
            base_model = Base.objects.get(name=kwargs['base'])
            auth_token = base_model.user.authprofile.access_token
            client = dropbox.client.DropboxClient(auth_token)
            # TODO: check if in cache?
            try:
                f = client.get_file(static_path).read()
            except ErrorResponse, e:
                logger.error("not found: '%s'" % static_path)
                return HttpResponseNotFound("Not found: "+static_path)
            cache.set(static_path, f, 60)
            logger.info("cache it: '%s'" % static_path)
        else:
            logger.info("found in cache: '%s'" % static_path)

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
        else:
            logger.error("suffix not recognized in '%s'" % static_path)
            return HttpResponseServerError("Static file suffix not recognized")
        logger.debug("deliver '%s' with '%s'" % (static_path, mimetype))
        return HttpResponse(f, mimetype=mimetype)

class DjendMixin(object):

    def connection(self, request):
        logger.info("Creating connection for %s" % request.user)
        return Connection(request.user.authprofile.access_token)


class DjendExecView(View, DjendMixin):
    STATE_OK = "OK"
    STATE_NOK = "NOK"
    STATE_NOT_FOUND = "NOT_FOUND"
    STATE_TIMEOUT = "TIMEOUT"

#    def _do(self, sfunc, do_kwargs):
#        exception = None;  returned = None
#        status = self.STATE_OK
#
#        func = None 
#
#        request = do_kwargs['request']
#        logger.info("do %s %s" % request.method, request.path_info)
#        username = copy.copy(do_kwargs['request'].user.username)
#
#        # debug incoming request
#        if request.method == "GET":
#            query_string = copy.copy(request.GET)
#        else:
#            query_string = copy.copy(request.POST)
#        try:
#            query_string.pop('json')
#        except KeyError, e:
#            logger.exception("invalid request")
#
#        user = channel_name_for_user(request)
#        debug(user, "%s-Request received, URI %s?%s " % (request.method, request.path, query_string.urlencode()))
#
#        try:
#
#            exec sfunc
#            func.username=username
#            func.channel=channel_name_for_user(request)
#            func.request=do_kwargs['request']
#            func.session=do_kwargs['request'].session
#
#            func.name = do_kwargs['exec_name']
#
#            # attach GET and POST data
#            func.GET=copy.deepcopy(request.GET)
#            func.POST=copy.deepcopy(request.POST)
#
#            # attach log functions
#            func.info=info
#            func.debug=debug
#            func.warn=warn
#            func.error=error
#
#            # attatch settings
#            setting_dict = do_kwargs['base_model'].setting.all().values('key', 'value')
#            setting_dict1 = Bunch()
#            for setting in setting_dict:
#                setting_dict1.update({setting['key']: setting['value']})
#            setting_dict1.update({'STATIC_DIR': "/%s/%s/static" % ("fastapp", do_kwargs['base_model'].name)})
#            func.settings = setting_dict1
#
#            returned = func(func)
#
#
#        except Exception, e:
#            exception = "%s: %s" % (type(e).__name__, e.message)
#            traceback.print_exc()
#            status = self.STATE_NOK
#        return {"status": status, "returned": returned, "exception": exception}
    @never_cache
    def get(self, request, *args, **kwargs):
        # get base
        base = kwargs['base']
        base_model = get_object_or_404(Base, name=base)

        # exec id
        exec_id = kwargs['id']

        # get exec from database
        try:
            exec_model = base_model.apys.get(name=exec_id)
        except Apy.DoesNotExist:
            warn(channel_name_for_user(request), "404 on %s" % request.META['PATH_INFO'])
            return HttpResponseNotFound("404 on %s"     % request.META['PATH_INFO'])

        user = channel_name_for_user(request)
        debug(user, "%s-Request received, URI %s" % (request.method, request.path))

        apy_data = serializers.serialize("json", [exec_model], fields=('base_id', 'name'))
        struct = json.loads(apy_data)
        apy_data = json.dumps(struct[0])
        rpc_request_data = {}
        rpc_request_data.update({'model': apy_data, 
                'base_name': base_model.name,
            })
        get_dict = copy.deepcopy(request.GET)
        post_dict = copy.deepcopy(request.POST)
        for key in ["json", "shared_key"]:
            if request.method == "GET":
                if get_dict.has_key(key): del get_dict[key]
            if request.method == "POST":
                if post_dict.has_key(key): del get_dict[key]
        rpc_request_data.update({'request': 
                { 
                'method': request.method,
                'GET': get_dict.dict(),
                'POST': post_dict.dict(),
                #'session': request.session.session_key,
                'user': {'username': request.user.username},
                'REMOTE_ADDR': request.META.get('REMOTE_ADDR')
                }
            })
        logger.debug("REQUEST-data: %s" % rpc_request_data)
        try:
            # _do on remote
            start = int(round(time.time() * 1000))
            response_data = call_rpc_client(json.dumps(rpc_request_data), 
                generate_vhost_configuration(base_model.user.username, base_model.name), 
                base_model.name, 
                base_model.executor.password)
            end = int(round(time.time() * 1000))
            ms=str(end-start)

            logger.info("RESPONSE-time: %sms" %  str(ms))
            logger.debug("RESPONSE-data: %s" % response_data[:120])
            data = json.loads(response_data)
        except Exception, e:
            logger.exception(e)
            raise HttpResponseServerError(e)

        # add exec's id to the response dict
        # add duration of rpc call
        data.update({
            "id": kwargs['id'],
            "time_ms": ms,
            })

        response_class = data.get("response_class", None)
        response_status_code = 200
        # respond with json
        if request.GET.has_key('json') or request.GET.has_key('callback'):
            user = channel_name_for_user(request)
            if data["status"] == "OK":
                info(user, str(data))
                exec_model.mark_executed()
            else:
                error(user, str(data))
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
                    {'executed': str(Apy.objects.get(id=exec_model.id).counter.executed), 
                        'failed': str(Apy.objects.get(id=exec_model.id).counter.failed)
                    },
                'apy_id': exec_model.id 
            }
            user = channel_name_for_user(request)
            send_client(user, "counter", cdata)

            # the exec can return an HttpResponseRedirect object, where we redirect
            if isinstance(data['returned'], HttpResponseRedirect):
                location = data['returned']['Location']
                info(user, "(%s) Redirect to: %s" % (exec_id, location))
                return HttpResponse(json.dumps({'redirect': data['returned']['Location']}), content_type="application/json", status=response_status_code)
            else:
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
                #content = json.loads(data['returned'])['content']
                content = json.loads(data['returned'])['content']
            else:
                logger.error("Wrong response")
                return HttpResponseServerError("You're apy did not return any allowed response-class or is not called with 'json' or 'callback' as querystring.")
            return HttpResponse(content, content_type, status=response_status_code)

        logger.error("Not received json or callback query string nor response_class from response.")
        return HttpResponseServerError()

        #return HttpResponse(data['returned'])

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
        context['DROPBOX_REDIRECT_URL'] = settings.DROPBOX_REDIRECT_URL
        context['PUSHER_KEY'] = settings.PUSHER_KEY
        context['CHANNEL'] = channel_name_for_user(request)
        context['FASTAPP_STATIC_URL'] = "/%s/%s/static/" % ("fastapp", base_model.name)

        rs = base_model.template(context)
        return HttpResponse(rs)

#class DjendMessageView(View):
#
#    def post(self, request, *args, **kwargs):
#        info(request.user.username, request.POST)
#        return HttpResponse()
#
#    @csrf_exempt
#    def dispatch(self, *args, **kwargs):
#        return super(DjendMessageView, self).dispatch(*args, **kwargs)

#MODULE_DEFAULT_CONTENT = """def func(self):\n\tpass"""

#class DjendExecSaveView(View):
#
#    def post(self, request, *args, **kwargs):
#        base = get_object_or_404(Base, name=kwargs['base'], user=User.objects.get(username=request.user))
#
#        # syncing to storage provider
#        # exec
#        if request.POST.has_key('exec_name'):
#            exec_name = request.POST.get('exec_name')
#            # save in database
#            #e = base.execs.get(name=exec_name)
#            try:
#                e, created = Apy.objects.get_or_create(name=exec_name, base=base)
#                if not created:
#                    warn(channel_name_for_user(request), "Exec '%s' does already exist" % exec_name)
#                    return HttpResponseBadRequest()
#                else:
#                    e.module = MODULE_DEFAULT_CONTENT
#                    e.save()
#            except Exception, e:
#                error(channel_name_for_user(request), "Error saving Exec '%s'" % exec_name)
#                return HttpResponseBadRequest(e)
#        # base
#
#        return HttpResponse('{"redirect": %s}' % request.META['HTTP_REFERER'])
#
#    @csrf_exempt
#    def dispatch(self, *args, **kwargs):
#        return super(DjendExecSaveView, self).dispatch(*args, **kwargs) 

class DjendBaseCreateView(View):

    def post(self, request, *args, **kwargs):
        base, created = Base.objects.get_or_create(name=request.POST.get('new_base_name'), user=User.objects.get(username=request.user.username))
        if not created:
            return HttpBadRequest()
        base.save()
        response_data = {"redirect": "/fastapp/%s/index/" % base.name}
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
            traceback.print_exc()
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
            info(request.user.username, "Exec '%s' deleted" % e.exec_name)
        except Exception, e:
            error(request.user.username, "Error deleting(%s)" % e)
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
                error(channel_name_for_user(request), "Exec '%s' is to big." % exec_name)
            else:    
                e.module = content
                e.description = request.POST.get('exec_description')
                e.save()
                info(channel_name_for_user(request), "Exec '%s' saved" % exec_name)
        # base
        else:
            base.content = content
            base.save()
            # save in database
            info(channel_name_for_user(request), "Base index '%s' saved" % base.name)

        return HttpResponse()

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super(DjendBaseSaveView, self).dispatch(*args, **kwargs)

class DjendBaseView(View, ContextMixin):

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
                context['VERSION'] = version
                context['FASTAPP_NAME'] = base
                context['DROPBOX_REDIRECT_URL'] = settings.DROPBOX_REDIRECT_URL
                context['PUSHER_KEY'] = settings.PUSHER_KEY
                context['CHANNEL'] = channel_name_for_user(request)
                context['FASTAPP_STATIC_URL'] = "/%s/%s/static/" % ("fastapp", base)
                context['active_base'] = base_model
                context['username'] = request.user.username
                context['LAST_EXEC'] = request.GET.get('done')
                rs = base_model.template(context)

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

        if not rs:
            rs = render_to_string("fastapp/index.html", context_instance=context)

        return HttpResponse(rs)


class DjendView(TemplateView):
    template_name = "fastapp/default.html"

    def get_context_data(self, **kwargs):
        context = super(DjendView, self).get_context_data(**kwargs)
        context['bases'] = Base.objects.filter(user=self.request.user).order_by('name')
        context['public_bases'] = Base.objects.filter(public=True).order_by('name')
        context['VERSION'] = version
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


@csrf_exempt
def login_or_sharedkey(function):
    def wrapper(request, *args, **kwargs):
        logger.info("authenticate %s" % request.user)
        user=request.user
        # if logged in
        if user.is_authenticated():
            return function(request, *args, **kwargs)
        # if shared key in query string
        base_name = kwargs.get('base')
        if request.GET.has_key('shared_key'):
            shared_key = request.GET.get('shared_key')
            logger.info(base_name)
            logger.info(shared_key)
            get_object_or_404(Base, name=base_name, uuid=shared_key)
            request.session['shared_key'] = shared_key
            return function(request, *args, **kwargs)
        # if shared key in session and corresponds to base
        has_shared_key = request.session.__contains__('shared_key')
        if has_shared_key:
            shared_key = request.session['shared_key']
            logger.info("authenticate on base '%s' with shared_key '%s'" % (base, shared_key))
            get_object_or_404(Base, name=base_name, uuid=shared_key)
            return function(request, *args, **kwargs)
        # don't redirect when access a exec withoud secret key
        if kwargs.has_key('id'):
            return HttpResponseNotFound('Ups, wrong URL?')
        return HttpResponseRedirect("/admin/")
    return wrapper

