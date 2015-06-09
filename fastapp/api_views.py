# -*- coding: utf-8 -*-
import zipfile
import requests
from threading import Thread
from rest_framework.renderers import JSONRenderer, JSONPRenderer
from rest_framework import permissions, viewsets
from rest_framework import status

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404

from django.db import transaction
from django.core.management import call_command

from rest_framework import renderers
from rest_framework.authentication import SessionAuthentication, TokenAuthentication, BasicAuthentication

from fastapp.importer import import_base
from fastapp.models import Base, Apy, Setting, TransportEndpoint
from fastapp.api_serializers import PublicApySerializer, ApySerializer, BaseSerializer, SettingSerializer, TransportEndpointSerializer
from fastapp.utils import check_code

from rest_framework.decorators import link
from rest_framework.response import Response
from rest_framework.exceptions import APIException

from django.contrib.auth import get_user_model
User = get_user_model()

import logging
logger = logging.getLogger(__name__)


class SettingViewSet(viewsets.ModelViewSet):
    model = Setting
    serializer_class = SettingSerializer
    renderer_classes = [JSONRenderer, JSONPRenderer]

    def get_queryset(self):
        base_pk = self.kwargs['base_pk']
        return Setting.objects.filter(base__user=self.request.user, base__pk=base_pk)

    def pre_save(self, obj):
        obj.base = Base.objects.get(id=self.kwargs['base_pk'])


class TransportEndpointViewSet(viewsets.ModelViewSet):
    model = TransportEndpoint
    serializer_class = TransportEndpointSerializer
    authentication_classes = (SessionAuthentication,)

    def get_queryset(self):
        return TransportEndpoint.objects.filter(user=self.request.user)

    def pre_save(self, obj):
        obj.user = self.request.user


class ApyViewSet(viewsets.ModelViewSet):
    model = Apy
    serializer_class = ApySerializer
    renderer_classes = [JSONRenderer, JSONPRenderer]
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        base_pk = self.kwargs['base_pk']
        return Apy.objects.filter(base__user=self.request.user, base__pk=base_pk)

    def pre_save(self, obj):
        obj.base = Base.objects.get(id=self.kwargs['base_pk'], user=self.request.user)
        result, warnings, errors = check_code(obj.module, obj.name)
        warnings_prep = []
        errors_prep = []
        for warning in warnings:
            warnings_prep.append(
                {
                    'filename': warning.filename,
                    'lineno': warning.lineno,
                    'col': warning.col,
                    'msg': warning.message % warning.message_args,
                })

        for error in errors:
            errors_prep.append(
                {
                    'filename': error.filename,
                    'lineno': error.lineno,
                    'col': error.col,
                    'msg': error.message,
                })
        if not result:
            response_data = {
                'warnings': warnings_prep,
                'errors': errors_prep
            }
            raise APIException(response_data)

    def post_save(self, obj, created=False):
        pass

    def clone(self, request, base_pk, pk):
        base = get_object_or_404(Base, id=base_pk,
                        user=User.objects.get(username=request.user.username))
        clone_count = base.apys.filter(name__startswith="%s_clone" % pk).count()
        created = False
        while not created:
            cloned_exec, created = Apy.objects.get_or_create(base=base,
                                name="%s_clone_%s" % (pk, str(clone_count+1)))
            clone_count += 1

        cloned_exec.module = base.apys.get(id=pk).module
        cloned_exec.save()

        self.object = cloned_exec
        self.kwargs['pk'] = self.object.id
        return self.retrieve(request, new_pk=cloned_exec.id)


class PublicApyViewSet(ApyViewSet):
    serializer_class = PublicApySerializer

    def get_queryset(self):
        return Apy.objects.filter(public=True)


class BaseAdminViewSet(viewsets.ModelViewSet):
    model = Base
    serializer_class = BaseSerializer
    renderer_classes = [JSONRenderer, JSONPRenderer]
    authentication_classes = (
        TokenAuthentication,
        SessionAuthentication,
        BasicAuthentication
        )
    permission_classes = (permissions.IsAuthenticated, permissions.IsAdminUser)

    def get_queryset(self):
        return Base.objects.all()._clone().all()

    def destroy_all(self, request):
        logger.info("Destroy all workers")
        thread = Thread(target=call_command, args=('destroy_workers', ))
        thread.start()
        return Response("ok", status=status.HTTP_202_ACCEPTED)

    def recreate_all(self, request):
        logger.info("Recreate all workers")
        thread = Thread(target=call_command, args=('recreate_workers', ))
        thread.start()
        return Response("ok", status=status.HTTP_202_ACCEPTED)


class BaseLogViewSet(viewsets.ViewSet):
    model = Base
    renderer_classes = [JSONRenderer, JSONPRenderer]
    authentication_classes = (
        TokenAuthentication,
        SessionAuthentication,
        BasicAuthentication
        )
    permission_classes = (permissions.IsAuthenticated, permissions.IsAdminUser)

    def log(self, request, pk):
        base = Base.objects.get(pk=pk)
        logs = base.executor.implementation.log(base.executor.pid)
        return Response(logs)


class BaseViewSet(viewsets.ModelViewSet):
    model = Base
    serializer_class = BaseSerializer
    renderer_classes = [JSONRenderer, JSONPRenderer]
    authentication_classes = (TokenAuthentication, SessionAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        return Base.objects.all()._clone().filter(user=self.request.user)

    def start(self, request, pk):
        transaction.set_autocommit(False)
        logger.info("starting %s" % pk)
        base = self.get_queryset().get(id=pk)
        base.start()
        transaction.commit()
        return self.retrieve(request, pk=pk)

    def stop(self, request, pk):
        transaction.set_autocommit(False)
        base = self.get_queryset().select_for_update(nowait=True).get(id=pk)
        logger.info("stopping %s" % base.name)
        base.stop()
        transaction.commit()
        return self.retrieve(request, pk=pk)

    def restart(self, request, pk):
        transaction.set_autocommit(False)
        logger.info("restarting %s" % pk)
        base = self.get_queryset().get(id=pk)
        base.stop()
        base.start()
        transaction.commit()
        return self.retrieve(request, pk=pk)

    def destroy(self, request, pk):
        transaction.set_autocommit(False)
        logger.info("destroying %s: " % pk)
        base = self.get_queryset().get(id=pk)
        base.stop()
        base.destroy()
        transaction.commit()
        return self.retrieve(request, pk=pk)

    def transport(self, request, pk):
        base = self.get_queryset().get(pk=pk)
        transport_url = self.request.DATA['url']
        transport_token = self.request.DATA['token']
        zf = base.export()
        zf.seek(0)
        logger.info("Calling "+transport_url)
        logger.info("Token "+transport_token)
        transport = TransportEndpoint.objects.get(
                user=request.user,
                url=transport_url
                )
        r = requests.post(transport_url, headers={
            'Authorization': 'Token '+transport_token
            }, data={
            'name': base.name,
            'override_private': transport.override_settings_priv,
            'override_public': transport.override_settings_pub,
            }, files={
            'file': zf
            }, verify=False)
        logger.info(r.request.headers)
        logger.info((r.status_code))
        logger.info((r.text))

        s = "transport %s" % transport_url
        if r.status_code == 201:
            logger.info("%s success" % s)
            return self.retrieve(request, pk=pk)
        else:
            print r.status_code
            logger.error("%s failed with returncode %s" % (s, r.status_code))
            raise Exception("%s failed" % s)

    @link()
    def apy(self, request, pk=None):
        queryset = Apy.objects.filter(base__pk=pk)
        serializer = ApySerializer(queryset,
                context={'request': request}, many=True)
        return Response(serializer.data)


class ZipFileRenderer(renderers.BaseRenderer):
    media_type = 'application/zip'
    format = 'zip'

    def render(self, data, media_type=None, renderer_context=None):
        return data


class BaseExportViewSet(viewsets.ModelViewSet):
    model = Base
    permission_classes = (permissions.IsAuthenticated,)
    renderer_classes = [ZipFileRenderer]

    def get_queryset(self):
        return Base.objects.all()._clone().filter(user=self.request.user)

    def export(self, request, pk):
        base = self.get_queryset().get(id=pk)
        f = base.export()
        logger.info(f)

        response = Response(f.getvalue(), headers={
            'Content-Disposition': 'attachment; filename=%s.zip' % base.name
            }, content_type='application/zip')
        return response


class BaseImportViewSet(viewsets.ModelViewSet):
    model = Base
    authentication_classes = (TokenAuthentication, SessionAuthentication, )
    permission_classes = (permissions.IsAuthenticated,)

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(BaseImportViewSet, self).dispatch(*args, **kwargs)

    def get_queryset(self):
        return Base.objects.all()._clone().filter(user=self.request.user)

    def imp(self, request):
        logger.info("start import")
        # Base
        name = request.POST['name']
        override_public = bool(request.GET.get('override_public', False))
        override_private = bool(request.GET.get('override_private', False))

        f = request.FILES['file']
        zf = zipfile.ZipFile(f)

        base = import_base(zf,
                           request.user,
                           name,
                           override_public,
                           override_private)

        base_queryset = base
        base.save()
        serializer = BaseSerializer(base_queryset,
                                    context={'request': request}, many=False)
        response = Response(serializer.data, status=201)
        return response
