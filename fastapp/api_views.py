# -*- coding: utf-8 -*-
import zipfile
import re
from rest_framework.renderers import JSONRenderer, JSONPRenderer
from rest_framework import permissions, viewsets

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from rest_framework import renderers
from rest_framework import status


from fastapp.utils import Connection
from fastapp.models import Base, Apy, Setting
from fastapp.serializers import ApySerializer, BaseSerializer, SettingSerializer
from fastapp.utils import info, check_code
from django.db import transaction
from rest_framework.decorators import link
from rest_framework.response import Response
from rest_framework.exceptions import APIException
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
        logger.info("Check code syntax")
        result, warnings, errors = check_code(obj.module, obj.name)
        logger.info(str(result))
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
            logger.info(str(warnings))
            logger.info(str(errors))
            response_data = {
                'warnings' : warnings_prep,
                'errors' : errors_prep
            }
            raise APIException(response_data)

    def post_save(self, obj, created=False):
        info(self.request.user.username, "Apy saved")

    def clone(self, request, base_pk, pk):
        base = get_object_or_404(Base, id=base_pk, user=User.objects.get(username=request.user.username))
        clone_count = base.apys.filter(name__startswith="%s_clone" % pk).count()
        created = False
        while not created:
            cloned_exec, created = Apy.objects.get_or_create(base=base, name="%s_clone_%s" % (pk, str(clone_count+1)))
            clone_count+=1

        cloned_exec.module = base.apys.get(id=pk).module
        cloned_exec.save()

        self.object = cloned_exec
        self.kwargs['pk'] = self.object.id
        return self.retrieve(request, new_pk=cloned_exec.id)

class BaseViewSet(viewsets.ModelViewSet):
    model = Base
    serializer_class = BaseSerializer
    renderer_classes = [JSONRenderer, JSONPRenderer]
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
        logger.info("stopping %s" % pk)
        base = self.get_queryset().select_for_update().get(id=pk)
        base.stop()
        transaction.commit()
        return self.retrieve(request, pk=pk)

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
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        return Base.objects.all()._clone().filter(user=self.request.user)

    def imp(self, request):
        # Base
        name = request.POST['name']
        base, created = Base.objects.get_or_create(user=request.user, name=name)
        if not created:
            raise Exception("Base '%s' does already exist" % name)
        base.save()
        f = request.FILES['file'] 
        zf = zipfile.ZipFile(f)

        # Dropbox connection
        dropbox_connection = Connection(base.auth_token)

        # read app.config
        from configobj import ConfigObj
        appconfig = ConfigObj(zf.open("app.config"))

        # get settings
        for k, v in appconfig['settings'].items():
            setting_obj = Setting(base=base)
            setting_obj.key = k
            setting_obj.value = v
            setting_obj.save()

        filelist = zf.namelist()
        for file in filelist:
            # static
            content = zf.open(file).read()
            if "static" in file:
                file = "/%s/%s" % (base.name, file)
                dropbox_connection.put_file(file, content)

            # Apy
            if "py" in file:
                apy = Apy(base=base)
                apy.name = file.replace(".py", "")
                apy.module = content
                apy.save()

        base_queryset = base
        serializer = BaseSerializer(base_queryset, 
                context={'request': request}, many=False)
        response = Response(serializer.data, status=201)
        return response
