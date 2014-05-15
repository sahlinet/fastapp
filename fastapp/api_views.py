from rest_framework.renderers import JSONRenderer, JSONPRenderer
from rest_framework import permissions, viewsets
from rest_framework import generics

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404

from fastapp.models import Base, Apy, Setting
from fastapp.serializers import ApySerializer, BaseSerializer, SettingSerializer
from fastapp.utils import info, error, warn
from rest_framework.decorators import link
from rest_framework.response import Response

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
        return Base.objects.filter(user=self.request.user)

    def start(self, request, pk):
        logger.info("starting %s" % pk)
        base = self.get_queryset().get(id=pk)
        base.start()
        return self.retrieve(request, pk=pk)

    def stop(self, request, pk):
        logger.info("stopping %s" % pk)
        base = self.get_queryset().get(id=pk)
        base.stop()
        return self.retrieve(request, pk=pk)

    @link()
    def apy(self, request, pk=None):
        queryset = Apy.objects.filter(base__pk=pk)
        serializer = ApySerializer(queryset, 
                context={'request': request}, many=True)
        return Response(serializer.data)


#class BaseListView(generics.GenericAPIView):
#    serializer_class = BaseSerializer
#    permission_classes = (permissions.IsAuthenticated,)
#
#    def get_queryset(self):
#        return Base.objects.filter(user=self.request.user)

#class BaseListView(generics.GenericAPIView):
#    serializer_class = BaseSerializer
#    permission_classes = (permissions.IsAuthenticated,)
#
#    def get_queryset(self):
#        return Base.objects.filter(user=self.request.user)

    #@link()
    #def apy(self, request, pk=None):
    #    queryset = Apy.objects.filter(base__pk=pk)
    #    serializer = ApySerializer(queryset, 
    #            context={'request': request}, many=True)
    #    return Response(serializer.data)
