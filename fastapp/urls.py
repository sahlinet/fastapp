from django.conf.urls import patterns, url
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from fastapp.views import DjendBaseView, DjendBaseDeleteView, DjendBaseSaveView, \
                DjendBaseCreateView, DjendExecDeleteView, DjendExecView, DjendStaticView, \
                login_or_sharedkey, dropbox_auth_finish, dropbox_auth_start, DjendView, \
                DjendBaseRenameView, CockpitView
from rest_framework import routers

from fastapp.api_views import BaseViewSet, SettingViewSet, ApyViewSet, BaseExportViewSet, BaseImportViewSet, TransportEndpointViewSet


from django.views.decorators.cache import never_cache

# Routers provide an easy way of automatically determining the URL conf
router = routers.DefaultRouter(trailing_slash=True)
router.register(r'apy', ApyViewSet)
router.register(r'base', BaseViewSet)

urlpatterns = patterns('',

    # dropbox auth
    url(r'dropbox_auth_start/?$',dropbox_auth_start),
    url(r'dropbox_auth_finish/?$',dropbox_auth_finish),

    url(r'cockpit/$', login_required(never_cache(CockpitView.as_view(template_name="fastapp/cockpit.html")))),

    # base
    url(r'(?P<base>[\w-]+)/index/$', login_required(DjendBaseView.as_view())),
    url(r'(?P<base>[\w-]+)/sync/$', login_required(DjendBaseSaveView.as_view())),
    url(r'(?P<base>[\w-]+)/new/$', login_required(DjendBaseCreateView.as_view())),
    url(r'(?P<base>[\w-]+)/delete/$', login_required(DjendBaseDeleteView.as_view())),
    url(r'(?P<base>[\w-]+)/rename/$', login_required(DjendBaseRenameView.as_view())),

    # execs
    url(r'(?P<base>[\w-]+)/exec/(?P<id>\w+)/$', \
                                            csrf_exempt(login_or_sharedkey(DjendExecView.as_view()))),
    url(r'(?P<base>[\w-]+)/delete/(?P<id>\w+)/$', \
                                            login_required(DjendExecDeleteView.as_view())),

    # static
    url(r'(?P<base>[\w-]+)/static/(?P<name>.+)$', \
                                            login_or_sharedkey(DjendStaticView.as_view())),
    # api
    url(r'^api/transportendpoints/$', TransportEndpointViewSet.as_view({'get': 'list', 'post': 'create'}), name='transportendpoint-list'),
    url(r'^api/transportendpoints/(?P<pk>\d+)/$', TransportEndpointViewSet.as_view({'put': 'update'}), name='transportendpoint-list'),
    url(r'^api/base/$', BaseViewSet.as_view({'get': 'list', 'post': 'create'}), name='base-list'),
    url(r'^api/base/(?P<pk>\d+)/$', BaseViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='base-detail'),
    url(r'^api/base/(?P<pk>\d+)/start/$', BaseViewSet.as_view({'post': 'start'}), name='base-stop'),
    url(r'^api/base/(?P<pk>\d+)/stop/$', BaseViewSet.as_view({'post': 'stop'}), name='base-start'),
    url(r'^api/base/(?P<pk>\d+)/export/$', BaseExportViewSet.as_view({'get': 'export'}), name='base-export'),
    url(r'^api/base/(?P<pk>\d+)/transport/$', BaseViewSet.as_view({'post': 'transport'}), name='base-transport'),
    url(r'^api/base/import/$', csrf_exempt(BaseImportViewSet.as_view({'post': 'imp'})), name='base-import'),
    url(r'^api/base/(?P<base_pk>\d+)/apy/$', ApyViewSet.as_view({'get': 'list', 'post': 'create'}), name='apy-list'),
    url(r'^api/base/(?P<base_pk>\d+)/apy/(?P<pk>\d+)/$', ApyViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='apy-detail'),
    url(r'^api/base/(?P<base_pk>\d+)/apy/(?P<pk>\d+)/clone/$', ApyViewSet.as_view({'post': 'clone'}), name='apy-clone'),
    url(r'^api/base/(?P<base_pk>\d+)/setting/$', SettingViewSet.as_view({'get': 'list', 'post': 'create'}), name='apy-list'),
    url(r'^api/base/(?P<base_pk>\d+)/setting/(?P<pk>\d+)/$', SettingViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='apy-detail'),

    # api-authtoken
    url(r'^api-token-auth/', 'rest_framework.authtoken.views.obtain_auth_token'),

    # home
    url(r'^$', DjendView.as_view()),
)

from rest_framework.urlpatterns import format_suffix_patterns
urlpatterns = format_suffix_patterns(urlpatterns, allowed=['json', 'api'])
