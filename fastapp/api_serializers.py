from rest_framework import serializers
from rest_framework.reverse import reverse
from fastapp.models import Base, Apy, Setting, Counter, TransportEndpoint, Transaction, LogEntry

import logging
logger = logging.getLogger(__name__)


class CounterSerializer(serializers.ModelSerializer):

    class Meta:
        model = Counter
        fields = ('executed', 'failed')

class LogSerializer(serializers.ModelSerializer):

    class Meta:
        model = LogEntry
        fields = ('level', 'msg', 'created', )


class TransactionSerializer(serializers.ModelSerializer):
    logs = LogSerializer(many=True, read_only=True)

    class Meta:
        model = Transaction
        fields = ('rid', 'tin', 'tout', 'status', 'created', 'modified', 'async', 'logs', )


class ApySerializer(serializers.ModelSerializer):
    counter = CounterSerializer(many=False, read_only=True)

    class Meta:
        model = Apy
        fields = ('id', 'name', 'module', 'counter', 'description', 'public', 'schedule', 'everyone')

    def save_object(self, obj, **kwargs):
        logger.debug("save_and_sync")
        obj.save_and_sync(**kwargs)


class PublicApySerializer(serializers.ModelSerializer):
    """
    Return all Apy objects which are made public. Enrich
    """
    first_lastname = serializers.SerializerMethodField(method_name="creator")
    base = serializers.SerializerMethodField(method_name="base_name")
    url = serializers.SerializerMethodField(method_name="detail_view")

    class Meta:
        model = Apy
        fields = ('id', 'name', 'module', 'description',
                  'first_lastname', 'url', 'base')

    def creator(self, obj):
        try:
            user = obj.base.user
            return user.first_name + " " + user.last_name
        except Base.DoesNotExist, e:
            logger.warn(e)

    def base_name(self, obj):
        return obj.base.name

    def detail_view(self, obj):
        return reverse('public-apy-detail', args=[obj.pk],
                       request=self.context['request'])


class SettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Setting
        fields = ('id', 'key', 'value', 'public')


class TransportEndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = TransportEndpoint
        fields = ('id', 'url', 'override_settings_priv',
                  'override_settings_pub', 'token')


class BaseSerializer(serializers.ModelSerializer):
    apy = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    state = serializers.Field()
    executors = serializers.Field()
    foreign_apys = serializers.HyperlinkedRelatedField(
        many=True,
        read_only=False,
        view_name='public-apy-detail'
    )

    class Meta:
        model = Base
        fields = ('id', 'name', 'state', 'uuid',
                  'executors', 'content', 'foreign_apys', 'public', 'static_public',)

    def save_object(self, obj, **kwargs):
        super(BaseSerializer, self).save_object(obj, **kwargs)
        logger.debug("save_and_sync")
        obj.save_and_sync(**kwargs)
