from rest_framework import serializers
from fastapp.models import Base, Apy, Setting, Counter, TransportEndpoint

class CounterSerializer(serializers.ModelSerializer):

    class Meta:
        model = Counter
        fields = ('executed', 'failed')

class ApySerializer(serializers.ModelSerializer):
    counter = CounterSerializer(many=False, read_only=True)

    class Meta:
        model = Apy
        fields = ('id', 'name', 'module', 'counter', 'description')
        #fields = ('id', 'name', 'module' )

    #def get_counter(self, obj):
    #    return obj.counter.executed

class SettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Setting
        fields = ('id', 'key', 'value', 'public')

class TransportEndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = TransportEndpoint
        fields = ('id', 'url', 'override_settings_priv', 'override_settings_pub', 'token')

class BaseSerializer(serializers.ModelSerializer):
    apy = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    state = serializers.Field()
    pids = serializers.Field()

    class Meta:
        model = Base
        #fields = ('id', 'name', 'uuid')
        fields = ('id', 'name', 'state', 'uuid', 'pids', 'content')
