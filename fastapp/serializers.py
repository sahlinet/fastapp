from swampdragon.serializers.model_serializer import ModelSerializer


class ApySocketSerializer(ModelSerializer):
    class Meta:
        model = 'fastapp.Apy'
        publish_fields = ('name')


class TransactionSerializer(ModelSerializer):
    apy = "app.ApySocketSerializer"

    class Meta:
        model = 'fastapp.Transaction'
        publish_fields = ('rid', 'async', 'created', 'modified', 'apy', 'tin', 'tout', 'logs')

    def serialize_apy_name(self, obj):
        return obj.apy.name

    def serialize_base_name(self, obj):
        return obj.apy.base.name

    def serialize_logs(self, obj):
        return [{'msg': log.msg,
                 'slevel': log.slevel,
                 'created': str(log.created),
            } for log in obj.logs.all()]

class LogEntrySerializer(ModelSerializer):
    apy = "app.LogEntry"

    class Meta:
        model = 'fastapp.LogEntry'
        publish_fields = ('tid', 'created', 'level', 'slevel', 'msg')
