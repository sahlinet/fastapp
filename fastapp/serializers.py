from swampdragon.serializers.model_serializer import ModelSerializer


class ApySocketSerializer(ModelSerializer):
    class Meta:
        model = 'fastapp.Apy'
        publish_fields = ('name')


class TransactionSerializer(ModelSerializer):
    apy = "app.ApySocketSerializer"

    class Meta:
        model = 'fastapp.Transaction'
        publish_fields = ('rid', 'async', 'created', 'modified', 'apy')


class LogEntrySerializer(ModelSerializer):
    apy = "app.LogEntry"

    class Meta:
        model = 'fastapp.LogEntry'
        publish_fields = ('tid', 'created', 'level', 'slevel', 'msg')
