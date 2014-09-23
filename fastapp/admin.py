from django.contrib import admin
from fastapp.models import Base, Apy, Transaction, TransportEndpoint

class BaseAdmin(admin.ModelAdmin):
    pass
admin.site.register(Base, BaseAdmin)

class ApyAdmin(admin.ModelAdmin):
    pass

class TransactionAdmin(admin.ModelAdmin):
    pass

class TransportEndpointAdmin(admin.ModelAdmin):
    pass

admin.site.register(Apy, ApyAdmin)
admin.site.register(Transaction, TransactionAdmin)
admin.site.register(TransportEndpoint, TransportEndpointAdmin)