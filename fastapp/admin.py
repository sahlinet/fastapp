from django.contrib import admin
from fastapp.models import Base, Apy, Transaction, TransportEndpoint, AuthProfile, Executor, Instance

from django.contrib.auth import get_user_model
User = get_user_model()

class BaseAdmin(admin.ModelAdmin):
    pass

class InstanceAdmin(admin.ModelAdmin):
    pass

class ApyAdmin(admin.ModelAdmin):
    list_display = ('name', 'public', 'schedule')

class TransactionAdmin(admin.ModelAdmin):
    list_display = ('rid', 'status')

class TransportEndpointAdmin(admin.ModelAdmin):
    pass

class UserAdmin(admin.ModelAdmin):
    pass

class AuthProfileAdmin(admin.ModelAdmin):
    pass

class ExecutorAdmin(admin.ModelAdmin):
    list_display = ('base', 'pid', 'ip', 'ip6', 'port',)

admin.site.register(Base, BaseAdmin)
admin.site.register(Apy, ApyAdmin)
admin.site.register(Transaction, TransactionAdmin)
admin.site.register(TransportEndpoint, TransportEndpointAdmin)
admin.site.register(AuthProfile, AuthProfileAdmin)
admin.site.register(Executor, ExecutorAdmin)
admin.site.register(Instance, InstanceAdmin)
