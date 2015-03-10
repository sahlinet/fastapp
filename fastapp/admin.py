from django.contrib import admin
from fastapp.models import Base, Apy, Transaction, TransportEndpoint, AuthProfile

from django.contrib.auth import get_user_model
User = get_user_model()

class BaseAdmin(admin.ModelAdmin):
    pass
admin.site.register(Base, BaseAdmin)

class ApyAdmin(admin.ModelAdmin):
    pass

class TransactionAdmin(admin.ModelAdmin):
    pass

class TransportEndpointAdmin(admin.ModelAdmin):
    pass

class UserAdmin(admin.ModelAdmin):
    pass

class AuthProfileAdmin(admin.ModelAdmin):
    pass

admin.site.register(Apy, ApyAdmin)
admin.site.register(Transaction, TransactionAdmin)
admin.site.register(TransportEndpoint, TransportEndpointAdmin)
admin.site.register(AuthProfile, AuthProfileAdmin)
admin.site.register(User, UserAdmin)
