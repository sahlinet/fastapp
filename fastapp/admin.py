from django.contrib import admin
from fastapp.models import Base, Apy

class BaseAdmin(admin.ModelAdmin):
    pass
admin.site.register(Base, BaseAdmin)

class ApyAdmin(admin.ModelAdmin):
    pass
admin.site.register(Apy, ApyAdmin)