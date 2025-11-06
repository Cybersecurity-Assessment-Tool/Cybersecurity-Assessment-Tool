from django.contrib import admin
from .models import *

admin.site.register(User)
admin.site.register(Organization)
admin.site.register(Report)
admin.site.register(Risk)
