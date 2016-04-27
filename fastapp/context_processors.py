from django.conf import settings
from planet import __VERSION__ as PLANET_VERSION
from fastapp import __version__ as FASTAPP_VERSION


def versions(request):
    return {
        'PLANET_VERSION': PLANET_VERSION,
        'FASTAPP_VERSION': FASTAPP_VERSION,
    }
