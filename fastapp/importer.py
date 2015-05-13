import logging

from distutils.util import strtobool
from configobj import ConfigObj

from fastapp.models import Base, Setting, Apy
from fastapp.utils import Connection

logger = logging.getLogger(__name__)


def import_base(zf, user_obj, name, override_public, override_private):
    base, created = Base.objects.get_or_create(user=user_obj, name=name)
    if not created:
        logger.warn("base '%s' did already exist" % name)
        base.save()

        # Dropbox connection
    try:
        dropbox_connection = Connection(base.auth_token)
    except Exception:
        pass

    # read app.config
    appconfig = ConfigObj(zf.open("app.config"))

    # get settings
    for k, v in appconfig['settings'].items():
        setting_obj, created = Setting.objects.get_or_create(base=base, key=k)
        # set if empty
        if not setting_obj.value:
            setting_obj.value = v['value']
        # override_public
        if setting_obj.public and override_public:
            setting_obj.value = v['value']
        # override_private
        if not setting_obj.public and override_private:
            setting_obj.value = v['value']
        setting_obj.public = strtobool(v['public'])
        setting_obj.save()

    filelist = zf.namelist()
    for file in filelist:
        # static
        logger.info("staticfile: "+file)
        content = zf.open(file).read()
        if file == "index.html":
            base.content = content
            base.save()

        if "static" in file:
            file = "/%s/%s" % (base.name, file)
            dropbox_connection.put_file(file, content)

        # Apy
        if file.endswith(".py"):
            logger.info("apy: "+file)
            name = file.replace(".py", "")
            apy, created = Apy.objects.get_or_create(base=base, name=name)
            apy.module = content
            description = appconfig['modules'][name]['description']
            if description:
                apy.description = description
            public = appconfig['modules'][name].get('public', None)
            if public:
                apy.public = strtobool(public)
            apy.save()

    return base
