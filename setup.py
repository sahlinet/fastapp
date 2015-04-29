from setuptools import setup, find_packages
from fastapp import __version__ as version

setup(name='django-fastapp',
	version=version,
	description='Reusable Django app for prototyping',
	long_description='django-fastapp is a reusable Django app which lets you prototype apps in the browser with client- and server-side elements.',
	url="https://github.com/fatrix/django-fastapp",
	author="Philip Sahli",
	author_email="philip@sahli.net",
	dependency_links=[
		'https://github.com/sahlinet/swampdragon/tarball/master#egg=SwampDragon-0.4.1.2'
	],
	install_requires=['dropbox==1.6',
		'djangorestframework==2.4.2',
		'requests==2.4.1',
		'django_extensions==1.3.5',
		'pusher==0.8',
		'bunch==1.0.1',
		'gevent==1.0',
		'pika==0.9.13',
		'jsonfield==0.9.22',
		'pyflakes==0.8.1',
		'configobj==5.0.5',
		'pyOpenSSL==0.14',
		'ndg-httpsclient==0.3.2',
		'pyasn1==0.1.7',
		'python-tutum==0.12.6',
		'SwampDragon>=0.4.1.2',
		'SwampDragon-auth==0.1.3'
	],
	packages = find_packages(),
	package_data = {'fastapp': ['fastapp/templates/*']},
	include_package_data=True,
	license ='MIT'
)
