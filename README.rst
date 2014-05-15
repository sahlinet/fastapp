==============
django-fastapp
==============

django-fastapp is a reusable Django app which lets you prototype apps in the browser with client- and server-side elements.

Installation
------------

Add fastapp to settings.INSTALLED_APPS

::

	"fastapp",

Install required modules

::

	pip install django-fastapp

Add fastapp to your urls.py

::

	("^fastapp/", include("fastapp.urls")),

Realtime Client-Server communication (http://pusher.com/)

::

	# pusher for websockets
	PUSHER_KEY = "xxxxxxx"
	PUSHER_SECRET = "xxxxxx"
	PUSHER_APP_ID = "xxxxxx"

Storages
--------

Dropbox
~~~~~~~

Add DROPBOX_CONSUMER_KEY and DROPBOX_CONSUMER_SECRET to your settings.py

::

	# django-fastapp
	DROPBOX_CONSUMER_KEY = "xxxxxx"
	DROPBOX_CONSUMER_SECRET = "xxxxxx"
	DROPBOX_REDIRECT_URL = "http://localhost:8000"


Usage
-----

- Read https://sahli.net/software/django-fastapp
- Visit http://localhost/fastapp