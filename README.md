# django-fastapp
-------

django-fastapp is a reusable Django app which lets you prototype apps in the browser with client- and server-side elements.

# Installation

Install required modules

	pip install django-fastapp


Add fastapp to settings.INSTALLED_APPS

	        "fastapp",

Add fastapp to your urls.py

	("^fastapp/", include("fastapp.urls")),


# Configuration

## Required

### Threads

	# Server
	FASTAPP_HEARTBEAT_LISTENER_THREADCOUNT = 10       # How many heartbeat listener threads are started
	FASTAPP_ASYNC_LISTENER_THREADCOUNT = 2			  # How many asynchronous response threads are started
	FASTAPP_LOG_LISTENER_THREADCOUNT = 2			  # How many log listener threads are started
	FASTAPP_CONSOLE_SENDER_THREADCOUNT = 2            # How many console threads are started 

	# Client
	FASTAPP_WORKER_THREADCOUNT = 30                   # How many worker threads are started
	FASTAPP_PUBLISH_INTERVAL = 5                      # How often the worker sends a heartbeat message

### Worker

#### Spawn Process

Workers are spawned from within server process.

> This can be a serious security whole if you have untrusted users!

    FASTAPP_WORKER_IMPLEMENTATION = "fastapp.executors.local.SpawnExecutor"

or

#### Docker

Workers are started in a Docker container.

    FASTAPP_WORKER_IMPLEMENTATION = "fastapp.executors.local.DockerExecutor"
    FASTAPP_DOCKER_MEM_LIMIT = "128m"
    FASTAPP_DOCKER_CPU_SHARES = 512

    FASTAPP_DOCKER_IMAGE = "tutum.co/philipsahli/skyblue-planet-worker:develop"

or

#### Tutum

Workers are started in a Docker container running on [Tutum.co](https://www.tutum.co/).

    FASTAPP_WORKER_IMPLEMENTATION = "fastapp.executors.local.TutumExecutor"
    TUTUM_USERNAME = "tutumuser"
    TUTUM_APIKEY = "asdf123asdf123asdf123asdf123"
	TUTUM_WORKER_IMAGE_NAME = "%(platform)s-%(name)s"			# must end in a unique service name in an account

	FASTAPP_DOCKER_MEM_LIMIT = "128m"
    FASTAPP_DOCKER_CPU_SHARES = 512

    FASTAPP_DOCKER_IMAGE = "tutum.co/philipsahli/skyblue-planet-worker:develop"

### Queue

For asynchronous communication RabbitMQ is used. The admin user is used to setup users and virtual hosts.

	RABBITMQ_ADMIN_USER = "admin"
	RABBITMQ_ADMIN_PASSWORD = "admin"
	RABBITMQ_HOST = "localhost"
	RABBITMQ_PORT = 5672
    RABBITMQ_HTTP_API_PORT = 15672

Following credentials are used for heartbeating between workers and server.

    FASTAPP_CORE_SENDER_PASSWORD = "asdf"
    FASTAPP_CORE_RECEIVER_PASSWORD = "asdf"

### Dropbox Storage

Create a Dropbox App and enter the key and secret.

	# django-fastapp
	DROPBOX_CONSUMER_KEY = "xxxxxx"
	DROPBOX_CONSUMER_SECRET = "xxxxxx"
	DROPBOX_REDIRECT_URL = "http://localhost:8000"

Development only (runserver) for loading static files, root path used for loading static files:

	FASTAPP_REPOSITORIES_PATH = "/Users/fatrix/Dropbox/Repositories"
	FASTAPP_DEV_STORAGE_DROPBOX_PATH="/Users/fatrix/Dropbox/Apps/planet dev"

## Optional

### Push events (http://pusher.com/)

	# pusher for websockets
	PUSHER_KEY = "xxxxxxx"
	PUSHER_SECRET = "xxxxxx"
	PUSHER_APP_ID = "xxxxxx"

# Running

    python manage.py runserver

    python manage.py heartbeat

    python manage.py console

# Usage

- Read more on [sahli.net](https://sahli.net/software/django-fastapp)
- Visit [http://localhost:8000/fastapp](http://localhost:8000/fastapp)