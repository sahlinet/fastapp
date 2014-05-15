import pusher
import pika
from django.conf import settings

def get_pusher_instance():
    print "get_pusher"
    p = pusher.Pusher(
      app_id=settings.PUSHER_APP_ID,
      key=settings.PUSHER_KEY,
      secret=settings.PUSHER_SECRET
    )
    return p
pusher_instance = get_pusher_instance()


def callback(ch, method, properties, body):
	payload = body.loads(body)
	channel = payload['channel']
	event = payload['event']
	data = payload['data']
	print "CALLBACK", body
	pusher_instance[channel].trigger(event, data)


def send_events():
	print "START - SEND_EVENTS Consumer"
	connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
	channel = connection.channel()
	channel.basic_consume(callback,
                      queue='pusher_events',
                      no_ack=True
	)	
	print "END - SEND_EVENTS Consumer"