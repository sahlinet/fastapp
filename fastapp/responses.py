import json
class Response(object):

	def __init__(self, content):
		if hasattr(self, "CONTENT_TYPE"):
			self.content_type = self.CONTENT_TYPE
		else:
			self.content_type = None
		self.content = content

	def serialize(self):
		return {'content_type': self.content_type,
				'content': self.content,
				'class': self.__class__.__name__
		}

	def __str__(self):
		return json.dumps(self.serialize())

class XMLResponse(Response):
	CONTENT_TYPE = "application/xml"

class HTMLResponse(Response):
	CONTENT_TYPE = "text/html"

class JSONResponse(Response):
	CONTENT_TYPE = "application/json"

class RedirectResponse(Response):
	pass
