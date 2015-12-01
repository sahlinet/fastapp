from datetime import datetime, timedelta

from django import template

register = template.Library()


@register.assignment_tag
def get_past_datetime(delta, step):
    if step == "h":
        td = timedelta(hours=delta)
    elif step == "m":
        td = timedelta(minutes=delta)
    else:
        raise Exception("specify correct step (h, m)")
    return datetime.now()-td
