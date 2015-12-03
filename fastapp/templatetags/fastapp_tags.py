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

@register.filter
def replacer(value, arg):
    args = arg.split(",")
    return value.replace(arg[0], arg[1])

from redis_metrics.utils import get_r
@register.assignment_tag
def get_slug_list(filter):
    slug_list = get_r().metric_slugs_by_category()['Uncategorized']
    slugs = []
    for slug in slug_list:
        if filter in slug:
            slugs.append(slug)
    return slugs
