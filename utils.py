import datetime


def parse_date_time(dt):
    return datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S%z")


def parse_label(label):
    new_label = label.replace("-", " ")
    return new_label.title()
