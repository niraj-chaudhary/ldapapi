import time
import datetime


def get_formatted_time():
    formatted_time = '%d %b, %Y %Hh%Mm%Ss'
    unix_time = time.time()
    timestamp = datetime.datetime.fromtimestamp(unix_time)
    return timestamp.strftime(formatted_time)
