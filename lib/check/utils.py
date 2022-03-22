from datetime import datetime, timezone


def get_ts_from_time_str(time_str):
    return int(datetime.strptime(time_str,  '%Y-%m-%dT%H:%M:%S').timestamp())


def get_ts_utc_now():
    dt = datetime.now(timezone.utc)
    utc_time = dt.replace(tzinfo=timezone.utc)
    return int(utc_time.timestamp())
