import threading
import time

_start_time = time.time()
_total_uploads = 0
_total_downloads = 0
_counter_lock = threading.Lock()


def record_upload():
    global _total_uploads
    with _counter_lock:
        _total_uploads += 1


def record_download():
    global _total_downloads
    with _counter_lock:
        _total_downloads += 1


def get_counters():
    with _counter_lock:
        return _start_time, _total_uploads, _total_downloads
