import time


def wait_for_stop(proc, timeout: int = 10):
    start_time = time.time()
    while True:
        if proc.poll() is not None:
            return
        else:
            current_time = time.time()
            if current_time - start_time > timeout:
                proc.terminate()
                return
