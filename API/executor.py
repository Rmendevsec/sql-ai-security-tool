# executor.py
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from typing import Iterable, Callable, Tuple

def parallel_map(func: Callable, items: Iterable, workers: int = 10, chunk: int = 1):
    """
    Run func(item) across items using ThreadPoolExecutor and return list of results.
    func should be safe to call concurrently.
    """
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(func, item): item for item in items}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                # log or ignore per design
                results.append(None)
    return results

def rate_limited_worker(func: Callable, items: Iterable, rate_per_second: float = 50, workers: int = 10):
    """
    Worker with coarse rate limiting to avoid DoS or getting blocked.
    rate_per_second: approx requests per second across all workers.
    """
    interval = 1.0 / rate_per_second if rate_per_second > 0 else 0
    def wrapper(item):
        time.sleep(interval)
        return func(item)
    return parallel_map(wrapper, items, workers=workers)
