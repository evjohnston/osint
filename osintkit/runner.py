"""Runs a set of independent checks concurrently and collects results."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class Skip(Exception):
    """Raise from a check to mark it skipped (e.g. missing API key)."""


def run_checks(checks, target, workers=16, on_done=None):
    """checks: dict name -> callable(target) returning JSON-able data.

    Returns dict name -> {"status": ok|empty|skipped|error, "data"|"error", "ms"}.
    on_done(name, result) fires once per source with result=None when queued,
    then again with the result when it finishes.
    """
    results = {}

    def wrap(fn):
        t0 = time.time()
        try:
            data = fn(target)
            status = "ok" if data not in (None, [], {}, "") else "empty"
            res = {"status": status, "data": data}
        except Skip as e:
            res = {"status": "skipped", "error": str(e)}
        except Exception as e:  # noqa: BLE001 — any source failure is non-fatal
            res = {"status": "error", "error": f"{type(e).__name__}: {e}"}
        res["ms"] = int((time.time() - t0) * 1000)
        return res

    if on_done:  # announce queued sources (result None) so UIs can list them up front
        for name in checks:
            on_done(name, None)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(wrap, fn): name for name, fn in checks.items()}
        for fut in as_completed(futs):
            name = futs[fut]
            results[name] = fut.result()
            if on_done:
                on_done(name, results[name])
    # keep declared order
    return {name: results[name] for name in checks}
