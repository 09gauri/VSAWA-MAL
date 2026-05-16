import os
import time
import requests

ZAP_BASE = os.environ.get("ZAP_BASEURL", "http://zap:8080")

_session = requests.Session()


def _get(path, params=None, timeout=30, retries=2):
    last_err = None
    url = f"{ZAP_BASE}{path}"
    for _ in range(retries + 1):
        try:
            r = _session.get(url, params=params, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            last_err = e
            time.sleep(1)
    raise last_err


def zap_version():
    j = _get("/JSON/core/view/version/")
    return j.get("version")


def access_url(url: str):
    _get("/JSON/core/action/accessUrl/", params={"url": url})


def spider_scan(url: str) -> str:
    j = _get("/JSON/spider/action/scan/", params={"url": url})
    sid = str(j.get("scan", "")).strip()
    if not sid or sid == "0":
        raise RuntimeError(f"ZAP spider did not start (scanId={sid})")
    return sid


def spider_status(scan_id: str) -> int:
    j = _get("/JSON/spider/view/status/", params={"scanId": scan_id})
    return int(j.get("status", 0))


def ascan_scan(url: str) -> str:
    j = _get("/JSON/ascan/action/scan/", params={"url": url})
    aid = str(j.get("scan", "")).strip()
    if not aid or aid == "0":
        raise RuntimeError(f"ZAP active scan did not start (scanId={aid})")
    return aid


def ascan_status(scan_id: str) -> int:
    j = _get("/JSON/ascan/view/status/", params={"scanId": scan_id})
    return int(j.get("status", 0))


def fetch_alerts(baseurl: str, start=0, count=5000):
    j = _get(
        "/JSON/core/view/alerts/",
        params={"baseurl": baseurl, "start": start, "count": count},
    )
    return j.get("alerts", [])


def run_full_scan(url: str):
    access_url(url)
    sid = spider_scan(url)
    while spider_status(sid) < 100:
        time.sleep(2)

    aid = ascan_scan(url)
    while ascan_status(aid) < 100:
        time.sleep(2)

    alerts = fetch_alerts(url)
    return sid, aid, alerts
