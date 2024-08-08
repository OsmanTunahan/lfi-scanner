from multiprocessing import Pool
import requests
import argparse
import signal
import re

class HTTPClient:
    def __init__(self, headers=None, proxies=None):
        self.headers = headers or {"Connection": "close"}
        self.proxies = proxies or {}
        requests.packages.urllib3.disable_warnings()

    def get(self, url):
        return requests.get(url, headers=self.headers, proxies=self.proxies, allow_redirects=False, verify=False)