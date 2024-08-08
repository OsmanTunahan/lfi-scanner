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
    

class OutputHandler:
    def write_output(self, lines):
        raise NotImplementedError("Subclasses should implement this!")

class FileOutputHandler(OutputHandler):
    def __init__(self, output_file):
        self.output_file = output_file

    def write_output(self, lines):
        with open(self.output_file, 'a') as out_file:
            for line in lines:
                out_file.write(line + "\n")

class ConsoleOutputHandler(OutputHandler):
    def write_output(self, lines):
        for line in lines:
            print(line)
