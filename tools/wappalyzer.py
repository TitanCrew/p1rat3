import requests
import json
import os


class lookup:
    def __init__(self, api_key):
        self.api_key = api_key

    def get_stack(self, url):
        to_fetch = f"https://api.wappalyzer.com/v2/lookup/?urls={url}&live=true&recursive=false"
        headers = {"x-api-key": self.api_key}

        try:
            output = requests.get(to_fetch, headers=headers).json()
        except:
            output = [{"url": "", "technologies": []}]
            with open("/p1rat3/data/scan/wappalyzer.json", "w") as file:
                json.dump(output, file, indent=4, separators=(",", ": "))
            return

        try:
            k = output[0]
            print("[+] TECH STACK SCAN SUCCESSFUL")
        except KeyError:
            print("[+] ERROR IN TECH STACK SCAN")
            output = [{"technologies": []}]
        print(output)
        with open("/p1rat3/data/scan/wappalyzer.json", "w") as file:
            json.dump(output, file, indent=4, separators=(",", ": "))

        return json.loads(open("/p1rat3/data/scan/wappalyzer.json", "r").read())
