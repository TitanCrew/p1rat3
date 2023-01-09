import requests
import json
import os


class lookup:
    def __init__(self, api_key):
        self.api_key = api_key

    def get_stack(self, url):
        to_fetch = f"https://api.wappalyzer.com/v2/lookup/?urls={url}&live=true&recursive=false"
        headers = {"x-api-key": self.api_key}

        output = requests.get(to_fetch, headers=headers).json()

        try:
            k = output[0]
            print("[+] TECH STACK SCAN SUCCESSFUL")
        except KeyError:
            print("[+] ERROR IN TECH STACK SCAN")
            output = [{"technologies": []}]

        with open("data/scan/wappalyzer.json", "w") as file:
            json.dump(output, file, indent=4, separators=(",", ": "))

        return json.loads(open("data/scan/wappalyzer.json", "r").read())
