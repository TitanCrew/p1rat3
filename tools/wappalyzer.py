import requests
import json
import os


class lookup:
    def __init__(self, api_key):
        self.api_key = api_key

    def get_stack(self, url):
        to_fetch = f"https://api.wappalyzer.com/v2/lookup/?urls={url}&live=true&recursive=false"
        headers = {"x-api-key": self.api_key}

        with open("data/scan/wappalyzer.json", "w") as file:
            json.dump(requests.get(to_fetch, headers = headers).json(), file, indent = 4, separators=(",", ": "))

        return json.loads(open("data/scan/wappalyzer.json", "r").read())
