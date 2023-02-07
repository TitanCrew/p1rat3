import requests
import json


class lookup:
    def __init__(self, api_key):
        self.api_key = api_key


    def get_stack(self, url):
        to_fetch = f"https://api.wappalyzer.com/v2/lookup/?urls={url}&live=true&recursive=false"
        headers = {"x-api-key": self.api_key}

        try:
            output = requests.get(to_fetch, headers=headers).json()
            print("[+] TECH STACK SCAN SUCCESSFUL")
        except:
            output = [{"technologies": []}]
            print("[-] ERROR IN TECH STACK SCAN")
            with open("/p1rat3/data/scan/wappalyzer.json", "w") as file:
                json.dump(output, file, indent=4, separators=(",", ": "))
            print(output)
            return

        try:
            k = output[0]
        except KeyError:
            print("[-] ERROR IN TECH STACK SCAN")
            output = [{"technologies": []}]
        with open("/p1rat3/data/scan/wappalyzer.json", "w") as file:
            json.dump(output, file, indent=4, separators=(",", ": "))
        print(output)
        return json.loads(open("/p1rat3/data/scan/wappalyzer.json", "r").read())
