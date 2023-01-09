import json
import xmltodict


"""
{'port': '22', 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': '7.2p2 Ubuntu 4ubuntu2.7', 'product': 'OpenSSH', 'additional_details': [{'ssh-hostkey': [{'type': 'ssh-rsa', 'key': 'AAAAB3NzaC1yc2EAAAADAQABAAABAQC8m00IxH/X5gfu6Cryqi5Ti2TKUSpqgmhreJsfLL8uBJrGAKQApxZ0lq2rKplqVMs+xwlGTuHNZBVeURqvOe9MmkMUOh4ZIXZJ9KNaBoJb27fXIvsS6sgPxSUuaeoWxutGwHHCDUbtqHuMAoSE2Nwl8G+VPc2DbbtSXcpu5c14HUzktDmsnfJo/5TFiRuYR0uqH8oDl6Zy3JSnbYe/QY+AfTpr1q7BDV85b6xP97/1WUTCw54CKUTV25Yc5h615EwQOMPwox94+48JVmgE00T4ARC3l6YWibqY6a5E8BU+fksse35fFCwJhJEk6xplDkeauKklmVqeMysMWdiAQtDj', 'fingerprint': 'b3ad834149e95d168d3b0f057be2c0ae', 'bits': '2048'}, {'type': 'ecdsa-sha2-nistp256', 'key': 'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBpJvoJrIaQeGsbHE9vuz4iUyrUahyfHhN7wq9z3uce9F+Cdeme1O+vIfBkmjQJKWZ3vmezLSebtW3VRxKKH3n8=', 'fingerprint': 'f8277d642997e6f865546522f7c81d8a', 'bits': '256'}, {'type': 'ssh-ed25519', 'key': 'AAAAC3NzaC1lZDI1NTE5AAAAIGB22m99Wlybun7o/h9e6Ea/9kHMT0Dz2GqSodFqIWDi', 'fingerprint': '5a06edebb6567e4c01ddeabcbafa3379', 'bits': '256'}]}]}
"""

def parse_data(json_data):
    template = {
        "ports": [],
        "os": {
            "os": "",
            "accuracy": "0",
            "type": "",
            "family": "",
            "osgen": ""
        }
    }

    try:
        ports = json_data['nmaprun']['host']['ports']['port']
    except KeyError:
        raise SyntaxError

    try:
        os_details = json_data['nmaprun']['host']['os']['osmatch']
        temp_block = {"os": "", "accuracy": "0", "type": "", "family": "", "osgen": ""}

        for block in os_details:
            try:
                try:
                    if float(block['@accuracy']) > float(temp_block['accuracy']):
                        try:
                            temp_block['os'] = block['@name']
                        except KeyError:
                            continue

                        temp_block['accuracy'] = block['@accuracy']

                        try:
                            temp_block['type'] = block['osclass']['@type']
                        except KeyError:
                            temp_block['type'] = ""

                        try:
                            temp_block['family'] = block['osclass']['@osfamily']
                        except KeyError:
                            temp_block['family'] = ""

                        try:
                            temp_block['osgen'] = block['osclass']['@osgen']
                        except KeyError:
                            temp_block['osgen'] = ""

                except TypeError:
                    continue

            except KeyError:
                continue

        template["os"] = temp_block

    except KeyError:
        pass

    if type(ports) == list:
        # ports is a list, not a dictionary
        for port in ports:
            port_template = {"port": "", "protocol": "", "state": "", "service": "", "version": "", "product": "",
                             "additional_details": []}

            try:
                port_template['port'] = port['@portid']
            except KeyError:
                port_template['port'] = 'Not found'

            try:
                port_template['protocol'] = port['@protocol']
            except KeyError:
                port_template['protocol'] = "Not found"

            try:
                port_template['state'] = port['state']['@state']
            except KeyError:
                port_template['state'] = 'Unknown state'

            try:
                port_template['service'] = port['service']['@name']
            except KeyError:
                port_template['service'] = "Unknown Service"

            try:
                port_template['version'] = port['service']['@version']
            except KeyError:
                port_template['version'] = ''

            try:
                port_template['product'] = port['service']['@product']
            except KeyError:
                port_template['product'] = ''

            # Additional Details

            if port_template['service'] == "ssh":
                port_template['additional_details'].append({"ssh-hostkey": []})

                try:
                    for block in port['script']['table']:
                        port_template['additional_details'][0]['ssh-hostkey'].append(
                            {small_block['@key']: small_block['#text'] for small_block in block['elem']})
                except KeyError:
                    pass

                except IndexError:
                    pass

            if port_template['service'] == "http":
                try:
                    if type(port['script']) == list:
                        for block in port['script']:

                            try:
                                if block['@id'] == "http-title":
                                    port_template['additional_details'].append({"http-title": block['@output']})
                            except KeyError:
                                pass

                            try:
                                if block['@id'] == "http-server-header":
                                    port_template['additional_details'].append({"http-server-header": block['@output']})
                            except KeyError:
                                pass

                            try:
                                if block['@id'] == "http-favicon":
                                    port_template['additional_details'].append({"http-favicon": block['@output']})
                            except KeyError:
                                pass

                            try:
                                if block['@id'] == "http-methods":
                                    port_template['additional_details'].append({"http-methods": block['table']['elem']})
                            except KeyError:
                                pass

                    elif type(port['script']) == dict:

                        try:
                            if port['script']['@id'] == "http-title":
                                port_template['additional_details'].append({"http-title": port['script']['@output']})
                        except KeyError:
                            pass

                        try:
                            if port['script']['@id'] == "http-server-header":
                                port_template['additional_details'].append(
                                    {"http-server-header": port['script']['@output']})
                        except KeyError:
                            pass

                        try:
                            if port['script']['@id'] == "http-favicon":
                                port_template['additional_details'].append({"http-favicon": port['script']['@output']})
                        except KeyError:
                            pass

                        try:
                            if port['script']['@id'] == "http-methods":
                                port_template['additional_details'].append(
                                    {"http-methods": port['script']['table']['elem']})
                        except KeyError:
                            pass

                    else:
                        pass
                except KeyError:
                    print("No additional details for http")

            if port_template['service'] == "ajp13":
                try:
                    if type(port['script']) == list:
                        for block in port['script']:

                            try:
                                if block['@id'] == "ajp-request":
                                    port_template['additional_details'].append({"ajp-request": block['@output']})
                            except KeyError:
                                pass

                            try:
                                if block['@id'] == "ajp-methods":
                                    port_template['additional_details'].append({"ajp-methods": block['@output']})
                            except KeyError:
                                pass

                            try:
                                if block['@id'] == "ajp-headers":
                                    port_template['additional_details'].append({"ajp-headers": block['@output']})
                            except KeyError:
                                pass

                    elif type(port['script']) == dict:

                        try:
                            if port['script']['@id'] == "ajp-request":
                                port_template['additional_details'].append({"ajp-request": port['script']['@output']})
                        except KeyError:
                            pass

                        try:
                            if port['script']['@id'] == "ajp-methods":
                                port_template['additional_details'].append({"ajp-methods": port['script']['@output']})
                        except KeyError:
                            pass

                        try:
                            if port['script']['@id'] == "ajp-headers":
                                port_template['additional_details'].append({"ajp-headers": port['script']['@output']})
                        except KeyError:
                            pass

                    else:
                        pass
                except KeyError:
                    print("No additional details for ajp13")

            if port_template['service'] == "ftp":
                try:
                    if type(port['script']) == list:
                        for block in port['script']:
                            try:
                                if block['@id'] == "ftp-anon":
                                    if "Anonymous FTP login allowed" in block['@output']:
                                        port_template['additional_details'].append(
                                            {"ftp-anon": [block['@output'].strip().split('\n')[-1: 0: -1]]})
                                    else:
                                        port_template['additional_details'].append(
                                            {'ftp-anon': "Anonymous FTP login not allowed"})
                            except KeyError:
                                pass

                    elif type(port['script']) == dict:
                        try:
                            if port['script']['@id'] == "ftp-anon":
                                if "Anonymous FTP login allowed" in port['script']['@output']:
                                    port_template['additional_details'].append(
                                        {"ftp-anon": [port['script']['@output'].strip().split('\n')[-1: 0: -1]]})
                                else:
                                    port_template['additional_details'].append(
                                        {'ftp-anon': "Anonymous FTP login not allowed"})
                        except KeyError:
                            pass
                    else:
                        pass
                except KeyError:
                    print("No additional details for FTP")

            if port_template['service'] == "ms-wbt-server":
                try:
                    if type(port['script']) == list:
                        for block in port['script']:

                            try:
                                if block['@id'] == "rdp-ntlm-info":
                                    port_template['additional_details'].append({"rdp-ntlm-info": {
                                        dict_temp['@key']: dict_temp['#text'] for dict_temp in block['elem']}})
                            except KeyError:
                                pass

                    elif type(port['script']) == dict:
                        try:
                            if port['script']['@id'] == "rdp-ntlm-info":
                                port_template['additional_details'].append({"rdp-ntlm-info": {
                                    dict_temp['@key']: dict_temp['#text'] for dict_temp in port['script']['elem']}})
                        except KeyError:
                            pass

                    else:
                        pass
                except KeyError:
                    print("No additional details for ms-wbt-server")

            template['ports'].append(port_template)

    elif type(ports) == dict:
        port_template = {"port": "", "protocol": "", "state": "", "service": "", "version": "", "product": "",
                         "additional_details": []}
        try:
            port_template['port'] = ports['@portid']
        except KeyError:
            pass

        try:
            port_template['protocol'] = ports['@protocol']
        except KeyError:
            pass

        try:
            port_template['state'] = ports['state']['@state']
        except KeyError:
            pass

        try:
            port_template['service'] = ports['service']['@name']
        except KeyError:
            port_template['service'] = "Unknown Service"

        try:
            port_template['version'] = ports['service']['@version']
        except KeyError:
            port_template['version'] = "Version not found"

        try:
            port_template['product'] = ports['service']['@product']
        except KeyError:
            pass

        if port_template['service'] == "ssh":
            port_template['additional_details'].append({"ssh-hostkey": []})
            try:
                for block in ports['script']['table']:
                    port_template['additional_details'][0]['ssh-hostkey'].append(
                        {small_block['@key']: small_block['#text'] for small_block in block['elem']})
            except KeyError:
                pass
            except TypeError:
                try:
                    port_template['additional_details'][0]['ssh-hostkey'].append(
                        {small_block['@key']: small_block['#text'] for small_block in
                         ports['script']['table']['elem']})
                except KeyError:
                    pass

        if port_template['service'] == "http":
            port = ports
            try:
                if type(port['script']) == list:
                    for block in port['script']:
                        try:
                            if block['@id'] == "http-title":
                                port_template['additional_details'].append({"http-title": block['@output']})
                        except KeyError:
                            pass

                        try:
                            if block['@id'] == "http-server-header":
                                port_template['additional_details'].append({"http-server-header": block['@output']})
                        except KeyError:
                            pass

                        try:
                            if block['@id'] == "http-favicon":
                                port_template['additional_details'].append({"http-favicon": block['@output']})
                        except KeyError:
                            pass

                        try:
                            if block['@id'] == "http-methods":
                                port_template['additional_details'].append({"http-methods": block['table']['elem']})
                        except KeyError:
                            pass

                elif type(port['script']) == dict:

                    try:
                        if port['script']['@id'] == "http-title":
                            port_template['additional_details'].append({"http-title": port['script']['@output']})
                    except KeyError:
                        pass

                    try:
                        if port['script']['@id'] == "http-server-header":
                            port_template['additional_details'].append(
                                {"http-server-header": port['script']['@output']})
                    except KeyError:
                        pass

                    try:
                        if port['script']['@id'] == "http-favicon":
                            port_template['additional_details'].append({"http-favicon": port['script']['@output']})
                    except KeyError:
                        pass

                    try:
                        if port['script']['@id'] == "http-methods":
                            port_template['additional_details'].append(
                                {"http-methods": port['script']['table']['elem']})
                    except KeyError:
                        pass

                else:
                    pass
            except KeyError:
                print("No additional details for HTTP")

        if port_template['service'] == "ajp13":
            port = ports
            try:
                if type(port['script']) == list:
                    for block in port['script']:

                        try:
                            if block['@id'] == "ajp-request":
                                port_template['additional_details'].append({"ajp-request": block['@output']})
                        except KeyError:
                            pass

                        try:
                            if block['@id'] == "ajp-methods":
                                port_template['additional_details'].append({"ajp-methods": block['@output']})
                        except KeyError:
                            pass

                        try:
                            if block['@id'] == "ajp-headers":
                                port_template['additional_details'].append({"ajp-headers": block['@output']})
                        except KeyError:
                            pass

                elif type(port['script']) == dict:

                    try:
                        if port['script']['@id'] == "ajp-request":
                            port_template['additional_details'].append({"ajp-request": port['script']['@output']})
                    except KeyError:
                        pass

                    try:
                        if port['script']['@id'] == "ajp-methods":
                            port_template['additional_details'].append({"ajp-methods": port['script']['@output']})
                    except KeyError:
                        pass

                    try:
                        if port['script']['@id'] == "ajp-headers":
                            port_template['additional_details'].append({"ajp-headers": port['script']['@output']})
                    except KeyError:
                        pass

                else:
                    pass
            except KeyError:
                print("No additional details for AJP13")

        if port_template['service'] == "ftp":
            port = ports
            try:
                if type(port['script']) == list:
                    for block in port['script']:
                        try:
                            if block['@id'] == "ftp-anon":
                                if "Anonymous FTP login allowed" in block['@output']:
                                    port_template['additional_details'].append(
                                        {"ftp-anon": [block['@output'].strip().split('\n')[-1: 0: -1]]})
                                else:
                                    port_template['additional_details'].append(
                                        {'ftp-anon': "Anonymous FTP login not allowed"})
                        except KeyError:
                            pass
                elif type(port['script']) == dict:
                    try:
                        if port['script']['@id'] == "ftp-anon":
                            if "Anonymous FTP login allowed" in port['script']['@output']:
                                port_template['additional_details'].append(
                                    {"ftp-anon": [port['script']['@output'].strip().split('\n')[-1: 0: -1]]})
                            else:
                                port_template['additional_details'].append(
                                    {'ftp-anon': "Anonymous FTP login not allowed"})
                    except KeyError:
                        pass
                else:
                    pass
            except KeyError:
                print("No additional details for FTP")

        if port_template['service'] == "ms-wbt-server":
            port = ports
            try:
                if type(port['script']) == list:
                    for block in port['script']:

                        try:
                            if block['@id'] == "rdp-ntlm-info":
                                port_template['additional_details'].append({"rdp-ntlm-info": {
                                    dict_temp['@key']: dict_temp['#text'] for dict_temp in block['elem']}})
                        except KeyError:
                            pass
                elif type(port['script']) == dict:
                    try:
                        if port['script']['@id'] == "rdp-ntlm-info":
                            port_template['additional_details'].append({"rdp-ntlm-info": {
                                dict_temp['@key']: dict_temp['#text'] for dict_temp in port['script']['elem']}})
                    except KeyError:
                        pass
                else:
                    pass
            except KeyError:
                print("No additional details for rdp")

        template['ports'].append(port_template)
    else:
        pass

    print(json.dumps(template, indent=4))
    return template


def final_port_data():
    with open("../data/scan/nmap.xml") as xml_file:
        data_dict = xmltodict.parse(xml_file.read())
        xml_file.close()

    with open('../data/scan/port_scan.json', 'w') as f:
        f.write(json.dumps(data_dict, indent=4))
        f.close()
    print("[+] PORT SCAN PARSE SUCCESSFUL")
    return parse_data(data_dict)
