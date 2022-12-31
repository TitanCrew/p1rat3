import json

with open('sample.json', 'r') as f:
    json_data = json.loads(f.read())
    f.close()


def parse_data():
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

            except KeyError:
                continue

        template["os"] = temp_block

    except KeyError:
        pass

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
            port_template['version'] = 'Version Not found'

        try:
            port_template['product'] = port['service']['@product']
        except KeyError:
            port_template['product'] = 'Product Not found'

        if port_template['service'] == "ssh":
            port_template['additional_details'].append({"ssh-hostkey": []})

            try:
                for block in port['script']['table']:
                    port_template['additional_details'][0]['ssh-hostkey'].append(
                        {small_block['@key']: small_block['#text'] for small_block in block['elem']})
            except KeyError or IndexError:
                pass

        if port_template['service'] == "http":

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

        if port_template['service'] == "ajp13":

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

        if port_template['service'] == "ftp":

            for block in port['script']:

                try:
                    if block['@id'] == "ftp-anon":
                        if "Anonymous FTP login allowed" in block['@output']:
                            port_template['additional_details'].append(
                                {"ftp-anon": [block['@output'].strip().split('\n')[-1: 0: -1]]})
                        else:
                            port_template['additional_details'].append({'ftp-anon': "Anonymous FTP login not allowed"})
                except KeyError:
                    pass

        template['ports'].append(port_template)

    print(json.dumps(template, indent=4))


parse_data()
