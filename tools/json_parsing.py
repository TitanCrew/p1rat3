import xmltodict


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

    try:
        if type(ports) == list:
            try:      # ports is a list, not a dictionary
                for port in ports:
                    port_template = {"port": "", "protocol": "", "state": "", "service": "", "version": "", "product": "", "additional_details": []}

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
                                    port_template['additional_details'].append({"http-server-header": port['script']['@output']})
                            except KeyError:
                                pass

                            try:
                                if port['script']['@id'] == "http-favicon":
                                    port_template['additional_details'].append({"http-favicon": port['script']['@output']})
                            except KeyError:
                                pass

                            try:
                                if port['script']['@id'] == "http-methods":
                                    port_template['additional_details'].append({"http-methods": port['script']['table']['elem']})
                            except KeyError:
                                pass

                        else:
                            pass

                    if port_template['service'] == "ajp13":

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

                    if port_template['service'] == "ftp":
                        if type(port['script']) == list:
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

                    if port_template['service'] == "ms-wbt-server":
                        if type(port['script']) == list:
                            for block in port['script']:

                                try:
                                    if block['@id'] == "rdp-ntlm-info":
                                        port_template['additional_details'].append({"rdp-ntlm-info": {dict_temp['@key']: dict_temp['#text'] for dict_temp in block['elem']}})
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

                    template['ports'].append(port_template)
            except KeyError:
                pass

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

            try:
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
                                {small_block['@key']: small_block['#text'] for small_block in ports['script']['table']['elem']})
                        except KeyError:
                            pass

                if port_template['service'] == "http":
                    port = ports
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

                if port_template['service'] == "ajp13":
                    port = ports
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

                if port_template['service'] == "ftp":
                    port = ports
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

                if port_template['service'] == "ms-wbt-server":
                    port = ports
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
                pass

            except TypeError:
                pass

            template['ports'].append(port_template)
        else:
            pass

    except KeyError:
        pass

    return template


def final_port_data():
    with open("data/scan/nmap/initial.xml") as xml_file:
        data_dict = xmltodict.parse(xml_file.read())
        xml_file.close()

    return parse_data(data_dict)