import subprocess
import json
import xml.etree.ElementTree as ET


def parse(json_string):
    data = json.loads(json_string)
    final_command = 'sudo nmap -oX data/scan/nmap/initial.xml -Pn'

    # TCP SYN scan
    if data['sS'] == '1':
        final_command += " -sS"

    # UDP scan
    if data['sU'] == '1':
        final_command += " -sU"

    # Probe open ports to determine service/version info
    if data['sV'] == '1':
        final_command += " -sV"

    # OS Detection
    if data['O'] == '1':
        final_command += " -O"

    final_command += f" {data['target']}"
    return final_command


def run_command(command):
    subprocess.run(command, shell=True, stdout=subprocess.DEVNULL)


def parse_output():
    return_json = [[]]
    tree = ET.parse('data/scan/nmap/initial.xml')
    root = tree.getroot()
    ports = root.findall('./host/ports/port')
    os_details = root.findall('./host/os/osmatch')

    for port in ports:
        temp_block = {"port": "", "protocol": "", "state": "", "service": "", "version": "", "product": ""}
        service_attrib = port.find('service').attrib

        try:
            temp_block['service'] = service_attrib['name']
        except Exception as e:
            print(e)

        try:
            temp_block['version'] = service_attrib['version']
        except Exception as e:
            print(e)

        try:
            temp_block['port'] = port.attrib['portid']
        except Exception as e:
            print(e)

        try:
            temp_block['protocol'] = port.attrib['protocol']
        except Exception as e:
            print(e)

        try:
            temp_block['state'] = port.find('state').attrib['state']
        except Exception as e:
            print(e)

        try:
            temp_block['product'] = service_attrib['product']
        except Exception as e:
            print(e)

        return_json[0].append(temp_block)

    # OS Details
    temp_block = {"os": "", "accuracy": "0", "type": "", "family": "", "osgen": ""}

    for os in os_details:
        os_class = os.find('osclass').attrib
        flag = 0

        try:
            if float(os.attrib['accuracy']) > float(temp_block['accuracy']):
                flag = 1
        except Exception as e:
            print(e)

        if flag == 1:
            try:
                temp_block['os'] = os.attrib['name']
            except Exception as e:
                print(e)

            try:
                temp_block['accuracy'] = os.attrib['accuracy']
            except Exception as e:
                print(e)

            try:
                temp_block['type'] = os_class['type']
            except Exception as e:
                print(e)

            try:
                temp_block['family'] = os_class['osfamily']
            except Exception as e:
                print(e)

            try:
                temp_block['osgen'] = os_class['osgen']
            except Exception as e:
                print(e)

    return_json.append(temp_block)

    return return_json


run_command(parse("""{
"sS": "0",
"sU": "0",
"sV": "1",
"O": "1",
"target": "localhost"
}
"""))

print(parse_output())
