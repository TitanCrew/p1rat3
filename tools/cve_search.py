import json
import subprocess


def list_vuln():

    file = open('data/scan/wappalyzer.json', 'r').read()
    json_data = json.loads(file)
    final = [{"url": json_data[0]['url'], "technologies": []}]

    try:
        template = json_data[0]['technologies']
    except KeyError:
        raise KeyError

    for block in template:
        block['vulnerable'] = 'no'
        if len(block['versions']) != 0 and len(block['name']) != 0:
            command = f"searchsploit -t -s --json {block['name']} {block['versions'][0]}"

            output = subprocess.run(command, shell=True, capture_output=True)

            if len(json.loads(output.stdout)["RESULTS_EXPLOIT"]) != 0:
                block['vulnerable'] = True
            else:
                block['vulnerable'] = False

        final[0]['technologies'].append(block)

    file = open('data/scan/wappalyzer.json', 'w').write(json.dumps(final))
