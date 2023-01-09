import requests
from bs4 import BeautifulSoup
import re
import openpyxl


def get_file_data(target):

    try:
        session = requests.session()
        req = session.get("https://dnsdumpster.com")
        soup = BeautifulSoup(req.content, "html.parser")

        # pattern = 'csrfmiddlewaretoken'
        texts = soup.find_all('input', attrs={'name': "csrfmiddlewaretoken"})[0]

        try:
            token = str(texts).split('value="', 1)[1].rsplit('"', 1)[0]
        except IndexError:
            raise SyntaxError

        post_request_for_link = session.post("https://dnsdumpster.com",
                         data={
                             "csrfmiddlewaretoken": token,
                             "targetip": target,
                             "user": "free"
                         },
                         headers={
                             "Referer": "https://dnsdumpster.com/"
                         })

        soup = BeautifulSoup(post_request_for_link.content, "html.parser")

        try:
            link_location = str(soup.find_all('a', attrs={'href': re.compile("^/static/xls/")})[0])
        except IndexError:
            raise SyntaxError

        xl_link = re.search("/static/xls/[a-zA-Z0-9.-]*", link_location)
        link = "https://dnsdumpster.com" + link_location[xl_link.start():xl_link.end()]

        file = session.get(link, headers={"Referer": "https://dnsdumpster.com/"}).content

        with open('/p1rat3/data/scan/dns_dumpster/dns_data.xlsx', 'wb') as f:
            f.write(file)
            f.close()

        return

    except Exception:
        raise FileExistsError


def parse_excel_data():
    path = '/p1rat3/data/scan/dns_dumpster/dns_data.xlsx'
    workbook = openpyxl.load_workbook(path)
    sheet = workbook.active

    template = {"sub_domains": [], "mails": []}

    for row in sheet.iter_rows():

        if row[2].value == "A":
            template['sub_domains'].append({"host_name": row[0].value, "ip": row[1].value, "country": row[5].value})

        elif row[2].value == "MX":
            template['mails'].append({"host_name": row[0].value, "ip": row[1].value, "provider": row[4].value})

    return template


def get_dns_data(target):
    get_file_data(target)
    return parse_excel_data()
