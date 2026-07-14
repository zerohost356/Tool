import requests
import secrets
import time 
import re 
url = "https://adsense.pandadevelopment.net/getkey?service=vegax&hwid=70267a42168b74b4"
def url_sprit():
    return url.split("/")[-1]
url1 = str(url_sprit())
match_hwid = re.search("hwid\s*=([a-zA-Z0-9]+)",url1)

def ja():
    return secrets.token_hex(16)

class PandaAuth:
    def __init__(self):
        pass
    def take_headers(self):
        self.headers1 = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en,vi-VN;q=0.9,vi;q=0.8,fr-FR;q=0.7,fr;q=0.6,en-US;q=0.5',
            'origin': 'https://ads.pandauth.com',
            'priority': 'u=1, i',
            'referer': 'https://ads.pandauth.com/',
            'sec-ch-ua': '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
            'x-inspector-session': str(ja()),
            }
        return self.headers1
headers = PandaAuth().take_headers()

params = {
    'hwid': str(match_hwid.group(1)),
    '_t': str(int(time.time() * 1000)),
}

sessionid_data = requests.get('https://api.pandauth.com/api/v1/public/getkey/vegax', params=params, headers=headers)
# print(response.json()["data"]["sessionId"])
#receive link 
headers = PandaAuth().take_headers()
json_data = {
    'sessionId': sessionid_data.json()["data"]["sessionId"],
    'useSecondary': True,
    'useTertiary': False,
    'customProvider': None,
}

recevei_link = requests.post(
    'https://api.pandauth.com/api/v1/public/getkey/vegax/revenue-link',
    headers=headers,
    json=json_data,
)
if recevei_link.json()["success"] == True :
    print(recevei_link.json()["data"]["link"])
