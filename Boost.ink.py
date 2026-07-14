import base64
import requests
from bs4 import BeautifulSoup

response = requests.get("https://boost.ink/kv_eam")
soup = BeautifulSoup(response.text, "html.parser")

unlock_soupfind = soup.find("script", src="/assets/js/unlock.js?v=3.5.10")
decode = unlock_soupfind.attrs["bufpsvdhmjybvgfncqfa"]

print(base64.b64decode(decode).decode('utf-8'))
