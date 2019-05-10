import requests
import json

try:
    with open("etag.cache", "rb") as c:
        etag = json.loads(c.read())
except FileNotFoundError:
    etag = {"hash": ""}

r = requests.get(
    "https://misp.infosec.mozilla.org/dupa", headers={"If-None-Match": etag["hash"]}
)

etag["hash"] = r.headers["ETag"]
if r.status_code == 304 and len(r.content) == 0:
    print("boo-boo")
elif r.status_code != 304 and len(r.content) != 0:
    print("new data {0}".format(r.content.decode("UTF-8")))
elif r.status_code == 304 and len(r.content) != 0:
    print("an impossible thing just happened")

with open("etag.cache", "wb") as c:
    c.write(json.dumps(etag).encode("UTF-8"))
