import hashlib
import hmac
import json
import time
import uuid
import ssl
import requests
import urllib3

proxies = {"http": "http://127.0.0.1:1087", "https": "http://127.0.0.1:1087"}

secret_key = "~n}$S9$lGts=U)8zfL/R.PM9;4[3|@/CEsl~Kk!7?BYZ:BAa5zkkRBL7r|1/*Cr"
BASE_URL = "https://picaapi.picacomic.com/"

s_uuid = str(uuid.uuid4()).replace("-", "")
api_key = "C69BAF41DA5ABD1FFEDC6D2FEA56B"

sign_url = BASE_URL + "auth/sign-in"
forgot_url = BASE_URL + "auth/forgot-password"
init_url = "https://139.59.113.68/init"
categories_url = BASE_URL + "categories"
search_url = BASE_URL + "comics/search"
comicWithId_url = BASE_URL + "comics/{comicId}"
comicEps_url = BASE_URL + "comics/{comicId}/eps"
comicPages_url = BASE_URL + "comics/{comicId}/order/{order}/pages"

headers = {
    "api-key": api_key,
    "accept": "application/vnd.picacomic.com.v1+json",
    "app-channel": "3",
    "time": "0",
    "nonce": s_uuid,
    "signature": "0",
    "app-version": "2.1.0.4",
    "app-uuid": "418e56fb-60fb-352b-8fca-c6e8f0737ce6",
    "app-platform": "android",
    "Content-Type": "application/json; charset=UTF-8",
    "User-Agent": "okhttp/3.8.1",
    "app-build-version": "39"}

requests.packages.urllib3.disable_warnings()


def post(url, json):
    return requests.post(url, data=json, headers=headers, proxies=proxies, verify=False)


def get(url, data=None):
    return requests.get(url, data=data, headers=headers, proxies=proxies, verify=False)


def signature(url, ts, method):
    raw = url.replace("https://picaapi.picacomic.com/", "") + str(ts) + s_uuid + method + api_key
    raw = raw.lower()
    hc = hmac.new(secret_key.encode(), digestmod=hashlib.sha256)
    hc.update(raw.encode())
    return hc.hexdigest()


def construct(url, method):
    ts = int(time.time())
    s = signature(url, ts, method)
    headers["signature"] = s
    headers["time"] = str(ts)


def getSinglePage(filesever, path):
    return get(filesever + "/static/" + path)


def getComicPages(auth, id, order):
    nurl = comicPages_url.replace("{comicId}", id).replace("{order}", order)
    construct(nurl, "GET")
    headers["authorization"] = auth
    return get(nurl).json()

def getComicEps(auth, id):
    nurl = comicEps_url.replace("{comicId}", id)
    construct(nurl, "GET")
    headers["authorization"] = auth
    return get(nurl).json()


def getComicWithId(auth, id):
    nurl = comicWithId_url.replace("{comicId}", id)
    construct(nurl, "GET")
    headers["authorization"] = auth
    return get(nurl).json()


def search(auth, key, page):
    nurl = search_url + "?page=" + page + "&q=" + key
    construct(nurl, "GET")
    headers["authorization"] = auth
    return get(nurl).json()


def categories(auth):
    construct(categories_url, "GET")
    headers["authorization"] = auth
    return get(categories_url).json()


def signin(email, pwd):
    ts = int(time.time())
    s = signature(sign_url, ts, "POST")
    headers["signature"] = s
    headers["time"] = str(ts)
    body = {"email": email, "password": pwd}
    return post(sign_url, json.dumps(body)).json()


def init():
    ts = int(time.time())
    s = signature(init_url, ts, "GET")
    headers["signature"] = s
    headers["time"] = str(ts)
    return get(sign_url)


if __name__ == "__main__":
    response = signin("email", "pwd")
    auth = response["data"]["token"]
    # print(auth)
    # categories_response = categories(auth)["data"]
    # print(categories_response)
    # search_response = search(auth, "s", "1")
    # print(search_response)
    # comicWithId_response = getComicWithId(auth, "5821859d5f6b9a4f93dbf719")
    # print(comicWithId_response)
    # comicEps_response = getComicEps(auth, "5821859d5f6b9a4f93dbf719")
    # print(comicEps_response)
    # comicPages_response = getComicPages(auth, "5821859d5f6b9a4f93dbf719", "1")
    # print(comicPages_response)
    # img = getSinglePage("https://storage1.picacomic.com", "9e776e75-894d-4a5a-9cc0-dcb44575ed85.jpg")
    # with open('save.jpg', 'wb') as file:
    #     file.write(img.content)
    #     file.close()