# PicAcg抓包分析记录

## 0x01 前言

为什么会变成这样呢……第一次有了普通地本子app，有了能普通的看本子机会。两件普通事情重合在一起。而这两份普通，又给我带来更多的快乐。得到的，本该是像梦境一般幸福的时间……但是，为什么，会变成这样呢……

## 0x02 尝试

`Fiddler`或者`Charles`都可以对安卓应用抓包

然而在进行了尝试之后发现竟然无法抓包

考虑应该是应用拦截了HTTP代理，那么通常的SSL中间人代理抓包方法都会失效...

当然最直接最暴力的方法tcpdump+wireshark分析…不过这样未免也蛋疼了...

## 0x03 反编译

首先反编译App，看到Apk包内`libs`目录下没有奇奇怪怪的`.so`就送了一口气...还好不用dump dex解固

用`jd-gui`查看反编译代码，竟然连混淆都没做，大喜，查看网络部分，采用`Retrofit2`作为网络请求库，Api很清晰，似乎很容易就能得到所有Api信息？

好像事情不简单，仔细分析`RestClient`发现每个Api都有自己的`authorization`，并且`header`还有与时间和`UUID`有关，应该需要拿出一个具体的请求包提取出所有`header`信息

可是既然不能抓包怎么提取数据包呢

## 0x03 Xposed

`Xposed`支持代码hook，理论上可以hook出一切需要的信息，所以`Xposed`应该可以完美替代掉采用`WireShark`的方案。

于是可以利用`Xposed`hook`okHttp`的`Request`，拿到请求报文头

Hook Rquest:

```java
try {
    Class clazz = lpparam.classLoader.loadClass("okhttp3.Request");
    XposedHelpers.findAndHookMethod(clazz, "toString", new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            super.beforeHookedMethod(param);
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            param.setResult(param.getResult().toString() + "\n"
                            + XposedHelpers.getObjectField(param.thisObject, "headers").toString());
        }
    });
}catch (Exception e) {
    XposedBridge.log(e);
}
```

Hook Request.Builder()

```java
try {
    Class clazz = lpparam.classLoader.loadClass("okhttp3.Request$Builder");
    XposedHelpers.findAndHookMethod(clazz, "build", new XC_MethodHook() {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            super.beforeHookedMethod(param);

        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            XposedBridge.log((param.getResult()).toString());
        }
    });

} catch (Error e) {
    Log.e(TAG, Log.getStackTraceString(e));
    XposedBridge.log(e);
}
```

运行就得到了api报头，分析里面的参数，重要的`time`,`nonce`,`signature`,`api-key`

`nonce`是一串一次性随机数，可以确定和`UUID`有关了，但是这个签名应该是不仅仅和`nonce`有关

于是继续分析源码，发现一个类`GenerateSignature`,这个类可以知道是生成签名的，签名的加密算法是利用`secret_key`做一次`HMAC_SHA256`算法得到，继续跟踪代码发现`secret_key`是来自一个native方法，这可不好反编译了，于是继续Xposed来hook得到这个key

Hook key:

```java
try {
    Class clazz = lpparam.classLoader.loadClass("com.picacomic.fregata.utils.GenerateSignature");
    XposedHelpers.findAndHookMethod(clazz, "getSignature", String.class, String.class, new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            //super.afterHookedMethod(param);
            XposedBridge.log("hook generator");
            XposedBridge.log(param.args[0] + " " + param.args[1]);
            XposedBridge.log(param.getResult().toString());
        }
    });
} catch (Error e) {
    XposedBridge.log(e);
}
```



这样就取得了所有的`header`

## 0x05 python

剩下的就是用python整理Api了

接下来就是一个非常蛋疼的事情了…因为服务器端接受的`request body`是`json`形式的，用`requests`进行debug了很久才试出来正确的`request body`...

完整代码

```python
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
    response = signin("email", "password")
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
```





