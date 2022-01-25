#!/usr/bin/env python
# coding: utf-8

# In[ ]:


"""
Jordan Stobbs
Data collection for legitimate and phishing URLs

A script which collects various features for a URL database.

Version 1.2
"""


# In[ ]:


import requests
from html.parser import HTMLParser
from bs4 import BeautifulSoup as bs
import json
import tldextract
import pandas as pd
import sqlite3
from sqlite3 import Error
import time
from datetime import datetime
from IPython.core.debugger import Tracer
import math
import selenium
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from collections import Counter


# In[ ]:


apiKeyUrlscan   = "9d03419d-e8e4-4e63-899f-4730e36728f0"
apiKeyPhishTank = "249e1887501ddd364099aaabecdb258e1d18228af11ce4534fe2b08d4747fc2d"
apiKeyGoogleSafeBrowsing = "AIzaSyBt4G0Lo0ysc5GTnKgbLUjr29qjaurVjA0"

phishTankUrl       = "http://data.phishtank.com/data/"+apiKeyPhishTank+"/online-valid.json"
urlscanScanUrl     = "https://urlscan.io/api/v1/scan/"
urlscanRetrieveUrl = "https://urlscan.io/api/v1/result/"

databaseDir = "data.db"
URLSCAN_DOM = "https://urlscan.io/dom/"


# In[ ]:


phishTank = requests.get(phishTankUrl)
print(phishTank)


# In[ ]:


con = sqlite3.connect(databaseDir)
cur = con.cursor()
for item in phishTank.json():
    url = item["url"]
    print(url)
    cur.execute("INSERT OR IGNORE INTO Url(url)                 VALUES(?)",(url,))
con.commit()
con.close()


# In[ ]:



con = sqlite3.connect(databaseDir)
cur = con.cursor()
cur.execute("SELECT url FROM Url WHERE urlUrlscanUuid is null")
rows = cur.fetchall()
con.close()
i=0
con = sqlite3.connect(databaseDir)
cur = con.cursor()
for row in rows:
    url = row[0]
    urlscanScan = requests.post(urlscanScanUrl, headers={"API-key":apiKeyUrlscan}, data={"url":url,"public":"on"})
    try:
        urlScanId   = urlscanScan.json()["uuid"]
        cur.execute("UPDATE OR IGNORE URL                     SET urlUrlscanUuid = ?                     WHERE url = ?",(urlScanId,url))
        time.sleep(2)
        print(i)
        i+=1
        if i%10==0:
            con.commit()
    except KeyError as error:
        time.sleep(2)
        pass
    
con.commit()
con.close()


# In[ ]:


genuine = pd.read_csv("top-1m.csv", usecols=[1], header=None)
genuine.head(20000)
con = sqlite3.connect(databaseDir)
cur = con.cursor()
print(genuine)
for url in genuine[1]:
    print(url)
    cur.execute("INSERT OR REPLACE INTO Url(url)                 VALUES(?)",(url,))
con.commit()
con.close()

    
    


# In[ ]:


class UrlMin():
    def setUrl(self,url):
        self.url = url
    def setUrlAsn(self,asn):
        self.asn = asn
    def setUrlCountry(self,country):
        self.country = country
    def setUrlHash(self,hash):
        self.hash = hash
    def setUrlIp(self,ip):
        self.ip = ip
    def setUrlSize(self,size):
        self.size=size
    def setUrlStatus(self,status):
        self.status = status
    def setUrlType(self,type):
        self.type = type
    def setUrlMethod(self,method):
        self.method = method
    
    def __init__(self,url,asn,country,hash,ip,size,status,type=None, method=None):
        self.setUrl(url)
        self.setUrlAsn(asn)
        self.setUrlCountry(country)
        self.setUrlHash(hash)
        self.setUrlIp(ip)
        self.setUrlSize(size)
        self.setUrlStatus(status)
        self.setUrlType(type)
        self.setUrlMethod(method)
        
        
class Url(UrlMin):
    def setCertificate(self,certificate):
        self.certificate=certificate
    def addCookie(self,cookie):
        self.cookies.append(cookie)
    def addGlobalVar(self,globalVar):
        self.globalVars.append(globalVar)
    def addRequest(self,request):
        self.requests.append(request)
    def setUuid(self,uuid):
        self.uuid = uuid
    def setUrlId(self,urlId):
        self.urlId = urlId
    def setUrlLoadingTime(self,loadingTime):
        self.loadingTime = loadingTime
    
    def __init__(self,uuid,urlId,loadingTime,url,asn,country,hash,ip,size,status):
        UrlMin.__init__(self,url,asn,country,hash,ip,size,status)
        self.requests   = []
        self.cookies    = []
        self.globalVars = []
        self.setUuid(uuid)
        self.setUrlId(urlId)
        self.setUrlLoadingTime(loadingTime)
    


# In[ ]:


class Cookie:
    def setCookieName(self, cookieName):
        self.cookieName = cookieName
    def setCookieValue(self, cookieValue):
        self.cookieValue = cookieValue
    def setCookieDuration(self, cookieDuration):
        self.cookieDuration = cookieDuration
    
    def __init__(self, cookieName, cookieValue, cookieDuration):
        self.setCookieName(cookieName)
        self.setCookieValue(cookieValue)
        self.setCookieDuration(cookieDuration)


# In[ ]:


class Global:
    def setGlobalName(self, globalName):
        self.globalName = globalName
    def setGlobalType(self, globalType):
        self.globalType = globalType
    
    def __init__(self, globalName, globalType):
        self.setGlobalName(globalName)
        self.setGlobalType(globalType)


# In[ ]:


class Certificate:
    def setCertificateName(self, certificateName):
        self.certificateName = certificateName
    def setCertificateIssuer(self, certificateIssuer):
        self.certificateIssuer = certificateIssuer
    def setCertificateValidFrom(self,certificateValidFrom):
        self.certificateValidFrom = certificateValidFrom
    def setCertificateValidTo(self,certificateValidTo):
        self.certificateValidTo = certificateValidTo
    
    def __init__(self, certificateName, certificateIssuer, certificateValidFrom, certificateValidTo):
        self.setCertificateName(certificateName)
        self.setCertificateIssuer(certificateIssuer)
        self.setCertificateValidFrom(certificateValidFrom)
        self.setCertificateValidTo(certificateValidTo)


# In[ ]:


def dataOrganisation(urlJson, uuid, url, urlId):
#     Tracer()()
#     print(uuid)
    try:
        items = urlJson["data"]["requests"]
    except KeyError:
        return -1
    first = True
    for item in items:
        response = item["response"]
        try:
            status  = response["response"]["status"]
        except Exception as e:
            print(e)
            return -1
        ##Tracer()()
        try:
            asn     = response["asn"]["asn"]
            country = response["asn"]["country"]
            ip      = response["asn"]["ip"]
        except Exception as e:
            print(e)
            asn = 0
            country = "not found"
            ip = "0"
        try:
            hash    = response["hash"]
            size    = response["size"]
        except Exception as e:
            print(e)
            hash = "fail"
            size = -1
        if(first):
            first = False
            
            beginNav = urlJson["data"]["timing"]["beginNavigation"]
            try:
                endNav   = list(urlJson["data"]["timing"].values())[-1]
#                 print(endNav)
                beginNav = datetime.strptime(beginNav,"%Y-%m-%dT%H:%M:%S.%fZ")
                endNav   = datetime.strptime(endNav,"%Y-%m-%dT%H:%M:%S.%fZ")
            
                beginNavUnix = beginNav.timestamp()
                endNavUnix   = endNav.timestamp()
            
                loadingTime = endNavUnix - beginNavUnix
                loadingTime = int(loadingTime*100000)
            except KeyError as e:
                exit()
                loadingTime = -1
#             print(loadingTime)
            
            urlContained = Url(uuid,urlId,loadingTime,url,asn,country,hash,ip,size,status)
            #____________CERTIFICATE____________#
            securityState = response["response"]["securityState"]
            if(securityState == "secure"):
                
                securityDetails = response["response"]["securityDetails"]
    
                certificateName      = securityDetails["subjectName"]
                certificateIssuer    = securityDetails["issuer"]
                certificateValidFrom = securityDetails["validFrom"]
                certificateValidTo   = securityDetails["validTo"]
                
                certificate = Certificate(certificateName, certificateIssuer, certificateValidFrom, certificateValidTo)
                urlContained.setCertificate(certificate)
            else:
                urlContained.setCertificate(None)
            #____________CERTIFICATE____________#
            #______________GLOBALS______________#
            try:
                for globalItem in urlJson["data"]["globals"]:
                    globalVarSet = Global(globalItem["prop"],globalItem["type"])
                    urlContained.addGlobalVar(globalVarSet)
            except KeyError:
                print("No globals found for " + urlContained.url)
            #______________GLOBALS______________#
            #______________COOKIES______________#
            try:
                for cookie in urlJson["data"]["cookies"]:
                    cookieName  = cookie["name"]
                    cookieValue = cookie["value"]
                    cookieEnd   = cookie["expires"]
                    if(cookieEnd == -1):
                        cookieDuration = -1
                    elif loadingTime != -1:
                        cookieDuration = endNavUnix - cookieEnd
                    else:
                        cookieDuration = -2
                    cookieSet = Cookie(cookieName, cookieValue, cookieDuration)
                    urlContained.addCookie(cookieSet)
            except KeyError:
                print("No cookies found for " + urlContained.url)
            #______________COOKIES______________#
        else:
            requestType   = item["response"]["type"]
            requestMethod = item["request"]["request"]["method"]
            requestUrl    = item["request"]["request"]["url"]
            requestContained = UrlMin(requestUrl,asn,country,hash,ip,size,
                                      status,requestType,requestMethod)
            urlContained.addRequest(requestContained)
        try:
            return urlContained
        except UnboundLocalError as e:
             print(e)
             return -1
            
            


# In[ ]:


con = sqlite3.connect(databaseDir)
cur = con.cursor()
cur.execute("SELECT url, urlUrlscanUuid, urlId             FROM Url             WHERE urlHash is null")
rows = cur.fetchall()
for row in rows:
    start = time.time()
    time.sleep(.2)
    url = row[0]
    uuid = row[1]
    urlId = int(row[2])
    tryAgain = True
    while tryAgain:
        try:
            result = requests.get(urlscanRetrieveUrl + uuid)
            print("Request Get:" + (str(time.time()-start)))
            tryAgain = False
        except:
            print("Connection failed. Trying again...")
            time.sleep(2)
            pass
    
    urlContained = dataOrganisation(result.json(),uuid,url,urlId)
    print(urlContained)
    print("data organisation: " + (str(time.time()-start)))
    if urlContained == -1 or urlContained == None:
        cur.execute("UPDATE url SET urlHash = 'Dead' where urlId = ?",(urlId,))
        con.commit()
        continue
    
    cur.execute("UPDATE url                 SET urlAsn=?,                     urlCountry=?,                     urlHash=?,                     urlIp=?,                     urlSize=?,                     urlStatus=?,                     urlLoadingTime=?                 WHERE urlId = ?",(urlContained.asn,urlContained.country,urlContained.hash,
                                  urlContained.ip,urlContained.size, urlContained.status,
                                  urlContained.loadingTime,urlId))
    print("Initial update:"+ (str(time.time()-start)))
    if(urlContained.certificate != None):
        cur.execute("INSERT INTO Certificate(urlId, certificateName,certificateIssuer,                                             certificateValidFrom, certificateValidTo)                     VALUES(?,?,?,?,?)",(urlId,urlContained.certificate.certificateName,
                                               urlContained.certificate.certificateIssuer,
                                               urlContained.certificate.certificateValidFrom,
                                               urlContained.certificate.certificateValidTo))
    print("Certificates:"+ (str(time.time()-start)))
    for cookie in urlContained.cookies:
        cur.execute("INSERT OR IGNORE INTO Cookie(cookieName, cookieValue, cookieDuration)                     VALUES(?,?,?)",(cookie.cookieName, cookie.cookieValue, 
                                       cookie.cookieDuration))
        cur.execute("SELECT cookieId                     FROM Cookie                     WHERE cookieName = ? AND cookieValue = ? AND cookieDuration = ?",
                     (cookie.cookieName, cookie.cookieValue, 
                                       cookie.cookieDuration))
        results  = cur.fetchall()
        cookieId = results[0][0]
        cur.execute("INSERT OR IGNORE INTO UrlCookie VALUES(?,?)",(urlId,cookieId))
    print("Cookies:"+ (str(time.time()-start)))
    for request in urlContained.requests:
        cur.execute("INSERT OR IGNORE INTO Request(requestUrl, requestAsn, requestCountry, requestHash, requestIp,                                         requestMethod, requestSize, requestStatus, requestType)                     VALUES(?,?,?,?,?,?,?,?,?)",(request.url, request.asn,request.country,
                                              request.hash, request.ip, request.method, 
                                              request.size, request.status, request.type))
        cur.execute("SELECT requestId                     FROM Request                     WHERE requestUrl = ?",(request.url,))
        results   = cur.fetchall()
        requestId = results[0][0]
        cur.execute("INSERT OR IGNORE INTO UrlRequest VALUES(?,?)",(urlId, requestId))
    print("Requests:"+ (str(time.time()-start)))
#     for globalVar in urlContained.globalVars:
#         cur.execute("INSERT OR IGNORE INTO Global(globalName, globalType)\
#                      VALUES(?,?)",(globalVar.globalName, globalVar.globalType))
#         cur.execute("SELECT globalId\
#                       FROM Global\
#                       WHERE globalName = ? AND globalType = ?",(globalVar.globalName,
#                                                                 globalVar.globalType))
#         results = cur.fetchall()
#         globalId = results[0][0]
#         cur.execute("INSERT OR IGNORE INTO UrlGlobal VALUES (?,?)",(urlId,globalId))
    print("Globals:"+ (str(time.time()-start)))
    con.commit()
    print("end:"+ (str(time.time()-start)))
con.close()


# In[ ]:


# #Url fix
# con = sqlite3.connect(databaseDir)
# cur = con.cursor()
# cur.execute("SELECT url, urlUrlscanUuid, urlId\
#              FROM Url")
# rows = cur.fetchall()
# for row in rows:
#     tryAgain = True
#     while tryAgain:
#          try:
#             result = requests.get(urlscanRetrieveUrl + row[1])
#             tryAgain = False
#          except:
#             print("Connection failed. Trying again...")
#             time.sleep(2)
#     try:
#         url = result.json()["page"]["url"]
#         print(url)
#         print(row[0])
#     except KeyError:
#         pass
#     try:
#         cur.execute("UPDATE url SET url = ? WHERE url = ?",(url, row[0]))
#     except sqlite3.IntegrityError as e:
#         print(e)
# con.commit()
# con.close()


# In[ ]:


#DOM
#percent of links that lead nowhere
#percent of external links
con = sqlite3.connect(databaseDir)
cur = con.cursor()
cur.execute("SELECT url, urlUrlscanUuid, urlId             FROM url")
results = cur.fetchall()
print(results)
linkNowhere  = []
linkExternal = []
for result in results:
    tryAgain = True
    url  = result[0]
    while tryAgain:
        try:
            html = requests.get(URLSCAN_DOM + result[1] + "/").text
            tryAgain = False
        except:
            print("Connection failed. Trying again...")
            time.sleep(2)
    soup = bs(html, 'html.parser')
#     print(soup.prettify())
    aTags = soup.find_all("a", href=True)
    numberOfLinks = len(aTags)
    print(numberOfLinks)
    countNowhere = 0
    countExternalDom = 0
    for a in aTags:
        if a['href'] == "#" or a['href'] == "":
            countNowhere += 1
        else:
            brokenLink = tldextract.extract(a['href'])
            brokenUrl  = tldextract.extract(url)
            if brokenUrl.domain !=  brokenLink.domain:
                countExternalDom += 1
    if countNowhere != 0: 
        countNowhere = countNowhere/numberOfLinks
    if countExternalDom != 0: 
        countExternalDom = countExternalDom/numberOfLinks
    cur.execute("INSERT INTO DomFeatures                 VALUES (?,?,?)",(result[2],countNowhere,countExternalDom))
rows = cur.fetchall()
con.commit()
con.close()


# In[ ]:


#Only allows 10000/day
con = sqlite3.connect(databaseDir)
cur = con.cursor()
cur.execute("SELECT COUNT(url)             FROM url")
urlCount = cur.fetchall()[0][0]

for i in range(0,urlCount):
    
    cur.execute("SELECT urlId,url                 FROM url                 WHERE urlId > 29463                 ORDER BY urlId                 LIMIT 1                 OFFSET ?",(i*1,))
    results = cur.fetchall()
    urlSafebrowsingDict = {}
    urlSafebrowsingDict["client"] = {}
    urlSafebrowsingDict["threatInfo"] = {}
    urlSafebrowsingDict["client"]["clientId"] = "phishingDetection"
    urlSafebrowsingDict["client"]["clientVersion"] = "20200228"
    urlSafebrowsingDict["threatInfo"]["threatTypes"] = ["SOCIAL_ENGINEERING"]
    urlSafebrowsingDict["threatInfo"]["platformTypes"] = ["ANY_PLATFORM"]
    urlSafebrowsingDict["threatInfo"]["threatEntryTypes"]=["URL"]
    urlSafebrowsingArray = []
    for result in results:
        urlSafebrowsingArray.append({"url": result[1]})
        print(result[0])
    urlSafebrowsingDict["threatInfo"]["threatEntries"]=urlSafebrowsingArray
    requestBody = json.dumps(urlSafebrowsingDict)
    tryAgain = True
    while(tryAgain):
        try:
            googleBrowsing = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
                  + apiKeyGoogleSafeBrowsing, requestBody, headers={"Content-type":"application/json"})
            tryAgain = False
        except ConnectionError:
            time.sleep(2)
            pass
    
    jsonGoogleBrowsing = json.loads(googleBrowsing.text)
    print(jsonGoogleBrowsing)
    try:
        for match in (jsonGoogleBrowsing)["matches"]:
            print(match["threat"]["url"])
            cur.execute("UPDATE url                         SET urlGoogleSafeBrowsing = 1                         WHERE url = ?",(result[1],))
    except KeyError:
        pass
    
con.commit()
con.close()


# In[ ]:


con = sqlite3.connect(databaseDir)
cur = con.cursor()
cur.execute("SELECT url, urlUrlscanUuid, urlId             FROM url             WHERE urlGoogleFrontPage = 0")
results = cur.fetchall()
# print(results)
linkNowhere  = []
linkExternal = []
i=0
browser = webdriver.Firefox()
for result in results:
    time.sleep(2.5)
    tryAgain = True
    onFrontPage = 0
    url  = result[0]
    while tryAgain:
        try:
            html = requests.get(URLSCAN_DOM + result[1] + "/").text
            tryAgain = False
        except:
            print("Connection failed. Trying again...")
            time.sleep(2)
    soup = bs(html, 'html.parser')
    for script in soup(["script", "style"]):
        script.decompose()  
    text = soup.get_text().encode('ISO-8859-1','ignore').decode('UTF-8','ignore')
    text = text.replace("\n","")
    text = text.replace("\t","")
#     print(text)
    count = Counter(text.split(' '))
    browser.get("https://www.google.com")
    element = browser.find_element_by_name("q")
    for word in count.most_common(10):
        print(word[0])
        phrase = str(word[0]) + " "
        element.send_keys(phrase)
    time.sleep(0.2)
    element.send_keys(Keys.ENTER)
    time.sleep(1)
    tryPageAgain = 1
    print(url)
    brokenUrl  = tldextract.extract(url)
    while tryPageAgain:
        try:
            toBeSoup  = browser.page_source
            soup = bs(toBeSoup, 'html.parser')
            for siteUrl in soup.find_all("cite"):
                siteUrl = siteUrl.text
                print(siteUrl)
                if "›" in siteUrl:
                    siteUrl = siteUrl.split(" ›")[0]
                brokenComparedUrl = tldextract.extract(siteUrl)
                print(url)
                if brokenComparedUrl.domain == brokenUrl.domain:
                    onFrontPage = 1
                    print("pass")
                    break
            tryPageAgain = False
        except AttributeError:
            time.sleep(1)
            pass
        except selenium.WebDriverException:
            pass
    cur.execute("UPDATE URL                 SET urlGoogleFrontPage = ?                 WHERE urlId = ?",(onFrontPage,result[2]))
    con.commit()
    i+=1
    print(i)
con.close()
    
#     print(soup.prettify())
#get search bar
#search thing, sleep
#search for things


# In[ ]:


con.commit()
con.close()

