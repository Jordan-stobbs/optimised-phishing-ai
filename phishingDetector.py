#!/usr/bin/env python
# coding: utf-8

# In[ ]:


"""
Jordan Stobbs
Phishing AI test area

An area to test various optimised and unoptimised AI models for phishing detection

Version 1.4
"""


# In[ ]:


import sklearn
from html.parser import HTMLParser
import requests
from sklearn.model_selection import train_test_split
import sqlite3
import pandas as pd
from sklearn import svm
from sklearn.linear_model import LogisticRegression
import tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn import svm
from sklearn.model_selection import cross_val_score, KFold
from sklearn.metrics import roc_auc_score
from sklearn.feature_selection import RFE
from sklearn.preprocessing import normalize
import re
from bs4 import BeautifulSoup as bs
from sklearn.preprocessing import StandardScaler, Binarizer
from selenium import webdriver
from keras.models import Sequential, load_model
from hyperopt import hp, fmin, tpe, STATUS_OK, Trials
from tpot import TPOTClassifier
import numpy as np
from statistics import mean
import pickle

import pyswarms as pso
	
from mealpy.swarm_based.MFO import BaseMFO
#used to define how layers are created

from keras.layers import Conv2D, MaxPooling2D
#used for convolutional layer (using a 2D array)
from keras.layers.normalization import BatchNormalization
#used to smooth activation
from keras.optimizers import SGD, Adam, Adadelta, RMSprop

from keras.layers.core import Activation, Flatten, Dropout, Dense
from keras.losses import binary_crossentropy


# In[ ]:


DATABASE_DIRECTORY = "data.db"
URLSCAN_DOM = "https://urlscan.io/dom/"


# In[ ]:


#Checks if a certain tld is used
def tldAdd(tldCheck,tld):
    if(tldCheck.startswith(tld)):
        return 1
    else:
        return 0
        


# In[ ]:


#Adds a feature to the dataframe with a given name.
def addFeatureToDataframe(arrayAdd,name,df):
    assert len(df) == len(arrayAdd)
    df[name] = arrayAdd
    
    


# In[ ]:


con = sqlite3.connect(DATABASE_DIRECTORY)
cur = con.cursor()
cur.execute("SELECT url, urlClassification FROM Url")
results = cur.fetchall()
df = pd.DataFrame(data = results, columns=["url","classification"])
dashArray = []
domainLengthArray = []
underscoreArray = []
atArray = []
slashArray = []
equalsArray = []
httpArray = []
httpsArray = [] 
wwwArray = []
dotArray = []
digitArray = []
phpArray = []
htmlArray = []
cssArray = []
logArray = []
payArray = []
webArray = []
cmdArray = []
govArray = []
accountArray = []
dispatchArray = []
freeArray = []
eduArray = []
netArray = []
ruArray = []
cnArray = []
orgArray = []
jpArray = []
comBrArray = []
deArray = []
irArray = []
tvArray = []
coJpArray = []
grArray = []
plArray = []
esArray = []
infoArray = []
appArray = []
comAuArray = []
mxArray = []
comTrArray = []
# aspArray = [] Not used due to other words containing "asp" e.g. aspire
coukArray = []
ipContained = []
for result in results:
    url = result[0]
    ipInUrl = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",url)
    if(len(ipInUrl) == 0):
        ipContained.append(0)
    else:
        ipContained.append(1)
        
    if(url.startswith("http://")):
        urlNoHttpWww = url[7:]
        httpsArray.append(0)
    elif(url.startswith("https://")):
        urlNoHttpWww = url[8:]
        httpsArray.append(1)
    else:
        httpsArray.append(0)
        urlNoHttpWww = url
    if(urlNoHttpWww.startswith("www.")):
        urlNoHttpWww = urlNoHttpWww[3:]
    dashArray.append(url.count("-"))
    underscoreArray.append(url.count("_"))
    atArray.append(url.count("@"))
    slashArray.append(urlNoHttpWww.count("/"))
    equalsArray.append(url.count("="))
    if "http" in urlNoHttpWww:
        httpArray.append(True)
    else:
        httpArray.append(False)
    if "www" in urlNoHttpWww:
        wwwArray.append(True)
    else:
        wwwArray.append(False)
    brokenUrl = tldextract.extract(url)
    domain = brokenUrl.domain +"." + brokenUrl.suffix
    domainLengthArray.append(len(brokenUrl.domain))
    dotArray.append(domain.count("."))
    digitArray.append(sum(letter.isdigit() for letter in domain))
    
    if "html" in domain:
        htmlArray.append(1)
    else:
        htmlArray.append(0)
    if "css" in domain:
        cssArray.append(1)
    else:
        cssArray.append(0)
    if "php" in domain:
        phpArray.append(1)
    else:
        phpArray.append(0)
    
    if "log" in domain:
        logArray.append(1)
    else:
        logArray.append(0)
    if "pay" in domain:
        payArray.append(1)
    else:
        payArray.append(0)
    if "web" in domain:
        webArray.append(1)
    else:
        webArray.append(0)
    if "cmd" in domain:
        cmdArray.append(1)
    else:
        cmdArray.append(0)
    if "account" in domain:
        accountArray.append(1)
    else:
        accountArray.append(0)
    if "dispatch" in domain:
        dispatchArray.append(1)
    else:
        dispatchArray.append(0)  
    if "free" in domain:
        freeArray.append(1)
    else:
        freeArray.append(0)  
    
    
    tld = brokenUrl.suffix
    
    coukArray.append(tldAdd(tld,"co.uk"))
    govArray.append(tldAdd(tld,"gov"))
    eduArray.append(tldAdd(tld,"edu"))
    netArray.append(tldAdd(tld,"net"))
    ruArray.append(tldAdd(tld,"ru"))
    cnArray.append(tldAdd(tld,"cn"))
    orgArray.append(tldAdd(tld,"org"))
    jpArray.append(tldAdd(tld,"jp"))
    comBrArray.append(tldAdd(tld,"com.br"))
    deArray.append(tldAdd(tld,"de"))
    irArray.append(tldAdd(tld,"ir"))
    tvArray.append(tldAdd(tld,"tv"))
    coJpArray.append(tldAdd(tld,"co.jp"))
    grArray.append(tldAdd(tld,"gr"))
    plArray.append(tldAdd(tld,"pl"))
    esArray.append(tldAdd(tld,"es"))
    infoArray.append(tldAdd(tld,"info"))
    appArray.append(tldAdd(tld,"app"))
    comAuArray.append(tldAdd(tld,"com.au"))
    mxArray.append(tldAdd(tld,"mx"))
    comTrArray.append(tldAdd(tld,"com.tr"))



addFeatureToDataframe(dashArray,"dash",df)
addFeatureToDataframe(domainLengthArray,"domainLength",df)
addFeatureToDataframe(underscoreArray,"underscore",df)
addFeatureToDataframe(atArray,"at",df)
addFeatureToDataframe(slashArray,"slash",df)
addFeatureToDataframe(equalsArray,"equals",df)
addFeatureToDataframe(httpArray,"http",df)
addFeatureToDataframe(wwwArray,"www",df)
addFeatureToDataframe(dotArray,"dot",df)
addFeatureToDataframe(digitArray,"digit",df)
addFeatureToDataframe(coukArray,"coukTld",df)
addFeatureToDataframe(govArray,"govTld",df)
addFeatureToDataframe(eduArray,"eduTld",df)
addFeatureToDataframe(netArray,"netTld",df)
addFeatureToDataframe(ruArray,"ruTld",df)
# addFeatureToDataframe(cssArray,"containsCss",df)
# addFeatureToDataframe(phpArray,"containsPhp",df)
# addFeatureToDataframe(htmlArray,"containsHtml",df)
addFeatureToDataframe(logArray,"containsLog",df)
addFeatureToDataframe(payArray,"containsPay",df)
addFeatureToDataframe(webArray,"containsWeb",df)
addFeatureToDataframe(cmdArray,"containsCmd",df)
addFeatureToDataframe(accountArray,"containsAccount",df)
addFeatureToDataframe(dispatchArray,"containsDispatch",df)
# addFeatureToDataframe(freeArray,"containsFree",df)
addFeatureToDataframe(httpsArray,"containsHttps",df)
addFeatureToDataframe(orgArray,"orgTld",df)
addFeatureToDataframe(jpArray,"jpTld",df)
addFeatureToDataframe(comBrArray,"comBrTld",df)
addFeatureToDataframe(deArray,"deTld",df)
addFeatureToDataframe(cnArray,"cnTld",df)
addFeatureToDataframe(irArray,"irTld",df)
addFeatureToDataframe(tvArray,"tvTld",df)
addFeatureToDataframe(coJpArray,"coJpTld",df)
addFeatureToDataframe(grArray,"grTld",df)
addFeatureToDataframe(plArray,"plTld",df)
addFeatureToDataframe(esArray,"esTld",df)
addFeatureToDataframe(infoArray,"infoTld",df)
addFeatureToDataframe(appArray,"appTld",df)
addFeatureToDataframe(comAuArray,"comAuTld",df)
addFeatureToDataframe(mxArray,"mxTld",df)
addFeatureToDataframe(comTrArray,"comTrTld",df)
addFeatureToDataframe(ipContained,"ipInUrl",df)


# In[ ]:


con = sqlite3.connect(DATABASE_DIRECTORY)
cur = con.cursor()
cur.execute("SELECT url, urlIp, urlHash, urlAsn, urlCountry, certificateIssuer,             certificateValidFrom, certificateValidTo,DomNowhere, DomExternal,              urlGoogleSafeBrowsing, urlGoogleFrontPage             FROM Url LEFT JOIN certificate on url.urlId = certificate.urlId                      LEFT JOIN DomFeatures on url.urlId = DomFeatures.urlId")
results = cur.fetchall()

certificateIssuerArray = []
certificateDurationArray = []
urlIpArray = []
urlHashArray = []
urlCountryArray = []
urlAsnArray = []
urlFrontPage = []
urlSafeBrowsing = []
domExternalArray = []
domNowhereArray = []
tempUrl = "-1"
for row in results:
    url = row[0]
    if(url == tempUrl):
        continue
    else:
        tempUrl = url
    urlIp = row[1]
    urlHash = row[2]
    urlAsn = row[3]
    urlCountry = row[4]
    certificateIssuer = row[5]
    if(certificateIssuer == None or certificateIssuer == "None"):
        certificateIssuer = "None"
        certificateDuration = -1
    else:    
        certificateIssuer = row[5]
        certificateDuration = row[7]-row[6]
    domNowhere = row[8]
    domExternal = row[9]
    safeBrowsing = row[10]
    frontPage = row[11]
    urlIpArray.append(urlIp)
    urlHashArray.append(urlHash)
    urlAsnArray.append(urlAsn)
    urlCountryArray.append(urlCountry)
    certificateDurationArray.append(certificateDuration)
    certificateIssuerArray.append(certificateIssuer)
    domNowhereArray.append(domNowhere)
    domExternalArray.append(domExternal)
    urlFrontPage.append(frontPage)
    urlSafeBrowsing.append(safeBrowsing)
urlIpArray = pd.factorize(urlIpArray)[0]
urlAsnArray = pd.factorize(urlAsnArray)[0]
certificateIssuerArray = pd.factorize(certificateIssuerArray)[0]
urlCountryArray = pd.factorize(urlCountryArray)[0]

# addFeatureToDataframe(urlIpArray,"ip",df)
# addFeatureToDataframe(urlHashArray,"hash",df)
addFeatureToDataframe(domNowhereArray,"linksToNowhere",df)
addFeatureToDataframe(domExternalArray,"linksToExternal",df)
addFeatureToDataframe(urlCountryArray,"urlCountry",df)
addFeatureToDataframe(urlAsnArray,"asn",df)
addFeatureToDataframe(certificateDurationArray,"certificateDuration",df)
addFeatureToDataframe(certificateIssuerArray,"certificateIssuer",df)
addFeatureToDataframe(urlFrontPage,"googleFrontPage",df)
addFeatureToDataframe(urlSafeBrowsing,"googleSafeBrowsing",df)


# In[ ]:


con = sqlite3.connect(DATABASE_DIRECTORY)
cur = con.cursor()
cur.execute("SELECT COUNT(requestId)             FROM Url LEFT JOIN urlRequest on url.urlId = urlRequest.urlId             GROUP BY url")
resultsCountsAll = cur.fetchall()

#This command gets all dead requests and counts them for each URL, including 0s
cur.execute("SELECT url, 0             FROM URL             WHERE url not in (                 SELECT url                 FROM Url LEFT JOIN urlRequest on url.urlId = urlRequest.urlId                      LEFT JOIN request on request.requestId = urlRequest.requestId                 WHERE requestStatus like '4%' or requestStatus like '5%')             UNION             SELECT url, COUNT(request.requestId)             FROM Url LEFT JOIN urlRequest on url.urlId = urlRequest.urlId                      LEFT JOIN request on request.requestId = urlRequest.requestId             WHERE requestStatus like '4%' or requestStatus like '5%'             GROUP BY url")
resultsCountDead = cur.fetchall()

cur.execute("SELECT url.urlId, url, requestUrl, requestStatus             FROM Url LEFT JOIN urlRequest on url.urlId = urlRequest.urlId                      LEFT JOIN request on request.requestId = urlRequest.requestId             GROUP BY url.urlId")
results = cur.fetchall()

sortedResults = []
tempId = -1
tempArray = []
first = True
for result in results:
    currentId = result[0]
    if currentId != tempId and not first:
        sortedResults.append([result[1],tempArray])
        tempArray = []
    else:
        if first:
            first = False
    tempId = result[0]
    tempArray.append([result[2],result[3]])
for result in sortedResults:
    print(result)


# In[ ]:


dfPred = df
dfPred = dfPred.drop("url",1)
print(df)
con.close()


# In[ ]:


x1 = dfPred.iloc[:,1:]
dfPred = dfPred.sample(frac=1).reset_index(drop=True)
x = dfPred.iloc[:,1:]
y = dfPred.iloc[:,0]
print(x)
print(y)
X_train, X_test, y_train, y_test = train_test_split(x, y, 
                                    test_size=0.2, random_state=12421)

#CELLS UP TO HERE ARE NEEDED TO RUN, THE REST ARE FOR SPECIFIC AI ALGORITHMS/OPTIMISATION ALGORITHMS


# In[ ]:


"""
def psoObjectiveFuncGeneric(mask, alpha=0.5):
    colLen = len(x.columns)
    if np.count_nonzero(mask) == 0:
        xTest = x
    else:
        xTest = x[:,mask==1]
#INSERT CLASSIFIER HERE
"""


# In[ ]:


#ADAPTED FROM https://pyswarms.readthedocs.io/en/latest/examples/usecases/feature_subset_selection.html?highlight=feature%20subset
def psoObjectiveFuncLR(mask, alpha=0.5):
    colLen = len(x.columns)
    xConv = x.to_numpy()
    if np.count_nonzero(mask) == 0:
        x_test = xConv
    else:
        x_test = xConv[:,mask==1]
    md = LogisticRegression(random_state=4324, solver='newton-cg', multi_class='ovr', max_iter=100000)
    md.fit(x_test,y)
    performance = md.predict(x_test)
    performance = accuracy_score(y, performance)
    result = (alpha*(1.0-performance)+(1.0-alpha)*(1-(x_test.shape[1]/colLen)))
    return result

def psoObjectiveFuncSVM(mask, alpha=0.5):
    colLen = len(x.columns)
    xConv = x.to_numpy()
#     print(mask)
#     print(xConv)
    if np.count_nonzero(mask) == 0:
        x_test = xConv
    else:
        x_test = xConv[:,mask==1]
    md = svm.LinearSVC(C=1.1,penalty='l1',max_iter=10000, dual=False)
    md.fit(x_test,y)
    performance = md.predict(x_test)
    performance = accuracy_score(y, performance)
    result = (alpha*(1.0-performance)+(1.0-alpha)*(1-(x_test.shape[1]/colLen)))
    return result

def MFOObjectiveFuncLR(xPassed, alpha=0.5):
    colLen = len(x.columns)
    mask = np.reshape(xPassed,(1,-1))
    mask = np.round(mask)
    mask = mask[0]
    xConv = x.to_numpy()
#     print(xConv)
    if np.count_nonzero(mask) == 0:
        x_test = xConv
    else:
        x_test = xConv[:,mask==1]
#     print(x_test)
    md = LogisticRegression(random_state=4324, solver='newton-cg', multi_class='ovr', max_iter=100000)
    md.fit(x_test,y)
    performance = md.predict(x_test)
    performance = accuracy_score(y, performance)
    result = (alpha*(1.0-performance)+(1.0-alpha)*(1-(x_test.shape[1]/colLen)))
    return result

def MFOObjectiveFuncSVM(xPassed, alpha=0.5):
    colLen = len(x.columns)
    mask = np.reshape(xPassed,(1,-1))
    mask = np.round(mask)
    mask = mask[0]
    xConv = x.to_numpy()
#     print(xConv)
    if np.count_nonzero(mask) == 0:
        x_test = xConv
    else:
        x_test = xConv[:,mask==1]
#     print(x_test)
    md = svm.LinearSVC(C=1.1,penalty='l1',max_iter=10000, dual=False)
    md.fit(x_test,y)
    performance = md.predict(x_test)
    performance = accuracy_score(y, performance)
    result = (alpha*(1.0-performance)+(1.0-alpha)*(1-(x_test.shape[1]/colLen)))
    return result

def MFOObjectiveFuncRF(xPassed, alpha=0.5):
    colLen = len(x.columns)
    mask = np.reshape(xPassed,(1,-1))
    mask = np.round(mask)
    mask = mask[0]
    xConv = x.to_numpy()
#     print(xConv)
    if np.count_nonzero(mask) == 0:
        x_test = xConv
    else:
        x_test = xConv[:,mask==1]
#     print(x_test)
    md = RandomForestClassifier(n_estimators = 100,                            max_depth=100, max_features="log2",                            min_samples_leaf=1, min_samples_split=4, n_jobs = -1)
    md.fit(x_test,y)
    performance = md.predict(x_test)
    performance = accuracy_score(y, performance)
    result = (alpha*(1.0-performance)+(1.0-alpha)*(1-(x_test.shape[1]/colLen)))
    return result


def psoObjectiveFuncRF(mask, alpha=0.5):
#     print(mask)
    colLen = len(x.columns)
    xConv = x.to_numpy()
    if np.count_nonzero(mask) == 0:
        x_test = xConv
    else:
        x_test = xConv[:,mask==1]
    md = RandomForestClassifier(bootstrap = True, criterion='entropy', n_estimators = 100,                            max_depth=100, max_features="log2",                            min_samples_leaf=1, min_samples_split=4, n_jobs = -1)
    print(x_test)
    md.fit(x_test,y)
    performance = md.predict(x_test)
    performance = accuracy_score(y, performance)
    result = (alpha*(1.0-performance)+(1.0-alpha)*(1-(x_test.shape[1]/colLen)))
    return result


def psoObjectiveFuncNN(mask, alpha=0.5):
    colLen = x_test.shape[1]
    md = Sequential()
    md.add(Dense(colLen,input_shape=(colLen,)))
    #needs to be low enough neurons to limit overfitting, but high enough to be useful
    md.add(BatchNormalization())
    md.add(Activation('relu'))

    md.add(Dense(371))
    md.add(BatchNormalization())
    md.add(Activation('relu'))
    md.add(Dropout(0.25))

    md.add(Dense(395))
    md.add(BatchNormalization())
    md.add(Activation('relu'))
    md.add(Dropout(0.41))

    md.add(Dense(52))
    md.add(BatchNormalization())
    md.add(Activation('relu'))
    md.add(Dropout(0.31))
    md.add(Dense(1, activation='sigmoid'))
    #normalises data into a probability distribution
    md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
    md.fit(x_test,y,68,10)
    performance = md.predict(x_test)
    performance = np.round(performance)
    performance = accuracy_score(y, performance)
    result = (alpha*(1.0-performance)+(1.0-alpha)*(1-(x_test.shape[1]/colLen)))
    return result

def MFOObjectiveFuncNN(xPassed, alpha=0.5):
    mask = np.reshape(xPassed,(1,-1))
    mask = np.round(mask)
    mask = mask[0]
    xConv = x.to_numpy()
    if np.count_nonzero(mask) == 0:
        x_test = xConv
    else:
        x_test = xConv[:,mask==1]
    colLen = x_test.shape[1]
    md = Sequential()
    md.add(Dense(colLen,input_shape=(colLen,)))
    #needs to be low enough neurons to limit overfitting, but high enough to be useful
    md.add(BatchNormalization())
    md.add(Activation('relu'))

    md.add(Dense(371))
    md.add(BatchNormalization())
    md.add(Activation('relu'))
    md.add(Dropout(0.25))

    md.add(Dense(395))
    md.add(BatchNormalization())
    md.add(Activation('relu'))
    md.add(Dropout(0.41))

    md.add(Dense(52))
    md.add(BatchNormalization())
    md.add(Activation('relu'))
    md.add(Dropout(0.31))
    md.add(Dense(1, activation='sigmoid'))
    #normalises data into a probability distribution
    md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
    md.fit(x_test,y,68,10)
    performance = md.predict(x_test)
    performance = np.round(performance)
    performance = accuracy_score(y, performance)
    result = (alpha*(1.0-performance)+(1.0-alpha)*(1-(x_test.shape[1]/colLen)))
    return result


def loopPso(x,alpha=0.88):
    particleCount = x.shape[0]
# The below need to be changed to fit the model being tested, really this should
# be altered to be more robust.
    loss = [psoObjectiveFuncRF(x[i],alpha) for i in range(particleCount)]
    return np.array(loss)


# In[ ]:


#Adapted from https://github.com/thieunguyen5991/mealpy/blob/master/mealpy/swarm_based/MFO.py

md =BaseMFO(MFOObjectiveFuncSVM,47,(0,1),100, 100)
pos, fit, loss = md._train__()
print(fit)          


# In[ ]:


print(pos)    
mask = np.reshape(pos/2,(1,-1))

mask = np.round(mask)
mask = mask[0]
print(mask)


# In[ ]:


mask = np.reshape(pos,(1,-1))
mask = np.round(mask)
mask = mask[0]
xConv = x.to_numpy()
xFeatures = xConv[:,mask==1]
md = svm.LinearSVC(C=1.1,penalty='l1',max_iter=10000, dual=False)
md.fit(xFeatures,y)
prediction = md.predict(xFeatures)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


#BASE MODEL LINEAR REGRESSION accuracy:0.6789
md = LogisticRegression(random_state=4324, solver='lbfgs', multi_class='ovr', max_iter=100000)
md.fit(X_train,y_train)
prediction = md.predict(X_test)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))

prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


#TPE optimisation LINEAR REGRESSION accuracy:
#0.05% less accurate than base model
#TODO SET UP PARAMS
space = {'solver' : hp.choice("solver",['newton-cg','lbfgs','sag','saga']),
         'class_weight' : hp.choice("class_weight",[None,'balanced']),
         'C' : hp.choice("C",[0.8,0.9,1.0,1.1,1.2])
         }

def objective(space):
    md = LogisticRegression(solver=space['solver'],
                                class_weight=space['class_weight'],
                                C=space["C"],
                                n_jobs=-1)
    accuracy = cross_val_score(md,X_train,y_train, cv=10).mean()
    return{'loss': -accuracy,'status':STATUS_OK}

best = fmin(fn=objective,
            space=space,
            algo= tpe.suggest,
            max_evals = 40,
            trials = Trials())
#there's only 40 combinations of parameters so no reason to do more.

best


# In[ ]:


md = LogisticRegression(random_state=4324, solver='newton-cg', multi_class='ovr', max_iter=100000)
md.fit(X_train,y_train)
prediction = md.predict(X_test)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))

prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


#Genetic optimisation LINEAR REGRESSION accuracy:
#TODO set up params

space = {'solver' : ['newton-cg','lbfgs','sag','saga'],
         'class_weight' : [None,'balanced'],
         'C' :[0.8,0.9,1.0,1.1,1.2]
         }

md = TPOTClassifier(generations = 15, population_size=40, offspring_size=40, verbosity = 2,
                   config_dict = {'sklearn.linear_model.LogisticRegression':space},
                   cv = 10, scoring = 'accuracy', n_jobs=-1)

md.fit(X_train,y_train)
prediction = md.predict(X_test)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))

prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


options = {'c1':0.5,'c2':0.5,'w':0.5,'k':33,'p':2}
dimensions = len(x.columns)
optimiser = pso.discrete.BinaryPSO(n_particles=33, dimensions=dimensions, options=options)
cost, pos = optimiser.optimize(loopPso,iters = 30)


# In[ ]:


xConv = x.to_numpy()
xFeatures = xConv[:,pos==1]
md = LogisticRegression(random_state=4324, solver='newton-cg', multi_class='ovr', max_iter=100000)
md.fit(xFeatures,y)
prediction = md.predict(xFeatures)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


md = LogisticRegression(random_state=4324, solver='newton-cg', multi_class='ovr', max_iter=100000)
import GAFO
test = GAFO.makeGene(0.01,100,100)
test.fit(md,"classification",x,y)
print(test.results())


# In[ ]:


pos = test.results()[0]
xConv = x.to_numpy()
xFeatures = xConv[:,pos==1]
md = LogisticRegression(random_state=4324, solver='newton-cg', multi_class='ovr', max_iter=100000)
md.fit(xFeatures,y)
prediction = md.predict(xFeatures)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


md = LogisticRegression(random_state=4324, solver='newton-cg', multi_class='ovr', max_iter=100000)
pos, fit, loss = md._train__()
print(fit)          
performance = md.predict(x_test)
performance = accuracy_score(y, performance)


# In[ ]:


md =BaseMFO(MFOObjectiveFuncLR,47,(0,1),25, 25)
pos, fit, loss = md._train__()
print(fit)       


# In[ ]:


print(pos)    
mask = np.reshape(pos/2,(1,-1))

mask = np.round(mask)
mask = mask[0]
print(mask)


# In[ ]:


mask = np.reshape(pos,(1,-1))
mask = np.round(mask)
mask = mask[0]
xConv = x.to_numpy()
xFeatures = xConv[:,mask==1]
md = LogisticRegression(random_state=4324, solver='newton-cg', multi_class='ovr', max_iter=100000)
md.fit(xFeatures,y)
prediction = md.predict(xFeatures)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


#BASE MODEL SVM accuracy:

X_train = normalize(X_train)
X_test = normalize(X_test)
md = svm.LinearSVC()
md.fit(X_train,y_train)
prediction = md.predict(X_test)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))
prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


#TPE optimisation SVM accuracy:
#code adpated from https://towardsdatascience.com/hyperparameters-optimization-526348bb8e2d
X_train = normalize(X_train)
X_test = normalize(X_test)
space = {'penalty' : hp.choice("penalty",['l1','l2']),
         'class_weight' : hp.choice("class_weight",[None,'balanced']),
         'C' : hp.choice("C",[0.8,0.9,1.0,1.1,1.2])
         }

def objective(space):
    md = svm.LinearSVC(penalty=space['penalty'],
                                class_weight=space['class_weight'],
                                C=space["C"], dual=False, max_iter=10000)
    accuracy = cross_val_score(md,X_train,y_train, cv=10).mean()
    return{'loss': -accuracy,'status':STATUS_OK}

best = fmin(fn=objective,
            space=space,
            algo= tpe.suggest,
            max_evals = 20,
            trials = Trials())

best


# In[ ]:


X_train = normalize(X_train)
X_test = normalize(X_test)
md = svm.LinearSVC(C=1.1,penalty='l1',max_iter=10000, dual=False)
md.fit(X_train,y_train)
prediction = md.predict(X_test)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))
prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


#Genetic optimisation SVM accuracy:
X_train = normalize(X_train)
X_test = normalize(X_test)
space = {'penalty' : ['l1','l2'],
         'class_weight' :[None,'balanced'],
         'C' : [0.8,0.9,1.0,1.1,1.2]
         }

md = TPOTClassifier(generations = 15, population_size=100, offspring_size=100, verbosity = 2,
                   config_dict = {'sklearn.svm.LinearSVC':space},
                   cv = 10, scoring = 'accuracy', n_jobs=-1)

md.fit(X_train,y_train)
prediction = md.predict(X_test)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))

prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


options = {'c1':0.5,'c2':0.5,'w':0.9,'k':20,'p':2}
dimensions = len(x.columns)
optimiser = pso.discrete.BinaryPSO(n_particles=100, dimensions=dimensions, options=options)


cost, pos = optimiser.optimize(loopPso,iters = 100)


# In[ ]:


xConv = x.to_numpy()
xFeatures = xConv[:,pos==1]
md = svm.LinearSVC(C=1.1,penalty='l1',max_iter=10000, dual=False)
md.fit(xFeatures,y)
prediction = md.predict(xFeatures)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


md = svm.LinearSVC(C=1.1,penalty='l1',max_iter=10000, dual=False)
import GAFO
test = GAFO.makeGene(0.001,100,100)
test.fit(md,"classification",x,y)
print(test.results())


# In[ ]:


pos = test.results()[0]


# In[ ]:


xConv = x.to_numpy()
xFeatures = xConv[:,pos==1]
md = svm.LinearSVC(C=1.1,penalty='l1',max_iter=10000, dual=False)
md.fit(xFeatures,y)
prediction = md.predict(xFeatures)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


#BASE MODEL RANDOM FOREST accuracy:96.02%

md = RandomForestClassifier(n_estimators = 10000, verbose=1, n_jobs = -1)
md.fit(X_train,y_train)
prediction = md.predict(X_test)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))

prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")



# In[ ]:


#TPE optimisation RANDOM FOREST accuracy:
#code adpated from https://towardsdatascience.com/hyperparameters-optimization-526348bb8e2d
#0.05% less accurate than base model
space = {'criterion' : hp.choice("criterion",['entropy','gini']),
         'max_depth' : hp.choice("depth",[10,25,50,100,250,500,1000]),
         'min_samples_split' : hp.choice("minSamplesSplit",[2,3,4,5,6,7,8,9,10,11,12]),
         'min_samples_leaf' : hp.choice("minSamplesLeaf",[1,2,3,4,5,6,7,8,9,10]),
         'max_features' : hp.choice("maxFeat",["auto","log2",None]),
         'bootstrap':hp.choice("bootstrap",[True,False]),
         'n_estimators':hp.choice("estimators",[100,250,500])}

def objective(space):
    md = RandomForestClassifier(criterion=space['criterion'],
                                max_depth=space['max_depth'],
                                min_samples_split=space["min_samples_split"],
                                min_samples_leaf=space["min_samples_leaf"],
                                max_features=space["max_features"],
                                bootstrap=space["bootstrap"],
                                n_estimators=space["n_estimators"],
                                n_jobs=-1)
    accuracy = cross_val_score(md,X_train,y_train, cv=10).mean()
    return{'loss': -accuracy,'status':STATUS_OK}

best = fmin(fn=objective,
            space=space,
            algo= tpe.suggest,
            max_evals = 100,
            trials = Trials())

best


# In[ ]:


#Testing the optimised parameters with a larger number of estimators
md = RandomForestClassifier(bootstrap = True, criterion='entropy', n_estimators = 10000,                            max_depth=100, max_features="log2",                            min_samples_leaf=1, min_samples_split=4, verbose=1, n_jobs = -1)
md.fit(X_train,y_train)
prediction = md.predict(X_test)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))

prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


#Genetic algorithm optimisation RANDOM FOREST accuracy:
space = {'criterion' : ['entropy','gini'],
         'max_depth' :[10,25,50,100,250,500,1000],
         'min_samples_split' : [2,3,4,5,6,7,8,9,10,11,12],
         'min_samples_leaf' : [1,2,3,4,5,6,7,8,9,10],
         'max_features' : ["auto","log2",None],
         'bootstrap':[True,False],
         'n_estimators':[100]}

md = TPOTClassifier(generations = 15, population_size=15, offspring_size=15, verbosity = 2,
                   config_dict = {'sklearn.ensemble.RandomForestClassifier':space},
                   cv = 10, scoring = 'accuracy', n_jobs=-1)
# large number of changes means large number of comparisons to do

md.fit(X_train,y_train)
prediction = md.predict(X_test)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))

prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


options = {'c1':0.5,'c2':0.5,'w':0.9,'k':20,'p':2}
dimensions = len(x.columns)
optimiser = pso.discrete.BinaryPSO(n_particles=100, dimensions=dimensions, options=options)

cost, pos = optimiser.optimize(loopPso,iters = 100)


# In[ ]:


pos =np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1])
xConv = x.to_numpy()
xFeatures = xConv[:,pos==1]
md = RandomForestClassifier(bootstrap = True, criterion='entropy', n_estimators = 10000,                            max_depth=100, max_features="log2",                            min_samples_leaf=1, min_samples_split=4, n_jobs = -1)
md.fit(xFeatures,y)
prediction = md.predict(xFeatures)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction, digits=5))
print(accuracy_score(y, prediction))


# In[ ]:


df["prediction"] = prediction
df.to_csv("results.csv")
with open("detectionModel.pkl",'wb') as fileW:
    pickle.dump(md,fileW)


# In[ ]:


md = RandomForestClassifier(n_estimators = 100,                            max_depth=100, max_features="log2",                            min_samples_leaf=1, min_samples_split=4, n_jobs = -1,verbose=2)
import GAFO
test = GAFO.makeGene(0.001,100,100)
test.fit(md,"classification",x,y)
print(test.results())


# In[ ]:


xConv = x.to_numpy()
xFeatures = xConv[:,pos==1]
md = RandomForestClassifier(n_estimators = 100,                            max_depth=100, max_features="log2",                            min_samples_leaf=1, min_samples_split=4, n_jobs = -1,verbose=2)
md.fit(xFeatures,y)
prediction = md.predict(xFeatures)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


md =BaseMFO(MFOObjectiveFuncRF,47,(0,1),100, 100)
pos, fit, loss = md._train__()
print(fit)          
performance = md.predict(x_test)
performance = accuracy_score(y, performance)


# In[ ]:


print(pos)    
mask = np.reshape(pos/2,(1,-1))
mask = np.round(mask)
mask = mask[0]
print(mask)


# In[ ]:


mask = np.reshape(pos,(1,-1))
mask = np.round(mask)
mask = mask[0]
xConv = x.to_numpy()
xFeatures = xConv[:,mask==1]
md = RandomForestClassifier(n_estimators = 100,                            max_depth=100, max_features="log2",                            min_samples_leaf=1, min_samples_split=4, n_jobs = -1)
md.fit(xFeatures,y)
prediction = md.predict(xFeatures)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


#BASE MODEL NN 1 layer
colLen = len(X_train.columns)
md = Sequential()
md.add(Dense(colLen,input_shape=(colLen,)))
#needs to be low enough neurons to limit overfitting, but high enough to be useful
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dense(500))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dense(1, activation='sigmoid'))
#normalises data into a probability distribution
md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
md.fit(X_train,y_train,50,20,1,validation_data = (X_test, y_test))
prediction = md.predict(X_test)

prediction = np.round(prediction)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))

prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


#BASE MODEL NN 2 layer

colLen = len(X_train.columns)
md = Sequential()
md.add(Dense(colLen,input_shape=(colLen,)))
#needs to be low enough neurons to limit overfitting, but high enough to be useful
md.add(BatchNormalization())
md.add(Activation('relu'))

md.add(Dense(500))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.5))

md.add(Dense(500))
md.add(BatchNormalization())
md.add(Activation('relu'))

md.add(Dense(1, activation='sigmoid'))
#normalises data into a probability distribution
md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
md.fit(X_train,y_train,50,20,1,validation_data = (X_test, y_test))
prediction = md.predict(X_test)
prediction = np.round(prediction)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))
       
prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


#BASE MODEL NN 3 layer

colLen = len(X_train.columns)
md = Sequential()
md.add(Dense(colLen,input_shape=(colLen,)))
#needs to be low enough neurons to limit overfitting, but high enough to be useful
md.add(BatchNormalization())
md.add(Activation('relu'))

md.add(Dense(500))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.5))

md.add(Dense(500))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.5))

md.add(Dense(500))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dense(1, activation='sigmoid'))
#normalises data into a probability distribution
md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
md.fit(X_train,y_train,50,20,1,validation_data = (X_test, y_test))
prediction = md.predict(X_test)
prediction = np.round(prediction)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))
       
prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


#basic tree based feature optimisation
estimator = RandomForestClassifier(n_estimators = 500, verbose=1, n_jobs = -1)
selector = RFE(estimator,round(len(x.columns)*0.6)) #perhaps a parameter to be optimised
selector = selector.fit(x,y)


# In[ ]:


i = len(selector.support_)
for columnRequired in reversed(selector.support_):
    i-=1
    if(not columnRequired):
        x = x.drop(x.columns[i],axis=1)
x
    #if false delete


# In[ ]:


#TPE optimisation 3 LAYER NN accuracy:


#remove all the unselected
space = {'neurons1':hp.uniform('neurons1',32,512),
         'neurons2':hp.uniform('neurons2',32,512),
         'neurons3':hp.uniform('neurons3',32,512),
         'dropout1':hp.uniform('dropout1',0.25,0.5),
         'dropout2':hp.uniform('dropout2',0.25,0.5),
         'dropout3':hp.uniform('dropout3',0.25,0.5),
         'batchSize':hp.uniform('batchSize',20,100),
         'optimiser':hp.choice('optimser',['RMSprop','SGD','Adadelta','Adam'])
        }
colLen = len(X_train.columns)
def nn(params):
    print("test of: ", params)
    model = Sequential()
    model.add(Dense(colLen,input_shape=(colLen,)))
    #needs to be low enough neurons to limit overfitting, but high enough to be useful
    model.add(BatchNormalization())
    model.add(Activation('relu'))
    model.add(Dense(round(params['neurons1'])))
    model.add(BatchNormalization())
    model.add(Activation('relu'))
    model.add(Dropout(params['dropout1']))
    model.add(Dense(round(params['neurons2'])))
    model.add(BatchNormalization())
    model.add(Activation('relu'))
    model.add(Dropout(params['dropout2']))
    model.add(Dense(round(params['neurons3'])))
    model.add(Activation('relu'))
    model.add(Dropout(params['dropout3']))
    model.add(Dense(1, activation='sigmoid'))
    #normalises data into a probability distribution
    
    model.compile(params['optimiser'],loss=binary_crossentropy, metrics=["accuracy"])
    model.fit(X_train,y_train,round(params['batchSize']),20,0,validation_data = (X_test, y_test))
    predAcc = model.predict_proba(X_test,batch_size=128,verbose=0)
    acc = roc_auc_score(y_test,predAcc)
    import sys
    sys.stdout.flush() 
    return{'loss':-acc,'status':STATUS_OK}


# In[ ]:


trials = Trials()
best = fmin(nn, space, algo=tpe.suggest, max_evals=100, trials=trials)
print('best:', best)


# In[ ]:


colLen = len(X_train.columns)
md = Sequential()
md.add(Dense(colLen,input_shape=(colLen,)))
#needs to be low enough neurons to limit overfitting, but high enough to be useful
md.add(BatchNormalization())
md.add(Activation('relu'))

md.add(Dense(371))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.25))

md.add(Dense(395))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.41))

md.add(Dense(52))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.31))
md.add(Dense(1, activation='sigmoid'))
#normalises data into a probability distribution
md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
md.fit(X_train,y_train,68,20,1,validation_data = (X_test, y_test))
prediction = md.predict(X_test)
prediction = np.round(prediction)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))
       
prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


from deephyper.search.nas.model.space import KSearchSpace
def nn(params):
    colLen = len(X_train.columns)
    struct = KSearchSpace(colLen)
    print("test of: ", params)
    model = Sequential()
    model.add(Dense(colLen,input_shape=(colLen,)))
    #needs to be low enough neurons to limit overfitting, but high enough to be useful
    model.add(BatchNormalization())
    model.add(Activation('relu'))
    model.add(Dense(round(params['neurons1'])))
    model.add(BatchNormalization())
    model.add(Activation('relu'))
    model.add(Dropout(params['dropout1']))
    model.add(Dense(round(params['neurons2'])))
    model.add(BatchNormalization())
    model.add(Activation('relu'))
    model.add(Dropout(params['dropout2']))
    model.add(Dense(round(params['neurons3'])))
    model.add(Activation('relu'))
    model.add(Dropout(params['dropout3']))
    model.add(Dense(1, activation='sigmoid'))
    model.compile(params['optimiser'],loss=binary_crossentropy, metrics=["accuracy"])
    model.fit(X_train,y_train,round(params['batchSize']),20,0,validation_data = (X_test, y_test))
    predAcc = model.predict_proba(X_test,batch_size=128,verbose=0)
    acc = roc_auc_score(y_test,predAcc)
    import sys
    sys.stdout.flush() 
    return{'loss':-acc,'status':STATUS_OK}


# In[ ]:


#I feel there is no cross validaiton in the algorithm and so the model is simply overfitting
#As the accuracy does nto carry over to a seperate test.
space = {
    "epochs":[20],
    "batch_size":[20,30,40,50],
    "n_layers":[2,3],
    "n_neurons":[100,200,300,400],
    "dropout":[0.1,0.25,0.5],
    "optimizers":['RMSprop','SGD','Adadelta','Adam'],
    "activations":["relu"],
    "last_layer_activations":["sigmoid"],
    "losses":["binary_crossentropy"],
    "metrics":["accuracy"]
}
from neuro_evolution import evolution
search = evolution.NeuroEvolution(generations = 15, population = 100, params = space)
search.evolve(X_train,y_train,X_test,y_test)


# In[ ]:




colLen = len(X_train.columns)
md = Sequential()
md.add(Dense(colLen,input_shape=(colLen,)))
#needs to be low enough neurons to limit overfitting, but high enough to be useful
md.add(BatchNormalization())
md.add(Activation('relu'))

md.add(Dense(300))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.1))

md.add(Dense(300))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.1))

md.add(Dense(300))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.1))
md.add(Dense(1, activation='sigmoid'))
#normalises data into a probability distribution
md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
md.fit(X_train,y_train,50,20,1,validation_data = (X_test, y_test))
prediction = md.predict(X_test)
prediction = np.round(prediction)
print(confusion_matrix(y_test,prediction))
print(classification_report(y_test,prediction))
print(accuracy_score(y_test, prediction))
       
prediction = md.predict(x1)
print(df)
df["prediction"] = prediction
print(prediction)
df.to_csv("results.csv")


# In[ ]:


options = {'c1':0.5,'c2':0.5,'w':0.2,'k':15,'p':2}
dimensions = len(x.columns)
optimiser = pso.discrete.BinaryPSO(n_particles=15, dimensions=dimensions, options=options)

cost, pos = optimiser.optimize(loopPso,iters = 5)


# In[ ]:


xConv = x.to_numpy()
xFeatures = xConv[:,pos==1]
colLen = xFeatures.shape[1]
md = Sequential()
md.add(Dense(colLen,input_shape=(colLen,)))
#needs to be low enough neurons to limit overfitting, but high enough to be useful
md.add(BatchNormalization())
md.add(Activation('relu'))

md.add(Dense(371))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.25))

md.add(Dense(395))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.41))

md.add(Dense(52))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.31))
md.add(Dense(1, activation='sigmoid'))
#normalises data into a probability distribution
md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
md.fit(xFeatures,y,68,10)
prediction = md.predict(xFeatures)
prediction = np.round(prediction)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


colLen = 47
md = Sequential()
md.add(Dense(colLen,input_shape=(colLen,)))
#needs to be low enough neurons to limit overfitting, but high enough to be useful
md.add(BatchNormalization())
md.add(Activation('relu'))

md.add(Dense(371))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.25))

md.add(Dense(395))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.41))

md.add(Dense(52))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.31))
md.add(Dense(1, activation='sigmoid'))
#normalises data into a probability distribution
md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
import GAFO
test = GAFO.makeGene(0.01,15,30)
test.fit(md,"classification",x,y,False)
print(test.results())


# In[ ]:


pos = test.results()[0]
xConv = x.to_numpy()
xFeatures = xConv[:,pos==1]
md = Sequential()
md.add(Dense(27))
#needs to be low enough neurons to limit overfitting, but high enough to be useful
md.add(BatchNormalization())
md.add(Activation('relu'))

md.add(Dense(371))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.25))

md.add(Dense(395))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.41))

md.add(Dense(52))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.31))
md.add(Dense(1, activation='sigmoid'))
#normalises data into a probability distribution
md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
print(y)
y = y.to_numpy()
md.fit(xFeatures,y,68,10)
prediction = md.predict(xFeatures)
prediction = np.round(prediction)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


#it just keeps running and doesnt stop?
md =BaseMFO(MFOObjectiveFuncNN,47,(0,1),epochT=10, pop_size=15)
pos, fit, loss = md._train__()
print(fit)    


# In[ ]:


print(pos)    
mask = np.reshape(pos/2,(1,-1))
mask = np.round(mask)
mask = mask[0]
print(mask)


# In[ ]:


mask = np.reshape(pos,(1,-1))
mask = np.round(mask)
mask = mask[0]
xConv = x.to_numpy()
xFeatures = xConv[:,mask==1]
md = Sequential()
md.add(Dense(27))
#needs to be low enough neurons to limit overfitting, but high enough to be useful
md.add(BatchNormalization())
md.add(Activation('relu'))

md.add(Dense(371))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.25))

md.add(Dense(395))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.41))

md.add(Dense(52))
md.add(BatchNormalization())
md.add(Activation('relu'))
md.add(Dropout(0.31))
md.add(Dense(1, activation='sigmoid'))
#normalises data into a probability distribution
md.compile('Adam',loss=binary_crossentropy, metrics=["accuracy"])
print(y)
y = y.to_numpy()
md.fit(xFeatures,y,68,10)
prediction = md.predict(xFeatures)
prediction = np.round(prediction)
print(confusion_matrix(y,prediction))
print(classification_report(y,prediction))
print(accuracy_score(y, prediction))


# In[ ]:


con = sqlite3.connect(DATABASE_DIRECTORY)
cur = con.cursor()
cur.execute("SELECT url, urlClassification FROM Url")
results = cur.fetchall()
#urlId, url, asn, classification, country, hash, ip, loadingTime,size,status,uuid
df = pd.DataFrame(data = results, columns=["url","classification"])
tldArray = []
for result in results:
    url = result[0]
    brokenUrl = tldextract.extract(url)
    tld = brokenUrl.suffix
#     print(tld)
    tldArray.append(tld)
assert len(df) == len(tldArray)
df["tld"] = tldArray
dfBl = df[df.classification == 1]
dfWl = df[df.classification == 0]
#using the below will find the count of a specific TLD for whitelist or blacklist
#if both are commented out, the top and bottom 25 counts are shown instead.
# dfWl = dfWl[df.tld == "com.tr"]
dfBl = dfBl[df.tld == "co.kr"]
"""
I prefer the output that jupyter shows, if you wish to see both you can add
a print statement to both of these instead, otherwise it'll show only the list
thats uncommented, or the last one if both are uncommented.
"""
# dfWl.groupby('tld').nunique().sort_values('url', ascending=False)
dfBl.groupby('tld').nunique().sort_values('url',ascending=False)


# In[ ]:


importances = list(md.feature_importances_)
feature_importances = [(feature, round(importance, 2)) for feature, importance in zip(list(X_train.columns.values), importances)]# Sort the feature importances by most important first
feature_importances = sorted(feature_importances, key = lambda x: x[1], reverse = True)# Print out the feature and importances 
[print('Variable: {:20} Importance: {}'.format(*pair)) for pair in feature_importances];


# In[ ]:


from sklearn.tree import export_graphviz
import os
import pydot
estimator = md.estimators_[9]
print(list(dfPred.columns.values))
export_graphviz(estimator, 
                out_file = 'small_tree.dot', 
                feature_names = list(X_train.columns.values),
                rounded = True, precision = 1)
(graph, ) = pydot.graph_from_dot_file('small_tree.dot')
graph.write_png('small_tree.png')

(graph, ) = pydot.graph_from_dot_file('small_tree.dot')
graph.write_png('small_tree.png');
#export_graphviz(estimator, feature_names = list(X_train.columns.values),
#                 filled=True,
#                 rounded=True)
# from subprocess import call
# call(['dot', '-Tpng', 'tree.dot', '-o', 'tree.png', '-Gdpi=600'])

# # Display in jupyter notebook
# from IPython.display import Image
# Image(filename = 'tree.png')


# In[ ]:


testdf = pd.read_csv("urlset.csv")
print(testdf["label"])
testdf = testdf[["domain","label"]]
for domain in testdf:
    url = result[0]
    brokenUrl = tldextract.extract(url)
    tld = brokenUrl.suffix
#     print(tld)
    tldArray.append(tld)
assert len(df) == len(tldArray)
df["tld"] = tldArray
dfBl = df[df.classification == 1]
dfWl = df[df.classification == 0]
dfWl = dfWl[df.tld == "com.tr"]
dfWl.groupby('tld').nunique().sort_values('url', ascending=False)
brokenUrl = tldextract.extract(url)
tld = brokenUrl.suffix


# In[ ]:


CMDPSOFS

