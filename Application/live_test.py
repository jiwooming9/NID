#!/bin/python2.7
from scapy.all import *
import re
import time
import urllib
from sklearn.externals import joblib
from nltk.probability import FreqDist
from nltk import classify
from nltk.classify.naivebayes import NaiveBayesClassifier

#load the models
classifier = joblib.load('models/classifier_compressed.pkl')
word_features = joblib.load('models/word_features_compressed.pkl')


def extract_features(document):
    """
        kiem tra cac tu voi tap word_features
    """
    document_words = set(document)
    features = {}
    global word_features	
    for word in word_features:
        features['contains(%s)' % word] = (word in document_words)
    return features


def find_Useragent(load,value,n=3):
    """
        tim dong giua User-agent va dong du lieu raw thu 3
    """
    start = load.find(value)
    while start >= 0 and n > 1:
        start = load.find(value, start+1)
        n -= 1
    return start

def isHttp(packet):
    #check http
    packet = str(packet)
    return "HTTP" in packet and any(i in packet for i in methods)

def nthofchar(s, c, n):
    # tim payload cua http
    regex=r'^((?:[^%s]*%s){%d}[^%s]*)%s(.*)' % (c,c,n-1,c,c)
    l = ()
    m = re.match(regex, s)
    if m: l = m.group(2)
    return l

# request HTTP 
methods= ["GET","POST","DELETE","HEAD","PUT","TRACE","CONNECT"]


dictionary = {}

#luu du lieu vao log
moment=time.strftime("%Y-%b-%d__%H_%M_%S",time.localtime())
f = open('logs/log-'+moment+'.txt', 'w')

def classify(load,mac_src,ip_src):
    try:
        srt=load.index('User-Agent:')
    except ValueError:
        srt = 0
    if srt:
        finish= find_Useragent(load,"\r\n")
        #URL
        start=load.index(' ')
        if start:
            end=load.index('HTTP')
            # tach ki tu dac biet tu payload
            p=re.compile('\+|\=|\&')
            if dictionary['Method']=='0':
                # GET co payload o tieu de
                try:
                    classed=classifier.classify(extract_features(str(p.sub(' ',load[start+1:end])).lower().split()))
                    print mac_src + "\n"+ ip_src + "\n" + str(load[srt:finish])+ "\n" + urllib.unquote(str(load[start+1:end]))+ "\n"+ classed
                    print >>f,mac_src + "\n" + ip_src + "\n" + str(load[srt:finish])
                    print >>f,urllib.unquote(str(load[start+1:end])) + "\n" + classed
                except ValueError:
                    return ""
	
            elif dictionary['Method']!='0':
                # phuong thuc khac co payload o cuoi
                reg= load[start+1:end]+nthofchar(load,'\r\n',load.count('\r\n'))
                classed=classifier.classify(extract_features(p.sub(' ',str(reg).lower()).split()))
                print mac_src + "\n" + ip_src + "\n" + str(load[srt:finish]) + "\n" + urllib.unquote(str(reg)) + "\n"+ classed 
                print >>f,mac_src + "\n" + ip_src + "\n" + str(load[srt:finish])
                print >>f,urllib.unquote(str(reg)) + "\n" + classed
	else:
            pass
	
def pfunc(packet):
    #loc HTTP request
    if isHttp(packet):
        if IP in packet:
            ip_src=packet[IP].src
            for att in methods:
                if att in str(packet):
                    dictionary['Method'] = str(methods.index(att)) 
                    classify(packet.load,packet.src,ip_src)

#sniffer
sniff(prn=pfunc)
