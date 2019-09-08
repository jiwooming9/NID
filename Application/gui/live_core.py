#!/bin/python2.7
from scapy.all import *
import re
import time
import urllib
import numpy as np
import pandas as pd
from numpy import *
from sklearn.externals import joblib
import os
import sys
import threading


# load the models
classifier = joblib.load('models/traininga.pkl')

# usual kinds of request and their numbering in order
METHODS = ["GET", "POST", "PUT", "HEAD", "DELETE", "TRACE", "CONNECT", "OPTIONS"]

# store key value pair of HTTP payload
OBTAINED_PAYLOAD = {}
count = 0



def find_user_agent(load, value, n=3):
    """String UA nam o dong thu ba"""
    start = load.find(value)
    while start >= 0 and n > 1:
        start = load.find(value, start + 1)
        n -= 1
    return start


def is_http(packet_captured):
    """kiem tra http request"""
    packet_captured = str(packet_captured)
    return "HTTP" in packet_captured and any(method in packet_captured for method in METHODS)


def parse_request(s, c, n):
    """tim payload bang regex"""
    regex = r'^((?:[^%s]*%s){%d}[^%s]*)%s(.*)' % (c, c, n - 1, c, c)
    l = ()
    m = re.match(regex, s)
    if m: l = m.group(2)
    return l

def classify_live_data(load, mac_src, ip_src, add_line, lognum):
    """ham phan loai pcap"""
    global input_file
    input_file.flush()
    global STOP_EV
    global countsniff
    method = OBTAINED_PAYLOAD['Method']
    # finding User-Agent
    try:
        srt = load.index('User-Agent:')
    except ValueError:
        srt = 0
    if srt:
        finish = find_user_agent(load, "\r\n")
        # finding URL
        try:
            start = load.index(' ')
        except ValueError:
            start = 0
        if start:
            end = load.index('HTTP')
            if OBTAINED_PAYLOAD['Method'] == '0':
                try:
                    url = 'http://localhost:8080' + str(load[start+1:end])
                    url_length = len(url)
                    special_path = re.findall('[^a-zA-Z\d\s\/:\.]', url) #len
                    non_an_path = re.findall('[^a-zA-Z\d\s]', url) #len
                    digit_path = re.findall('[0-9]', url) #len
                    host = 0
                    try:
                       arg = load[start + 1:end].split('?')[1]
                       arg_num = re.findall('&', load[start + 1:end])
                    except IndexError:
                       arg = ""
                       arg_num = []
                    arg_length = len(arg)
                    digit_in_arg = re.findall('[0-9]', arg) #len
                    letter_in_arg = re.findall('[a-zA-Z]', arg) #len
                    contentLength = arg_length + len(arg_num)
                    test = np.array([[method, url_length, len(special_path), len(special_path), len(non_an_path), len(digit_path), arg_length, len(arg_num)+1, len(digit_in_arg), len(letter_in_arg), contentLength]])
                    print test
                    prediction = classifier.predict(test)
                    result = list()
                    for w in prediction:
                       result.append(w)
                    anomalous = True if 1 in result else False
                    if anomalous:
                       classed = 'anomalous'
                    else:
                       classed = 'normal'
                    print >> input_file, mac_src + "\n" + ip_src + "\n" + str(load[srt:finish])
                    print >> input_file, urllib.unquote(str(load[start + 1:end])) + "\n" + classed
                    if not STOP_EV.is_set():
                        if add_line:
                            add_line(mac_src)
                            add_line(ip_src)
                            add_line(str(load[srt+12:finish]))
                            add_line(urllib.unquote(str(load[start + 1:end])))
                            add_line(str(classed))
                            add_line("end cap")
                        if lognum:
                            countsniff = countsniff + 1
                            lognum(str(countsniff))
                except ValueError:
                    return ""

            elif OBTAINED_PAYLOAD['Method'] != '0':
                # tim den dong cuoi cua goi tin
                url = str(load[start+1:end]) + parse_request(load, '\r\n', load.count('\r\n'))
                url_length = len(url)
                special_path = re.findall('[^a-zA-Z\d\s\/:\.]', url) #len
                non_an_path = re.findall('[^a-zA-Z\d\s]', url) #len
                digit_path = re.findall('[0-9]', url) #len
                host = 0
                try:
                    arg = load[start + 1:end].split('?')[1]
                    arg_num = re.findall('&', load[start + 1:end])
                except IndexError:
                    arg = ""
                    arg_num = []
                arg_length = len(arg)
                digit_in_arg = re.findall('[0-9]', arg) #len
                letter_in_arg = re.findall('[a-zA-Z]', arg) #len
                contentLength = arg_length + len(arg_num)
                test = np.array([[method, url_length, len(special_path), len(special_path), len(non_an_path), len(digit_path), arg_length, len(arg_num)+1, len(digit_in_arg), len(letter_in_arg), contentLength]])
                prediction = classifier.predict(test)
                print test
                result = list()
                for w in prediction:
                    result.append(w)
                anomalous = True if 1 in result else False
                if anomalous:
                    classed = 'anomalous'
                else:
                    classed = 'normal'
                print >> input_file, mac_src + "\n" + ip_src + "\n" + str(load[srt:finish])
                print >> input_file, urllib.unquote(str(url)) + "\n" + classed
                if not STOP_EV.is_set():
                    if add_line:
                        add_line(mac_src)
                        add_line(ip_src)
                        add_line(str(load[srt+12:finish]))
                        add_line(urllib.unquote(str(url)))
                        add_line(str(classed))
                        add_line("end cap")
                    if lognum:
                        countsniff = countsniff + 1
                        lognum(str(countsniff))
        else:
            pass
    else:
        pass

def classify_live_nginx(load, mac_src, ip_src, add_line, lognum, count):
    """phan loai nginx"""
    global input_file
    input_file.flush()
    global STOP_EV
    # finding URL
    try:
        start=load.index(' /')
    except ValueError:
        start = 0
    if start:
        try:
            end=load.index(' HTTP/')
        except ValueError:
            end=load.index('" bytes_sent')
        # finding UA
        try:
            star=load.index('user_agent=')
        except ValueError:
            star = 0
        if star:
            endd=load.index(' request_time')
            try:
                for methodd in METHODS:
                    if methodd in load:
                        method = METHODS.index(methodd)+1
                url = load[start + 1:end]
                url_length = len(url)
                special_path = re.findall('[^a-zA-Z\d\s\/:\.]', load[start + 1:end]) #len
                non_an_path = re.findall('[^a-zA-Z\d\s]', load[start + 1:end]) #len
                digit_path = re.findall('[0-9]', load[start + 1:end]) #len
                host = 0
                lest = load.index("sent=")
                leed = load.index(" re")
                try:
                    arg = load[start + 1:end].split('?')[1]
                    arg_num = re.findall('&', load[start + 1:end])
                except IndexError:
                    arg = ""
                    arg_num = []
                arg_length = len(arg)
                digit_in_arg = re.findall('[0-9]', arg) #len
                letter_in_arg = re.findall('[a-zA-Z]', arg) #len
                contentLength = arg_length + len(arg_num)
                test = np.array([[method, url_length, len(special_path), len(special_path), len(non_an_path), len(digit_path), arg_length, len(arg_num)+1, len(digit_in_arg), len(letter_in_arg), contentLength]])
                prediction = classifier.predict(test)
                print test
                result = list()
                for w in prediction:
                     result.append(w)
                anomalous = True if 1 in result else False
                if anomalous:
                     classed = 'anomalous'
                else:
                     classed = 'normal'
                if not STOP_EV.is_set():
                    if add_line:
                        add_line("null")
                        add_line("null")
                        add_line(METHODS[method-1])
                        add_line(str(load[star+12:endd-1]))
                        add_line(str(load[start + 1:end]))
                        add_line(str(load[lest + 6:leed]))
                        add_line(classed)
                        add_line("end cap")
                    if lognum:
                        lognum(str(count))

            except ValueError:
                return ""
        else:
            pass
    else:
        pass


def classify_live_apache(load, add_line, lognum, count):
    """phan loai apache"""
    global input_file
    input_file.flush()
    global STOP_EV
    load = load.replace("127.0.1.1:80 ","")
    print load
    regex = '(.*?) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    res = re.match(regex, load)
    if res:
        try:
           for methodd in METHODS:
              if methodd in res.groups()[2].split(' ')[0]:
                method = METHODS.index(methodd)+1
           res1 = res.groups()[2].split(' ')[1]
           url = 'http://localhost:8080' + res1.split('?')[0]
           url_length = len(url)
           special_path = re.findall('[^a-zA-Z\d\s\/:\.]', url) #len
           non_an_path = re.findall('[^a-zA-Z\d\s]', url) #len
           digit_path = re.findall('[0-9]', url) #len
           host = 0
           
           try:
               arg = res1.split('?')[1]
               arg_num = re.findall('&', url)
           except IndexError:
               arg = ""
               arg_num = []
           arg_length = len(arg)
           digit_in_arg = re.findall('[0-9]', arg) #len
           letter_in_arg = re.findall('[a-zA-Z]', arg) #len
           contentLength = arg_length + len(arg_num)
           test = np.array([[method, url_length, len(special_path), len(special_path), len(non_an_path), len(digit_path), arg_length, len(arg_num)+1, len(digit_in_arg), len(letter_in_arg), contentLength]])
           prediction = classifier.predict(test)
           print test
           result = list()
           for w in prediction:
                result.append(w)
           anomalous = True if 1 in result else False
           if anomalous:
                classed = 'anomalous'
           else:
                classed = 'normal'
           if not STOP_EV.is_set():
               if (add_line or count==-1) and count!=-2:
                  add_line(res.groups()[1].split(' ')[0])
                  add_line(res.groups()[0])
                  add_line(res.groups()[2].split(' ')[0])
                  add_line(res.groups()[6])
                  add_line(res1)
                  add_line(res.groups()[3])
                  add_line(res.groups()[4])
                  add_line(classed)
                  add_line("end cap")
               if add_line and count==-2:
                  add_line(res.groups()[1].split(' ')[0])
                  add_line(res.groups()[0])
                  add_line(res.groups()[2].split(' ')[0])
                  add_line(res.groups()[6])
                  add_line(res1)
                  add_line(res.groups()[4])
                  add_line(classed)
                  add_line("end cap")
               if lognum:
                  if count!=-1 and count!=-2:
                     lognum(str(count))
        except ValueError:
             return ""
    else:
        pass


def sniff_packets(packet_captured):
    """pass the request of it valid http header"""
    global GUI
    if not STOP_EV.is_set():
       if is_http(packet_captured) and IP in packet_captured:
          ip_src = packet_captured[IP].src
          for method in METHODS:
              if method in str(packet_captured):
                  OBTAINED_PAYLOAD['Method'] = str(METHODS.index(method))
                  classify_live_data(packet_captured.load, packet_captured.src, ip_src, GUI, LABEL)
def sniff_apache():
    global TSNIFF
    global workapa
    apachef = open("/var/log/apache2/other_vhosts_access.log")
    apachef.seek(0,2)
    while True:
        if not STOP_EV.is_set():
           line = apachef.readline()
           print line
           if not line:
              time.sleep(0.1)
              continue
           classify_live_apache(line, TSNIFF, LABEL, -1)
        else:
           apachef.close()
           break
 
def sniff_nginx():
    global TSNIFF
    global workng
    nginxf = open("/var/log/nginx/access.log")
    nginxf.seek(0,2)
    while True:
        if not STOP_EV.is_set():
           line = nginxf.readline()
           print line
           if not line:
              time.sleep(0.1)
              continue
           classify_live_apache(line, TSNIFF, LABEL, -2)
        else:
           nginxf.close()
           break

def fromfile(filename):
    count =0
    f = open(filename)
    fstr = f.read()
    strpackets = fstr.split('\n')
    for packet in strpackets:
        count = count + 1
        print count
        classify_live_nginx(packet, 'null', 'null', GUI, LABEL, count)

def fromfile1(filename):
    count =0
    f = open(filename)
    fstr = f.read()
    strpackets = fstr.split('\n')
    for packet in strpackets:
        count = count + 1
        print count
        classify_live_apache(packet, GUI, LABEL, count)
def fromfile2(filename):
    count =0
    packets = rdpcap(filename)
    for packet_captured in packets:
       if is_http(packet_captured) and IP in packet_captured:
          ip_src = packet_captured[IP].src
          for method in METHODS:
              if method in str(packet_captured):
                  OBTAINED_PAYLOAD['Method'] = str(METHODS.index(method))
                  print packet_captured
                  classify_live_data(packet_captured.load, packet_captured.src, ip_src, GUI, LABEL)

GUI = None
STOP_EV = None
LABEL = None
TSNIFF = None
countsniff = 0

# luu log
moment = time.strftime("%Y-%m-%d__%H_%M_%S", time.localtime())
input_file = open('logs/log-' + moment + '.txt', 'w')

def start_sniff(thegui, thesniff, thelabel, stopev):
    global GUI
    global STOP_EV
    global LABEL
    global TSNIFF
    TSNIFF = thesniff
    STOP_EV = stopev
    GUI = thegui
    LABEL = thelabel
    # sniffer
    workapa = threading.Thread(target=sniff_apache)
    workapa.start()
    workng = threading.Thread(target=sniff_nginx)
    workng.start()
    sniff(prn=sniff_packets)
    
    

def start_nginx(thegui, thelabel, stopev, filename):
    global GUI
    global STOP_EV
    global LABEL
    STOP_EV = stopev
    GUI = thegui
    LABEL = thelabel
    fromfile(filename)
def start_apache(thegui, thelabel, stopev, filename):
    global GUI
    global STOP_EV
    global LABEL
    STOP_EV = stopev
    GUI = thegui
    LABEL = thelabel
    fromfile1(filename)
def start_pcap(thegui, thelabel, stopev, filename):
    global GUI
    global STOP_EV
    global LABEL
    STOP_EV = stopev
    GUI = thegui
    LABEL = thelabel
    fromfile2(filename)
 
if __name__ == "__main__":
     start_sniff(None, None, None, None)
