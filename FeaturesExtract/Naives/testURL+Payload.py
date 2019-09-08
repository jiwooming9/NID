
#!/bin/python2.7
from scapy.all import *
import re
import urllib

#file to store words
f = open('normalCombinedWordng.txt', 'w')


def checkForMethod(load):
    """
    check data if data is in packet body or title
    return 0 if in body i.e. it is not a standard  packet
    """
    regex=re.compile(r'^GET|^POST|^HEAD|^PUT|^TRACE|^CONNECT',re.M)
    m=regex.search(load)
    if m:
        return 1
    else:
        return 0

def checkForGet(load):
    # Check if its a valid GET request
    regex=re.compile(r'GET',re.M)
    if (regex.search(load)):
        return 1
    return 0


def filter(load):
    p=re.compile('\+|\&|\=|\%3C|\%3E')
    regex = '([(\d\.)]+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    res = re.match(regex, load)
    if res:
        res1 = res.groups()[2].split(' ')[1]
        #print urllib.unquote(str(p.sub(' ', res1)).lower()).split()  #tach chuoi so sanh
        #print urllib.unquote(res1) 
   
def fromfile(filename):
    f = open(filename)
    fstr = f.read()
    strpackets = fstr.split('\n')
    for packet in strpackets:
        filter(packet)

fromfile("access.log.1")
