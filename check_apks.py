#!/usr/bin/python
# -*- coding: utf-8 -*-

from vt_api import vtapi
import os
import argparse
import hashlib

__author__= "ketian"


def parse_options():
    parser = argparse.ArgumentParser(description="Send or retrieve the apk files")
    parser.add_argument('-s', '--send', type=str, help='the action to send apks to search')
    parser.add_argument('-r', '--retrieve', type=str, help='the action to retrieve apks from dataset in virustotal' )    
    args = parser.parse_args()
    return args


def get_filepaths(directory):
    """
    this function will generate the fienames in a directory
    """ 
    file_paths = []
    #walk tree  
    for root,directories,files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root,filename)
            file_paths.append(filepath)
    
    return file_paths 


def calculate(filename,vt,option):    
    f = open(filename, "rb")
    try:
        f_name = filename.split('/')[-1]     
        print (f_name)
    except:
        pass  
    fhash = hashlib.sha256()
    fhash.update(str(f.read()))
    value = fhash.hexdigest()
    
    flag = 2
    files = {"file":f}    
    # (value)  the sha256 value 
    
    flag = vt.do_it(files, value, option=option)
    #print (str(flag) + "\n")
    f.close()
    
    return flag

def write_report(mal_list,ben_list,no_resp_list):
    assert isinstance(mal_list,list)
    assert isinstance(ben_list,list)
    assert isinstance(no_resp_list,list)
    f = open('report.txt', "wb") 
    f.write('malicious # %s \n' % str(len(mal_list)))
    f.write('benign # %s \n' % str(len(ben_list)))
    f.write('no response # %s \n' %str(len(no_resp_list)))
    for i in mal_list:
        f.write('malicious apk: %s \n' %str(i))
    
    for i in ben_list:
        f.write('benign apk: %s \n' %str(i))
    
    for i in no_resp_list:
        f.write('no response apk: %s \n' %str(i))   
 
    f.close()

def main():
    apk_str = 'apk'
    vt = None
    option = None
    vt = vtapi()
    args = parse_options()
    mal_list =[]
    ben_list =[]
    no_resp_list =[]

    if args.send:
       print (args.send)
       option = 's'
       _dir = args.send 
    if args.retrieve:
       print (args.retrieve)
       option = 'r'
       _dir = args.retrieve

    files = get_filepaths(_dir)
    files = sorted(files, key=str.lower)

    i = 0
    for f in files:
        if not f.endswith(apk_str):
           continue   
        flag = calculate(f,vt,option)
        i = i+1  
        if option == 'r':
           if flag==1:
              mal_list.append(f)
           elif flag==0:
              ben_list.append(f)
           elif flag==2:
              no_resp_list.append(f)
    
    print ("total analyzed apks: {}".format(i)) 
    if option == 'r':
       write_report(mal_list,ben_list,no_resp_list)
       print ("report finished in report.txt")  
        
if __name__ == "__main__":
   exit(main())
