#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import json
import time 


class vtapi():
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.api = "79cfe4a9acf92f308311b7d877ed4b27f286c493c955d701f51094dfb7e54dbd"
        #replace by your publick api key
        self.baseurl = "https://www.virustotal.com/vtapi/v2/"

    def do_it(self, files, value, option):
        
        if option=="S" or option=="s": #send
           try:
             results = self.send_results(files)
             flag = self.scan_and_print_send_results( results)
           except:
             return 2
        elif option=="R" or option == "r": #retrieve
           try: 
             results = self.retrieve_results(value)
             flag = self.scan_and_print_retrieve_results(results)
           except:
             return 2
        else:
             raw_input("Wrong Option! Enter to exit")  
             exit()  

        return flag 
 
    #Print results from a file
    def scan_and_print_retrieve_results(self, results):
        
        flag =0
        if results['response_code'] == 0:
            print "No response got, try again later"
            flag =2
        else:
            for i in results['scans']:
                if (str(results['scans'][i]['detected']) == "False"):
                    pass  
                else:
                    print ("Malware detected by %s as %s" % ( str(i), str(results['scans'][i]['result'])) )
                    flag = 1
         
        return flag

    def scan_and_print_send_results(self, results):
        
        flag = 0
        if results['response_code'] == 0:
            print "No response got, try again later"
        else:
            print ("the permanentlink is ")
            print (results['permalink'])
        #print (results) 
        return flag

    #retrieve 
    def retrieve_results(self, value):

        url = self.baseurl + "file/report"
        para = {"apikey": self.api, "resource": value}
        response = requests.post(url, data=para)
        #print (response)
        time.sleep(15)    
        json_data = json.loads(response.text)
        return (json_data)


    #Function to get results of a scanned file/url
    def send_results(self, files):
        
        url = self.baseurl + "file/scan" 
        attr = {"apikey": self.api}
        response = requests.post(url, data=attr, files=files )       
        time.sleep(15)    
        json_data = json.loads(response.text)
        return (json_data)

    
