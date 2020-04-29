import requests
import urllib3 #to supress the warning
from sql_execute import *
from basic_operation import *

#Suppress all the request ssl error
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Make the request and store the response with timeout 10s
def header_scan_parser(hostname,port,service,out_dir):
	status="Success"
	result_dict={}
	search_list=['x-xss-protection','x-content-type-options','x-frame-options','strict-transport-security'] #add the headers in small case only
	for item in search_list:
		result_dict[item]="N/A"
	try:
		target_url=service+"://"+hostname+":"+str(port)
		response = requests.get(target_url, verify=False,timeout=10)
		output_file=out_dir+"/HEADER_OUTPUT/"+hostname+"_"+str(port)+"_HEADER.json" #Destination file to save the output
		res_headers=dict((k.lower(), v.lower()) for k,v in (response.headers).items()) #Store the response headers in res_headers dict and convert all them to small case
		dict_to_file(res_headers,output_file) #Function call to write the output to json file
		for item in search_list:
			if item in res_headers.keys():
				result_dict[item]=res_headers[item]
	except Exception as e:
		#print(e)
		result_dict = dict.fromkeys( result_dict, "ERROR" ) #if any error occurs set all the value to ERROR
		status="Failure"
	return status,result_dict 	#Return the dict contains the headers and respective value

#Parse the output and save the result to DB
def header_scan_save(sqliteConnection,select_result,protocol,out_dir):
	for ip_addr,ports_string in select_result:
		ports_list=ports_string.split(',')
		if ports_list!=['']:
			for port in ports_list:
				ip_port=ip_addr+":"+port
				status,result_dict=header_scan_parser(ip_addr,port.strip(),protocol,out_dir)
				hsts=result_dict['strict-transport-security']
				xframe=result_dict['x-frame-options']
				xss=result_dict['x-xss-protection']
				csp=result_dict['x-content-type-options']
				header_result_insert(sqliteConnection,"header_scan","ip_addr",ip_addr,"ip_port",ip_port,"hsts",hsts,"xframe",xframe,"xss",xss,"csp",csp)
				print("[+]: "+ip_port.ljust(16)+" =>  "+status)
				#update_one_field(sqliteConnection,"ip","cert_scan",status,"ip_addr",ip_port) 

#Main entry for program and Initiate header Scan
def header_scan_initialize(sqliteConnection,out_dir):
	print("[-] Header Scan Initiated....")
	select_result=select_two_column(sqliteConnection,"ip_addr","https","nmap_scan")
	header_scan_save(sqliteConnection,select_result,"https",out_dir)
	print("[+] Header Scan Completed....")
