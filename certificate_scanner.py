import OpenSSL
import ssl, socket
from datetime import timedelta, date
from sql_execute import *

#Get Certificate Details
def cert_scan_parser(hostname,port):
	status="Failure"
	result_dict={'expiry_status':'N/A','expiry_date':'N/A','expiry_in':'N/A','sign_alg':'N/A'}
	try:
		public_cert_obj=ssl.get_server_certificate((hostname, port))
		x509_object = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, public_cert_obj)
		exp_date =x509_object.get_notAfter()
		exp_day = int(exp_date[6:8].decode('utf-8'))
		exp_month = int(exp_date[4:6].decode('utf-8'))
		exp_year = int(exp_date[:4].decode('utf-8'))
		exp_date = str(exp_year) + "-" + str(exp_month) + "-" + str(exp_day)
		result_dict['expiry_status']=x509_object.has_expired() #Certificate Expired or not
		result_dict['expiry_date']=exp_date #The Date in which the certificate Expires
		result_dict['expiry_in']=(date(exp_year,exp_month,exp_day)-date.today()).days #Get the No.of.Days Left for Expiry
		result_dict['sign_alg']=(x509_object.get_signature_algorithm()).decode('utf-8') #Get the signature algorithm
		status="Success"
	except Exception as e:
		#print(e)
		result_dict = dict.fromkeys( result_dict, "ERROR" ) #if any error occurs set all the value to ERROR
	return status,result_dict 	#Return the dict contains the result

#Parse the output and save the details to the DB
def cert_scan_save(sqliteConnection,select_result,protocol):
	for ip_addr,ports_string in select_result:
		ports_list=ports_string.split(',')
		if ports_list!=['']:
			for port in ports_list:
				ip_port=ip_addr+":"+port
				status,result_dict=cert_scan_parser(ip_addr,port.strip())
				expiry_status=result_dict['expiry_status']
				expiry_in=result_dict['expiry_in']
				sign_alg=result_dict['sign_alg']
				cert_result_insert(sqliteConnection,"cert_scan","ip_addr",ip_addr,"ip_port",ip_port,"expiry_status",expiry_status,"expiry_in",expiry_in,"sign_alg",sign_alg)
				print("[+]: "+ip_port.ljust(16)+" =>  "+status)
				#update_one_field(sqliteConnection,"ip","cert_scan",status,"ip_addr",ip_port) 


#Main entry for program and Initiate certificate Scan
def cert_scan_initialize(sqliteConnection,out_dir):
	print("[-] Certificate Scan Initiated....")
	select_result=select_two_column(sqliteConnection,"ip_addr","https","nmap_scan")
	cert_scan_save(sqliteConnection,select_result,"https")
	print("[+] Certificate Scan Completed....")
