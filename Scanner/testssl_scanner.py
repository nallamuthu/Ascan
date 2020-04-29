#Perform the testssl scan and save it to CSV file
from execute_command import * 
from sql_execute import *
from Parser.testssl_parser import *
from basic_operation import *


#Get the result from the parse file and save it to Database
def testssl_scan_save(sqliteConnection,input_file,ip_addr,ip_port):
	heartbleed,ccs,ticketbleed,robot,crime_tls="N/A","N/A","N/A","N/A","N/A"
	breach,poodle_ssl,freak,beast,lucky13,sweet32="N/A","N/A","N/A","N/A","N/A","N/A"
	logjam,drown,secure_renego,secure_client_renego,fallback_scsv="N/A","N/A","N/A","N/A","N/A"
	if input_file=="N/A":
		testssl_result_insert(sqliteConnection,ip_addr,ip_port,heartbleed,ccs,ticketbleed,robot,crime_tls,breach,poodle_ssl,freak,beast,lucky13,sweet32,logjam,drown,secure_renego,secure_client_renego,fallback_scsv)
	else:
		result_dict=parse_testssl_csv_file(input_file) #Function call to parse csv file - testssl_parser.py
		heartbleed=result_dict['heartbleed']
		ccs=result_dict['ccs']
		ticketbleed=result_dict['ticketbleed']
		robot=result_dict['robot']
		crime_tls=result_dict['crime_tls']
		breach=result_dict['breach']
		poodle_ssl=result_dict['poodle_ssl']
		freak=result_dict['freak']
		beast=result_dict['beast']
		lucky13=result_dict['lucky13']
		sweet32=result_dict['sweet32']
		logjam=result_dict['logjam']
		drown=result_dict['drown']
		secure_renego=result_dict['secure_renego']
		secure_client_renego=result_dict['secure_client_renego']
		fallback_scsv=result_dict['fallback_scsv']
		testssl_result_insert(sqliteConnection,ip_addr,ip_port,heartbleed,ccs,ticketbleed,robot,crime_tls,breach,poodle_ssl,freak,beast,lucky13,sweet32,logjam,drown,secure_renego,secure_client_renego,fallback_scsv)


#Perform the scan
def testssl_scan_start(sqliteConnection,out_dir,ip_addr,ip_port):
	output_file=out_dir+"/SSL_VULN_OUTPUT/"+ip_port+"_VULN.csv"
	cmd="testssl --openssl-timeout 120 --csvfile "+output_file+" -U "+ip_port
	status=execute_command(cmd,"testssl") #Function scan to execute os commands - execute_command.py
	if check_file(output_file): #Function call to check the file exist and not empty - basic_operation.py
		status = "Success"
	else:
		status = "Failed"
		output_file="N/A"
	return status,output_file


#Main entry for program and Initiate TESTSSL Scan
def testssl_scan_initialize(sqliteConnection,out_dir):
	print("[-] SSL Vuln Scan Initiated....")
	select_result=select_two_column(sqliteConnection,"ip_addr","https","nmap_scan")
	for ip_addr,ports_string in select_result:
		ports_list=ports_string.split(',')
		if ports_list!=['']:
			for port in ports_list:
				ip_port=ip_addr+":"+port.strip()
				status,output_file = testssl_scan_start(sqliteConnection,out_dir,ip_addr,ip_port) #Internal Function call
				testssl_scan_save(sqliteConnection,output_file,ip_addr,ip_port) #Internal Function call
				print("[+]: "+ip_addr+":"+port.strip()+" =>  "+status)
	print("[+] SSL Vuln Scan Completed....")







