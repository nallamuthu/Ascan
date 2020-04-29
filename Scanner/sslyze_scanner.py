#Perform the sslyze scan and save it to XML file
import xml.etree.ElementTree as ET
from xlrd import *
from Basic.execute_command import *
from Basic.sql_execute import *
from Basic.basic_operation import *
from Parser.sslyze_parser import *






#Get the result from the parse file and save it to Database
def sslyze_scan_save(sqliteConnection,input_file,ip_addr,ip_port):
	sslv2,sslv3,tlsv1,tlsv1_1,tlsv1_2,tlsv1_3=("N/A","N/A","N/A","N/A","N/A","N/A")
	sslv2_wc,sslv3_wc,tlsv1_wc,tlsv1_1_wc,tlsv1_2_wc,tlsv1_3_wc=("N/A","N/A","N/A","N/A","N/A","N/A")
	if input_file=="N/A":
		sslyze_result_insert(sqliteConnection,ip_addr,ip_port,sslv2,sslv3,tlsv1,tlsv1_1,tlsv1_2,tlsv1_3,sslv2_wc,sslv3_wc,tlsv1_wc,tlsv1_1_wc,tlsv1_2_wc,tlsv1_3_wc)
	else:
		result_dict=parse_sslyze_xml_file(input_file) #Function call to parse xml file - sslyze_parser.py
		sslyze_result_insert(sqliteConnection,ip_addr,ip_port,result_dict['sslv2'],result_dict['sslv3'],result_dict['tlsv1'],result_dict['tlsv1_1'],result_dict['tlsv1_2'],result_dict['tlsv1_3'],result_dict['sslv2_wc'],result_dict['sslv3_wc'],result_dict['tlsv1_wc'],result_dict['tlsv1_1_wc'],result_dict['tlsv1_2_wc'],result_dict['tlsv1_3_wc'])

#perform the scan
def sslyze_scan_start(sqliteConnection,out_dir,ip_addr,ip_port):
	output_file=out_dir+"/SSLYZE_OUTPUT/"+ip_port+"_SSLYZE.xml"
	cmd="sslyze  --regular "+ip_port+" --xml_out="+output_file
	status=execute_command(cmd,"SSLYZE") #Function scan to execute os commands - execute_command.py
	if check_file(output_file): #Function call to check the file exist and not empty - basic_operation.py
		status = "Success"
	else:
		status = "Failed"
		output_file="N/A"
	return status,output_file


#Main entry for program and Initiate SSLYZE Scan
def sslyze_scan_initialize(sqliteConnection,out_dir):
	print("[-] Cipher Scan Initiated....")
	select_result=select_two_column(sqliteConnection,"ip_addr","https","nmap_scan")
	for ip_addr,ports_string in select_result:
		ports_list=ports_string.split(',')
		if ports_list!=['']:
			for port in ports_list:
				ip_port=ip_addr+":"+port.strip()
				status,output_file = sslyze_scan_start(sqliteConnection,out_dir,ip_addr,ip_port) #Internal Function call
				sslyze_scan_save(sqliteConnection,output_file,ip_addr,ip_port) #Internal Function call
				print("[+]: "+ip_addr+":"+str(port)+" => "+status)
	print("[+] Cipher Scan Completed....")



