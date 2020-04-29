#Perform the NMAP scan and save it to XML file
from Basic.execute_command import * 
from Basic.sql_execute import *
from Basic.basic_operation import *
from Parser.nmap_parser import *




#Get the result from the parse file and save it to Database
def nmap_scan_save(sqliteConnection,input_file,ip_addr):
	if input_file=="N/A":
		nmap_result_update(sqliteConnection,"N/A","N/A","N/A","N/A","N/A","N/A","N/A","N/A",ip_addr)
	else:
		ssh_ports,ftp_ports,smtp_ports,http_ports,https_ports,rdp_ports,other_ports=([],[],[],[],[],[],[])
		host_status,result_dict=parse_nmap_xml_file(input_file) #Function call to parse xml file - nmap_parser.py
		for port, service in result_dict.items():
			if service=="ssh":
				ssh_ports.append(port)
			elif service=="ftp":
				ftp_ports.append(port)
			elif service=="smtp":
				smtp_ports.append(port)
			elif service=="http":
				http_ports.append(port)
			elif service=="https":
				https_ports.append(port)
			elif service=="rdp":
				rdp_ports.append(port)
			else:
				other_ports.append(port)
		nmap_result_update(sqliteConnection,host_status,ssh_ports,ftp_ports,smtp_ports,http_ports,https_ports,rdp_ports,other_ports,ip_addr)


#Perform the Scan
def nmap_scan_start(out_dir,ip_addr):
	output_file=out_dir+"/NMAP_OUTPUT/"+ip_addr+"_NMAP.xml"
	cmd="nmap "+ip_addr+" --top-ports 100 -oX "+output_file
	status=execute_command(cmd,"NMAP")        #Function scan to execute os commands - execute_command.py
	if status=="SUCCESS" and check_file(output_file): #Function call to check the file exist and not empty - basic_operation.py
		pass
	else:
		output_file="N/A"
		status=="FAILURE" 
	return status,output_file #Return the path of the xml file contains the nmap output

#Main entry for program and Initiate NMAP Scan
def nmap_scan_initialize(sqliteConnection,out_dir):
	select_query="select ip_addr from ip"
	ip_select_output = sqliteConnection.execute(select_query)
	print("[-] Nmap Scan Initiated....")
	#print(len(ip_select_output))
	for ip_addr in ip_select_output:
		ip_addr=str(ip_addr[0]).strip()
		status,output_file=nmap_scan_start(out_dir,ip_addr) #Internal Function call
		print("[+]: "+ip_addr.ljust(16)+" =>  "+status)
		update_two_field(sqliteConnection,"ip","nmap_scan",status,"nmap_path",output_file,"ip_addr",ip_addr) 
		nmap_scan_save(sqliteConnection,output_file,ip_addr) #Internal Function call
	print("[+] Nmap Scan Completed")





