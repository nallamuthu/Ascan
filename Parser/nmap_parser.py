#Read ME - NMAP Output file is converted to dictonary and processed
#Input - NMAP Output XML File
#Output - Dictonary (Contains the opened port number and service name)

#pip install xmltodict
import xmltodict
from basic_operation import *

#Function to parse the xml file
def parse_nmap_xml_file(input_file):
	result_dict={} #To store the port_number:service_name
	host_status="N/A"
	try:
		if check_file(input_file):  #Function call to check the file exist and not empty - basic_operation.py
			with open(input_file) as fd:
				col_ordered_dict = xmltodict.parse(fd.read()) #Convert the xml file to dictonary to process it
			host_status=col_ordered_dict['nmaprun']['runstats']['hosts']['@up'] #Get the Host status Valye 1 or 0
			if host_status=="1": #if Host status is up then process further
				for items in col_ordered_dict['nmaprun']['host']['ports']['port']: #Loop Through all the open ports and get the list
					if items['state']['@state']=="open":
						result_dict[int(items['@portid'])] = items['service']['@name'] #Save Port Number and Service Name into Dict
	except Exception as e:
		#print(e)
		host_status="ERROR"
	return host_status,result_dict

