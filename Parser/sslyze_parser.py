#Read ME - SSLYZE Output file processed as XML
#Input - SSLYZE Output XML File
#Output - Dictonary (Contains the hostname, ip, port, SSL versions and respective weak ciphers if any)
import xml.etree.ElementTree as ET
from Basic.basic_operation import *

#Global Variables - set all the required to N/A
result_dict={}
ssl_versions=['sslv2','sslv3','tlsv1','tlsv1_1','tlsv1_2','tlsv1_3']
required_details=['host','ip','port']
for item in ssl_versions:
	result_dict[item]="N/A"
for item in required_details:
	result_dict[item]="N/A"

#Check for SSL Supported Versions
def is_ssl_version_supported(root,search_element):
	status="Error" #Return Error in case of the element / parameter not found
	for element in root.iter(search_element):
		if element: #Check if the element is present or not
			if 'isProtocolSupported' in element.attrib: #Check if the element has the parameter isProtocolSupported
				status= element.attrib['isProtocolSupported'] #Return True or False
			else:
				status="FALSE"
	return status

#Check weak ciphers is enabled on the enabled SSL versions
def is_weak_cipher_enabled(root,search_element):
	weak_cipher_list=[]
	for element in root.iter(search_element): #Root Element - SSLv3 or TLS1_1 or TLS1_2
		if element: #check if there is further elements like <acceptedCipherSuites , <preferredCipherSuite, <rejectedCipherSuites
			for childs in element.getiterator('acceptedCipherSuites'): #Loop through only acceptedCipherSuites. if changes required make it empty element.getiterator()
				if childs: #if the childs has the elements <cipherSuite
					for cipher in childs:
						if ('connectionStatus' in cipher.attrib) and ('name' in cipher.attrib): #If the cipher element has attributes like connectionstatus and name
							conn_status=cipher.attrib['connectionStatus']
							conn_cipher=cipher.attrib['name']
							if (("200" in conn_status) and ("MD5" in conn_cipher or "RC4" in conn_cipher or "SHA1" in conn_cipher or "CBC" in conn_cipher)):
								weak_cipher_list.append(conn_cipher)
	return weak_cipher_list

#Get all the SSL Version and respective cipher
def get_ssl_ciphers(root):
	global ssl_version
	global result_dict
	try:
		for version in ssl_versions:
			status=is_ssl_version_supported(root,version) #Check the ssl version is supported or not
			wc=version+"_wc"
			if status=="True":
				result=is_weak_cipher_enabled(root,version) #If the version is supported then look for weak ciphers
				if result : #Check any weak cipher list came or empty
					result_dict[version]="TRUE" #If weak ciphers present, set the version to weak ciphers as list
					result_dict[wc]=result
				else:
					result_dict[version]="TRUE" #If no weak ciphers present, set version to true
					result_dict[wc]="N/A"
			else:
				result_dict[version]="FALSE" #if the ssl version is not enabled set version to flase
				result_dict[wc]="N/A"
	except Exception as e:
		print(e)
		result_dict = dict.fromkeys( result_dict, "ERROR" ) #if any error occurs set all the value to ERROR
	return result_dict

#Get scan details(host, ip, port)
def get_scan_details(root):
	global required_details
	global result_dict
	for element in root.iter('target'):
		if element.attrib: #If the arget <target element has attributes (host, ip,port)
			for items in required_details:
				result_dict[items]=element.attrib[items]
	return result_dict

#Take the SSLYZE input file and parse the output
def parse_sslyze_xml_file(input_file):
	global result_dict
	try:
		if check_file(input_file): #Function call to check the file exist and not empty - basic_operation.py
			tree=ET.parse(input_file)
			root=tree.getroot()
			result_dict=get_ssl_ciphers(root) #get the ssl version enabled and weak ciphers
			result_dict=get_scan_details(root) #get the host,ip,port
			#result_dict.update(result_dict) #merge 2 dictonary
	except Exception as e:
		#print(e)
		result_dict = dict.fromkeys( result_dict, "ERROR" ) #if any error occurs set all the value to ERROR	
	return result_dict
