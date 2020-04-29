import socket
import os
import time
import importlib
from Basic.execute_command import *

'''
def check_prerequisite():
def create_out_folders(timestamp):
def validate_ip_logic(ip_address):
def validate_ip(ip_address):
def set_all_dict_value(input_dict,value):
def remove_duplicate_list(input_list):
def remove_empty_element_list(input_list):
def list_to_file(input_list,output_file):
def file_to_list(input_file): 
def get_file_details(input_file):
def file_string_replace(input_file):
def check_file(input_file):
def dict_to_file(input_dict,output_file):
'''

#Create Outut Directory
def create_out_folders(timestamp):
	out_dir="OUTPUT_"+time.strftime("%d_%m_%Y_%H%M%S")
	cmd="mkdir "+out_dir
	return_code=execute_command(cmd,"MKDIR") #Create Output Folder
	folders=['NMAP_OUTPUT','HEADER_OUTPUT','SSLYZE_OUTPUT','CERT_OUTPUT','SSL_VULN_OUTPUT']
	for names in folders:
		temp_out_dir=out_dir+"/"+names
		cmd="mkdir "+temp_out_dir
		return_code=execute_command(cmd,"MKDIR") #Create Output Folder
	return out_dir


#Remove Duplicates from list - Input (ipaddress)1 | Output (status)1
def validate_ip_logic(ip_address):
	valid_host=ip_address.split(".")
	len_host=len(valid_host)
	if (len_host<4) or (len_host>4):
		status=False
	elif len_host==4:
		for i in valid_host:
			if (int(i)<0) or (int(i)>255):
				status=False
				break
			if valid:
				status=True
	return status

#Remove Duplicates from list - Input (ipaddress)1 | Output (status)1
def validate_ip(ip_address):
	status=""
	try:
		socket.inet_aton(ip_address)
		status=True
	except socket.error:
		status=False
	return status

#Set all the dictonary value to some string - Input (input_dict,string) | Output (output_dict)1
def set_all_dict_value(input_dict,value):
	result_dict = dict.fromkeys( input_dict, value )
	return result_dict

#Remove Duplicates from list - Input (list)1 | Output (list)1
def remove_duplicate_list(input_list):
	output_list = list(set(input_list))
	return output_list

#Remove Empty elements from list  - Input (list)1 | Output (list)1
def remove_empty_element_list(input_list):
	output_list = [x for x in input_list if x] 
	return output_list

#Convert list to File - Input (input_list, output_file)2 | Output (output_file)1
def list_to_file(input_list,output_file):
	with open(output_file,'w') as fi:
		for element in input_list:
			fi.write(element+"\n")
	return output_file

#Convert file to list - Input (input_file)1 | Output (list)1
def file_to_list(input_file): 
	output_list=[]
	if os.path.isfile(input_file): #Check file exist
		with open(output_file) as f: #Open file
			output_list = f.read().splitlines() #Convert file to list
	return output_list

#Get the file details - Input (filename)1 | Output (file_abspath,dir_abspath,filename_withext,filename_only,file_ext_only) 5
def get_file_details(input_file):
	#Get absolute path of the file
	file_abspath=os.path.abspath(input_file)
	#Get the directory path - leaving the file name
	dir_abspath=os.path.dirname(file_abspath)
	#Get the File name with extension
	filename_withext=os.path.basename(file_abspath)
	#Get the filename removing the extension 
	filename_only=os.path.splitext(filename_withext)[0]  #Assuming there is only 1 dot
	#Get the extension
	file_ext_only=os.path.splitext(filename_withext)[1]  #Assuming there is only 1 dot
	return file_abspath,dir_abspath,filename_withext,filename_only,file_ext_only

#Open file and replace particular string and save the file in same name - Input (filename)1 | Output()
def file_string_replace(input_file):
	f1=open(input_file,"r+")
	input=f1.read()
	input=input.replace('<BR>','\n') #Replace all the '<BR>' with new line
	f2=open(input_file,"w+")
	f2.write(input)
	f1.close()
	f2.close()
    
#Check file and exist and file is not empty - Input (filename)1 | Output(status) 
def check_file(input_file):
    status=False
    if os.path.isfile(input_file) and os.path.getsize(input_file) > 0:
        status=True
    return status

#Check if folder exist or create it
def is_folder_exit(out_dir):
	if os.path.isdir(out_dir):
		status="SUCCESS"
	else:
		cmd="mkdir -p "+out_dir #Create folder with recursive
		status=execute_command(cmd,"MKDIR") #Create Output Folder
	return status 

#Write dict to file
def dict_to_file(input_dict,output_file):
	f=open(output_file,"w+")
	for key,value in input_dict.items():
		f.write(str(key)+": "+str(value)+"\n")
