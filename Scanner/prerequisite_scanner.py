import importlib
import subprocess

#Check required os commands are installed
def check_os_module(input_dict):
	status=True
	result_dict = dict.fromkeys( input_dict, False)
	try:
		for key,value in result_dict.items():
			output=subprocess.run(key, shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)  # returns the exit code in unix
			if "not" in str((output.stderr).decode('utf-8')):
				result_dict[key]=False
			else:
				result_dict[key]=True
		if False in result_dict.values():
			status=False		
	except Exception as e:
		print(e)
		status=False	
	return status,result_dict

#Check required pip modules are installed
def check_pip_module(input_dict):
	status=True
	result_dict = dict.fromkeys( input_dict, False)
	try:
		for key,value in result_dict.items():
			if importlib.util.find_spec(key) is None:
				result_dict[key]=False
			else:
				result_dict[key]=True
		if False in result_dict.values():
			status=False
	except Exception as e:
		#print(e)
		status=False
	return status,result_dict

#Main entry for program to check the required programs
def check_prerequisite():
	check_cmd_dict={'testssl','sslyze','nmap'}	
	check_module_dict={'socket','OpenSSL','datetime','ssl','xlsxwriter','sqlite3','requests','urllib3','argparse','shutil','xmltodict','xlrd','csv','sslyze'}
	status1,result_dict=check_pip_module(check_module_dict)
	if not status1:
		print("[!] Below PIP modules - Not Found[!]")
	for key,value in result_dict.items():
		if not value:
			print(" * "+key.ljust(16))
	status2,result_dict=check_os_module(check_cmd_dict)
	if not status2:
		print("\n[!] Below OS Commands - Not Found[!]")
	for key,value in result_dict.items():
		if not value:
			print(" * "+key.ljust(16))	
	return status1 and status2

