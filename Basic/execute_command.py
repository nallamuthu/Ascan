import subprocess


#Execute the command and return the status
def execute_command(cmd,caller):
	status = "SUCCESS"
	try:
		output = subprocess.check_output(cmd, shell=True,timeout=120)  # returns the exit code in unix 12 minutes timeout
		#if ("Screenshot somehow failed" in str(output)) and caller=="webscreenshot": #Check the outut status of the webscreenshot process
		#	status="FAILED"
	except Exception as e:
		#print("Except:"+str(e))
		status = "FAILED"
	return status



