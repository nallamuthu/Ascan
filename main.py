import sys
import argparse
import shutil
from Basic.basic_operation import *
from Basic.sql_initialize import *
from Basic.dbtoexcel import *
from Basic.execute_command import *
from Scanner.nmap_scanner import *
from Scanner.certificate_scanner import *
from Scanner.header_scanner import *
from Scanner.testssl_scanner import *
from Scanner.sslyze_scanner import *
from Scanner.prerequisite_scanner import *



#Parse the input parameters
my_parser = argparse.ArgumentParser(description='Pass the input file contains the IP to perform the scan')
my_parser.add_argument('-i','--input', action='store', required=True, help='Input file')
args = my_parser.parse_args()
input_file=args.input

#Check for all the pre-requisite in places
status=check_prerequisite()
if not status:
	sys.exit(0)

#Check the input file exist or not empty - Function call to basic operation
if not check_file(input_file):
	print("[!]File doesn't exist[!]")
	sys.exit(0)

timestamp = time.strftime("%d_%m_%Y_%H%M%S")
#Create Folder if not Exist. Create Folder if not Exist
out_dir=create_out_folders(timestamp)


#Create Database schema, connection and populate the DB
db_name,sqliteConnection = create_database(input_file,out_dir)

#sqliteConnection = sqlite3.connect('ip_sheet2_03_04_2020_114342.db')
#Initiate Nmap Scan
nmap_scan_initialize(sqliteConnection,out_dir)

#Initiate Certificate Scan
cert_scan_initialize(sqliteConnection,out_dir)

#Initiate Header Scan
header_scan_initialize(sqliteConnection,out_dir)

#Initiate Testssl scan
testssl_scan_initialize(sqliteConnection,out_dir)

#Initiate sslyze Scan
sslyze_scan_initialize(sqliteConnection,out_dir)


#Close and Commit the database
sqliteConnection.commit()
sqliteConnection.close()
#Export all the SQLITE data to Excel file
db_to_excel(db_name,out_dir)
#Create Zip File
shutil.make_archive(out_dir, 'zip', out_dir)
print("********************************************")
print(('[+] Input File:').ljust(20)+input_file)
print(('[+] Output Folder:').ljust(20)+out_dir)
print(('[+] Database:').ljust(20)+db_name)
print(('[+] Output File:').ljust(20)+out_dir+'/Output.xlsx')
print(('[+] Output Zip:').ljust(20)+out_dir+'.zip')
print("********************************************")
sys.exit(0)




