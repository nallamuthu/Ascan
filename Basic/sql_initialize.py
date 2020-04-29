import sqlite3
import os
from Basic.basic_operation import *

#Read the sql query from the sql file and create DB and execute it
def readData():
	f = open('Basic/query.sql', 'r')
	with f:
		data = f.read()
		return data

#Populate the ip in to IP Table
def ip_populate(sqliteConnection,ip):
	ip="'"+ip+"'"
	ip_populate_query="INSERT INTO IP (ip_addr) VALUES ({0})".format(str(ip))
	sqliteConnection.execute(ip_populate_query)


#Initialize Sqlite and execute Query
def initialize_sql(sqliteConnection,input_file):
	ip_list=[]
	f = open(input_file, "r")
	for x in f:
		ip_addr =x.strip()
		ip_list.append(ip_addr)
	ip_list = remove_duplicate_list(ip_list) #To Remove All the duplicates - Function call to basic_operatio file
	#Start pushing all the IP in to the DB
	print("[-] Read the Input File and Populate IP Table [-]")
	for ip in ip_list:
		ip_populate(sqliteConnection,str(ip))
	sqliteConnection.commit()
	print("[+] Read the Input File and Populate IP Table [+]")
	query_list=['delete from header_scan','delete from cipher_scan','delete from nmap_scan','delete from ssl_vuln_scan','insert into nmap_scan(ip_addr) select ip_addr from ip;']
	for query in query_list:
		sqliteConnection.execute(query)
	sqliteConnection.commit()


#Create Database
def create_database(input_file,out_dir):
	db_name="".join(os.path.splitext(input_file)[0].split()) #Remove all the spaces,file ext,path from the input file passed
	db_name = out_dir+"/Database.db"
	sqliteConnection = sqlite3.connect(db_name)
	with sqliteConnection:
		cur = sqliteConnection.cursor()
		sql = readData()
		cur.executescript(sql)
	sqliteConnection.commit()
	initialize_sql(sqliteConnection,input_file) #Populate the Database with IP address
	sqliteConnection.commit()
	return db_name,sqliteConnection


