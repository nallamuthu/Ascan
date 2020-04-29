#Import Module
import sqlite3


###Select one column from any table
def select_one_column(sqliteConnection,column_name,table_name):
	select_one_column_query="select {column} from {tn}".format(column=column_name,tn=table_name)
	select_one_column_result = sqliteConnection.cursor()
	select_one_column_result.execute(select_one_column_query)
	return select_one_column_result


###Select one column with condition from any table 
def select_one_column_where(sqliteConnection,column_name,table_name,where_field,where_value):
	select_one_column_where_query="select {column} from {tn} where {wf}=?".format(column=column_name,tn=table_name,wf=where_field)
	data=(where_value,)
	select_one_column_where_result = sqliteConnection.cursor()
	select_one_column_where_result.execute(select_one_column_where_query,data)
	return select_one_column_where_result


###Select two column from any table
def select_two_column(sqliteConnection,column_name1,column_name2,table_name):
	select_two_column_query="select {column1},{column2} from {tn}".format(column1=column_name1,column2=column_name2,tn=table_name)
	select_two_column_result = sqliteConnection.cursor()
	select_two_column_result.execute(select_two_column_query)
	return select_two_column_result

###Update One Field in any Table
def update_one_field(sqliteConnection,table_name,set_field1,set_value1,where_field,where_value):
	update_one_field_query="UPDATE {tn} SET {sf1}=? WHERE {wf}=?".format(tn=table_name,sf1=set_field1, wf=where_field)
	data = (set_value1, where_value) #SQLITE does not support address data type. Covert to string before store it to DB
	sqliteConnection.execute(update_one_field_query, data)
	sqliteConnection.commit()


###Update Two Field in any Table
def update_two_field(sqliteConnection,table_name,set_field1,set_value1,set_field2,set_value2,where_field,where_value):
	update_two_field_query="UPDATE {tn} SET {sf1}=?,{sf2}=? WHERE {wf}=?".format(tn=table_name,sf1=set_field1,sf2=set_field2, wf=where_field)
	data = (set_value1,str(set_value2), where_value) #SQLITE does not support address data type. Covert to string before store it to DB
	sqliteConnection.execute(update_two_field_query, data)
	sqliteConnection.commit()


###Update Three Field in any Table
def update_three_field(sqliteConnection,table_name,set_field1,set_value1,set_field2,set_value2,set_field3,set_value3,where_field,where_value):
	update_three_field_query="UPDATE {tn} SET {sf1}=?,{sf2}=?,{sf3}=? WHERE {wf}=?".format(tn=table_name,sf1=set_field1,sf2=set_field2,sf3=set_field3,wf=where_field)
	data = (set_value1,str(set_value2).strip('[]'),str(set_value3),where_value) #if required remove [] from the data
	sqliteConnection.execute(update_three_field_query, data)
	sqliteConnection.commit()


###Insert any 4 columns values into any table
def insert_four_field(sqliteConnection,table_name,update_field1,update_value1,update_field2,update_value2,update_field3,update_value3,update_field4,update_value4):
	insert_four_field_query="INSERT INTO {tn} ({uf1},{uf2},{uf3},{uf4}) VALUES (?,?,?,?)".format(tn=table_name,uf1=update_field1,uf2=update_field2,uf3=update_field3,uf4=update_field4)
	data = (update_value1,update_value2,update_value3,update_value4)
	sqliteConnection.execute(insert_four_field_query, data)
	sqliteConnection.commit()


###Update any 8 columns values into any table
def update_eight_field(sqliteConnection,table_name,set_field1,set_value1,set_field2,set_value2,set_field3,set_value3,set_field4,set_value4,set_field5,set_value5,set_field6,set_value6,set_field7,set_value7,set_field8,set_value8,where_field,where_value):
	update_eight_field_query="UPDATE {tn} SET {sf1}=?,{sf2}=?,{sf3}=?,{sf4}=?,{sf5}=?,{sf6}=?,{sf7}=?,{sf8}=? WHERE {wf}=?".format(tn=table_name,sf1=set_field1,sf2=set_field2,sf3=set_field3,sf4=set_field4,sf5=set_field5,sf6=set_field6,sf7=set_field7,sf8=set_field8,wf=where_field)
	data = (str(set_value1),str(set_value2).strip('[]'),str(set_value3).strip('[]'),str(set_value4).strip('[]'),str(set_value5).strip('[]'),str(set_value6).strip('[]'),str(set_value7).strip('[]'),str(set_value8).strip('[]'),str(where_value))
	sqliteConnection.execute(update_eight_field_query, data)
	sqliteConnection.commit()


###Certificate Scan Result Vuln Insert Result
def cert_result_insert(sqliteConnection,table_name,update_field1,update_value1,update_field2,update_value2,update_field3,update_value3,update_field4,update_value4,update_field5,update_value5):
	query="INSERT INTO {tn} ({uf1},{uf2},{uf3},{uf4},{uf5}) VALUES (?,?,?,?,?)".format(tn=table_name,uf1=update_field1,uf2=update_field2,uf3=update_field3,uf4=update_field4,uf5=update_field5)
	data = (update_value1,update_value2,update_value3,update_value4,update_value5)
	sqliteConnection.execute(query, data)
	sqliteConnection.commit()

###Header Scan Result Vuln Insert Result
def header_result_insert(sqliteConnection,table_name,update_field1,update_value1,update_field2,update_value2,update_field3,update_value3,update_field4,update_value4,update_field5,update_value5,update_field6,update_value6):
	query="INSERT INTO {tn} ({uf1},{uf2},{uf3},{uf4},{uf5},{uf6}) VALUES (?,?,?,?,?,?)".format(tn=table_name,uf1=update_field1,uf2=update_field2,uf3=update_field3,uf4=update_field4,uf5=update_field5,uf6=update_field6)
	data = (update_value1,update_value2,update_value3,update_value4,update_value5,update_value6)
	sqliteConnection.execute(query, data)
	sqliteConnection.commit()


###testssl Scan Result  Insert Result
def testssl_result_insert(sqliteConnection,ip_addr,ip_port,heartbleed,ccs,ticketbleed,robot,crime,breach,poodle,freak,beast,lucky13,sweet32,logjam,drown,sr_server,sr_client,fallback_scsv):
	query="INSERT INTO ssl_vuln_scan (ip_addr,ip_port,heartbleed,ccs,ticketbleed,robot,crime,breach,poodle,freak,beast,lucky13,sweet32,logjam,drown,sr_server,sr_client,fallback_scsv) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
	data = (ip_addr,ip_port,heartbleed,ccs,ticketbleed,robot,crime,breach,poodle,freak,beast,lucky13,sweet32,logjam,drown,sr_server,sr_client,fallback_scsv)
	sqliteConnection.execute(query, data) 
	sqliteConnection.commit()

###sslyze Scan Result Insert Result
def sslyze_result_insert(sqliteConnection,ip_addr,ip_port,sslv2,sslv3,tlsv1,tlsv1_1,tlsv1_2,tlsv1_3,sslv2_wc,sslv3_wc,tlsv1_wc,tlsv1_1_wc,tlsv1_2_wc,tlsv1_3_wc):
	cipher_insert_result_query="INSERT INTO cipher_scan (ip_addr,ip_port,sslv2,sslv3,tlsv1,tlsv1_1,tlsv1_2,tlsv1_3,sslv2_wc,sslv3_wc,tlsv1_wc,tlsv1_1_wc,tlsv1_2_wc,tlsv1_3_wc) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
	data = (ip_addr,ip_port,sslv2,sslv3,tlsv1,tlsv1_1,tlsv1_2,tlsv1_3,str(sslv2_wc),str(sslv3_wc),str(tlsv1_wc),str(tlsv1_1_wc),str(tlsv1_2_wc),str(tlsv1_3_wc))
	sqliteConnection.execute(cipher_insert_result_query, data) 
	sqliteConnection.commit()

###nmap Scan Result Insert Result
def nmap_result_update(sqliteConnection,host_status,ssh_ports,ftp_ports,smtp_ports,http_ports,https_ports,rdp_ports,other_ports,ip_addr):
	query="UPDATE nmap_scan SET status=?,ssh=?,ftp=?,smtp=?,http=?,https=?,rdp=?,others=? WHERE ip_addr=?"
	data = (host_status,str(ssh_ports).strip('[]'),str(ftp_ports).strip('[]'),str(smtp_ports).strip('[]'),str(http_ports).strip('[]'),str(https_ports).strip('[]'),str(rdp_ports).strip('[]'),str(other_ports).strip('[]'),ip_addr)
	sqliteConnection.execute(query, data)
	sqliteConnection.commit()



