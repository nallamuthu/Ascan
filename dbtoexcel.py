import xlsxwriter
import sqlite3

#To Fetch all the data from the table
def fetch_table_data(conn,cur,table_name):
    # The connect() constructor creates a connection to the SQLITE
    cur = conn.cursor()
    cur.execute('select * from ' + table_name)
    header = [row[0] for row in cur.description]
    rows = cur.fetchall()
    return header, rows

#Convert the data from Table to Excel
def export(wb,conn,cur,table_name):
    # Create Sheet in the name of Table
    worksheet = wb.add_worksheet(table_name.upper())
    # Create style for cells
    header_cell_format = wb.add_format({'bold': True, 'border': True, 'bg_color': 'yellow'})
    body_cell_format = wb.add_format({'border': True})
    header, rows = fetch_table_data(conn,cur,table_name)
    row_index = 0
    column_index = 0
    for column_name in header:
        worksheet.write(row_index, column_index, column_name.upper(), header_cell_format)
        column_index += 1
    row_index += 1
    for row in rows:
        column_index = 0
        for column in row:
            worksheet.write(row_index, column_index, column, body_cell_format)
            column_index += 1
        row_index += 1

#Initialize Function
def db_to_excel(db_name,out_dir):
	out_file=out_dir+"/Output.xlsx"
	wb = xlsxwriter.Workbook(out_file)
	conn = sqlite3.connect(db_name)
	cur = conn.cursor()
	tables_list=cur.execute('SELECT name from sqlite_master where type= "table"')
	for table in tables_list:
		export(wb,conn,cur,table[0])
	wb.close()



