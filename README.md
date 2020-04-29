# :a: Ascan :a:

Tool take IP's as input from the text file and perform the scans. Tools generated output are stored and final summary is stored in database and Excel

## Pre-requisite:
* pip install -r requirements.txt
* NMAP (apt install nmap)
* TESTSSL.SH (apt install testssl.sh)

## Scanners:
* NMAP - Top ports Scan
* SSLYZE - SSL Vulnerability Scan
* TESTSSL - Weak Ciphers Scan
* HEADER - HTTP Security Headers Scan
* CERTIFICATE - Certificate Scan


## Execution:
* python main.py -i ip_file.txt

## Output
* Sqlite DB File
* Excel File
* Zip File (Contains - DB, Excel and all the tool output)