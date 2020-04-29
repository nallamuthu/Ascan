CREATE TABLE IF NOT EXISTS 'ssl_vuln_scan' (
	'ip_addr'	TEXT,
	'ip_port'	TEXT,
	'heartbleed'	TEXT,
	'ccs'	TEXT,
	'ticketbleed'	TEXT,
	'robot'	TEXT,
	'crime'	TEXT,
	'breach'	TEXT,
	'poodle'	TEXT,
	'freak'	TEXT,
	'beast'	TEXT,
	'lucky13'	TEXT,
	'sweet32'	TEXT,
	'logjam'	TEXT,
	'drown'	TEXT,
	'SR_Server'	TEXT,
	'SR_Client'	TEXT,
	'Fallback_SCSV'	TEXT,
	PRIMARY KEY('ip_port')
);
CREATE TABLE IF NOT EXISTS 'nmap_scan' (
	'ip_addr'	TEXT NOT NULL,
	'status'	TEXT,
	'ssh'	TEXT,
	'ftp'	TEXT,
	'smtp'	TEXT,
	'http'	TEXT,
	'https'	TEXT,
	'rdp'	TEXT,
	'others'	TEXT
);
CREATE TABLE IF NOT EXISTS 'ip' (
	'ip_addr'	TEXT NOT NULL UNIQUE,
	'nmap_scan'	TEXT,
	'nmap_path'	TEXT,
	'header_scan'	TEXT,
	'ssl_scan'	TEXT,
	'cert_scan'	TEXT,
	PRIMARY KEY('ip_addr')
);
CREATE TABLE IF NOT EXISTS 'header_scan' (
	'ip_addr'	TEXT,
	'ip_port'	TEXT,
	'hsts'	TEXT,
	'xframe'	TEXT,
	'xss'	TEXT,
	'csp'	TEXT,
	PRIMARY KEY('ip_port')
);
CREATE TABLE IF NOT EXISTS 'cipher_scan' (
	'ip_addr'	TEXT,
	'ip_port'	TEXT,
	'sslv2'	TEXT,
	'sslv3'	TEXT,
	'tlsv1'	TEXT,
	'tlsv1_1'	TEXT,
	'tlsv1_2'	TEXT,
	'tlsv1_3'	TEXT,
	'sslv2_wc'	TEXT,
	'sslv3_wc'	TEXT,
	'tlsv1_wc'	TEXT,
	'tlsv1_1_wc'	TEXT,
	'tlsv1_2_wc'	TEXT,
	'tlsv1_3_wc'	TEXT,
	PRIMARY KEY('ip_port')
);
CREATE TABLE IF NOT EXISTS 'cert_scan' (
	'ip_addr'	TEXT,
	'ip_port'	TEXT,
	'expiry_status'	TEXT,
	'expiry_in'	TEXT,
	'sign_alg'	TEXT
);
