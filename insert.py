import psycopg2
import ipaddress
import yaml

with open('creds.yaml', 'r') as file:
    doc = yaml.load(file)
db_host = doc['host']
db_name = doc['database']
db_user = doc['user']
db_user_password = doc['password']

#Database connection:
database = psycopg2.connect(host=db_host,database=db_name,user=db_user,password=db_user_password)
cursor = database.cursor()

for ip in ipaddress.ip_network('192.168.143.0/24'):
    psql_statement = " INSERT INTO host (ip_addr, auto_sys) VALUES (%s,%s)"
    iw = str(ipaddress.IPv4Address(ip))
    insert = (iw,1)
    cursor.execute(psql_statement,insert)
    database.commit()
