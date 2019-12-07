import nmap, psycopg2, datetime, yaml, sys

with open('creds.yaml', 'r') as file:
    doc = yaml.load(file)
db_host = doc['host']
db_name = doc['database']
db_user = doc['user']
db_user_password = doc['password']

#Database connection:
database = psycopg2.connect(host=db_host,database=db_name,user=db_user,password=db_user_password)
cursor = database.cursor()

#Init scanner object:
scanner = nmap.PortScanner()

def read_hosts(cursor):
    psql_statement = "SELECT id,ip_addr FROM host"
    cursor.execute(psql_statement)
    return cursor.fetchall()

def write_host(state,hostname,host_id,database,cursor,timestamp):
    print_neutral()
    print("Updating host data...")
    try:
        psql_statement = " UPDATE host SET state = %s, hostname = %s, last_scan = %s WHERE id = %s"
        insert = (state, hostname, timestamp, host_id)
        cursor.execute(psql_statement,insert)
        database.commit()
        print_neutral()
        print("Host data updated successfully")
    except:
        print_negative()
        print("Failed when updating host data")

def insert_service_row(host_id,port,proto,service_name,service_product,service_version,service_info,state,database,cursor):
    print_neutral()
    print("Inserting new row")
    try:
        psql_statement = " INSERT INTO service (host, port, protocol, name, product, version, info, state) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
        insert = (host_id,port,proto,service_name,service_product,service_version,service_info,state)
        cursor.execute(psql_statement,insert)
        database.commit()
        print_neutral()
        print("Row inserted successfully")
    except:
        print("Failed when inserting new service row")

def update_service_row(service_name,service_product,service_version,service_info,host_id,port,database,cursor):
    try:
        psql_statement = "UPDATE service SET name = %s, product = %s, version = %s, info = %s WHERE host = %s AND port = %s"
        update = (service_name,service_product,service_version,service_info,host_id,port)
        cursor.execute(psql_statement,update)
        database.commit()
        print_neutral()
        print("Existing row updated successfully")
    except:
        print("Failed when updating existing row")


def existing_ports(host_id,database,cursor):
    psql_statement = " SELECT port FROM service WHERE host = %s"
    insert = (host_id)
    cursor.execute(psql_statement,[insert])
    database.commit()
    return cursor.fetchall()

def new_service(port,host_id,database,cursor):
    for x in existing_ports(host_id,database,cursor):
        if x[0] == port:
            return True
        else:
            pass
    if not update:
        return False

def print_discovery(ports, protocols, names, products, versions, infos):
    print_neutral()
    print("Found the following new services:")
    print_neutral()
    print("Port:\tProtocol:\tName:\t\tProduct:\tVersion:\tInfo:") #80 long, but not really? idk...
    print_neutral()
    print("================================================================================")#Make this a fuction lol
    while len(ports) > 0:
        print_positive()
        print(ports.pop(),"\t",protocols.pop(),"\t",names.pop(),"\t",products.pop(),"\t",versions.pop(),"\t",infos.pop())

def print_red(text):
    print("\033[91m {}\033[00m" .format(text), end = '')

def print_green(text):
    print("\033[92m {}\033[00m" .format(text), end = '')

def print_blue(text):
    print("\033[96m {}\033[00m" .format(text), end = '')

def print_positive():
    print_green("[+] ")

def print_neutral():
    print_blue("[*] ")

def print_negative():
    print_red("[-] ")

def print_host_up(state):
    print_positive()
    print("Host is up")
    return state

def print_host_down():
    print_negative()
    print("Host down")
    state = 'down'
    return state

def print_hostname_exists(hostname):
    print_neutral()
    print("Hostname:",hostname)
    return hostname

def print_hostname_not_exists():
    print_neutral()
    print("No hostname found")

def protocol_type(scanner, address):
    try:
        if scanner[address].has_tcp():
            return 'TCP'
    except:
        try:
            if scanner[address].has_upd():
                return 'UDP'
        except:
            return ''

while True:
    for row in read_hosts(cursor):
        hostname = ''
        state = ''
        print("")
        print_neutral()
        print("Scanning host", row[1])
        try:
            timestamp = datetime.datetime.now()
            scanner.scan(hosts=row[1], arguments='-A -p-')
            try:
                state = print_host_up(scanner[row[1]].state())
            except:
                hostname = print_host_down()
            if state == 'up':
                try:
                    hostname = print_hostname_exists(scanner[row[1]].hostname())
                except:
                    hostname = print_hostname_not_exists()
            write_host(state,hostname,row[0],database,cursor,timestamp)
            if state == 'up':
                ports = []
                protocols = []
                names = []
                products = []
                versions = []
                infos = []
                service_discovery = False
                for port in range(65000):
                    update = False
                    proto = ''
                    state = ''
                    service_name = ''
                    service_info = ''
                    service_product = ''
                    service_version = ''
                    if scanner[row[1]].has_tcp(port) or scanner[row[1]].has_udp(port):
                        proto = protocol_type(scanner, row[1])
                        try:
                            state = scanner[row[1]][proto][port]['state']
                        except:
                            pass
                        try:
                            service_name = scanner[row[1]][proto][port]['name']
                        except:
                            pass
                        try:
                            service_version = scanner[row[1]][proto][port]['product']
                        except:
                            pass
                        try:
                            service_info = scanner[row[1]][proto][port]['extrainfo']
                        except:
                            pass

                        update = new_service(port,row[0],database,cursor)
                        if not update:
                            print_positive()
                            print("Found new service:",service_name,"\tVersion:",service_version,"\tPort:",port,"\tState:",state)
                            insert_service_row(row[0],port,proto,service_name,service_product,service_version,service_info,state,database,cursor)
                            ports.append(port)
                            protocols.append(proto)
                            names.append(service_name)
                            products.append(service_product)
                            versions.append(service_version)
                            infos.append(service_info)
                            service_discovery = True
                        else:
                            print_neutral()
                            print("Updating service:",service_name,"on port:",port)
                            update_service_row(service_name,service_product,service_version,service_info,row[0],port,database,cursor)
                if service_discovery:
                    print_discovery(ports,protocols,names,products,versions,infos)
        except:
            cursor.close()
            database.close()
            sys.exit('Scan Failed... Time to debug this shit lmao\n')
            pass
