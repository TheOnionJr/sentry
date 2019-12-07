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


#############Functions###############

def read_hosts(cursor):
    psql_statement = "SELECT id,ip_addr FROM host"
    cursor.execute(psql_statement)
    return cursor.fetchall()

def find_scannable_hosts(cursor,database):
    #Find 10 hosts to scan that are not reserved
    psql_statement = "SELECT id, ip_addr FROM host WHERE reserved = false ORDER BY id FETCH FIRST 16 ROWS only"
    cursor.execute(psql_statement)
    hosts = cursor.fetchall()

    #Race condition is technically possible, but should not matter. Only loss is efficensy
    for row in hosts:
        psql_statement = "UPDATE host SET reserved = true WHERE id = {0}".format(row[0])
        cursor.execute(psql_statement)
        database.commit()
    return hosts

def free_hosts(hosts,cursor,database):
    for row in hosts:
        psql_statement = "UPDATE host SET reserved = false where id = {0}".format(row[0])
        cursor.execute(psql_statement)
        database.commit()


def write_host(state,hostname,host_id,database,cursor):
    print_neutral()
    print("Updating host data...")
    try:
        psql_statement = " UPDATE host SET state = %s, hostname = %s, last_scan = NOW() WHERE id = %s"
        insert = (state, hostname, host_id)
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

def protocol_type(scanner, address, port):
    try:
        if scanner[address].has_tcp(port):
            print("tcp")
            return 'tcp'
    except:
        print("not tcp")
        try:
            if scanner[address].has_upd(port):
                print("udp")
                return 'udp'
        except:
            print("not udp")
            return ''

def create_ipaddr_list(host_list):
    ipaddr_to_return = []
    for row in host_list:
        ipaddr_to_return.append(row[1])
    print(ipaddr_to_return)
    return ipaddr_to_return



######################Main######################

while True:
    host_list = find_scannable_hosts(cursor,database)
    try:
        for host in host_list:
            hostname = ''
            state = ''
            print("")
            print_neutral()
            print("Scanning host", host[1])
            scanner.scan(hosts=host[1], arguments='-A -p-')
            try:
                state = print_host_up(scanner[host[1]].state())
            except:
                state = print_host_down()
            if state == 'up':
                try:
                    hostname = print_hostname_exists(scanner[host[1]].hostname())
                except:
                    hostname = print_hostname_not_exists()
            write_host(state,hostname,host[0],database,cursor)
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
                    if scanner[host[1]].has_tcp(port) or scanner[host[1]].has_udp(port): #Host[1] = ip address
                        print("Found port")
                        proto = protocol_type(scanner, host[1], port)
                        try:
                            state = scanner[host[1]][proto][port]['state']
                        except:
                            pass
                        try:
                            service_name = scanner[host[1]][proto][port]['name']
                        except:
                            pass
                        try:
                            service_version = scanner[host[1]][proto][port]['product']
                        except:
                            pass
                        try:
                            service_info = scanner[host[1]][proto][port]['extrainfo']
                        except:
                            pass

                        update = new_service(port,host[0],database,cursor)
                        if not update:
                            print_positive()
                            print("Found new service:",service_name,"\tVersion:",service_version,"\tPort:",port,"\tState:",state)
                            insert_service_row(host[0],port,proto,service_name,service_product,service_version,service_info,state,database,cursor)
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
                            update_service_row(service_name,service_product,service_version,service_info,host[0],port,database,cursor)
                if service_discovery:
                    print_discovery(ports,protocols,names,products,versions,infos)
        free_hosts(host_list,cursor,database)
    except:
        free_hosts(host_list,cursor,database)
        cursor.close()
        database.close()
        sys.exit('Scan Failed... Time to debug this shit lmao\n')
        pass
