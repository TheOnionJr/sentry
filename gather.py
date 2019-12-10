import nmap, psycopg2, datetime, yaml, sys, time

hosts_pr_session = 32

#############Functions###############
def create_database_connection():
    with open('creds.yaml', 'r') as file:
        doc = yaml.load(file, Loader=yaml.FullLoader)
    db_host = doc['host']
    db_name = doc['database']
    db_user = doc['user']
    db_user_password = doc['password']
    return psycopg2.connect(host=db_host,database=db_name,user=db_user,password=db_user_password)

def create_database_cursor(database):
    return database.cursor()

def write_to_db(host, scan_result):
    #Create database connection:
    database = create_database_connection()
    cursor = create_database_cursor(database)

    state = ''
    hostname = ''

    try:
        state = scan_result['scan'][host]['status']['state']
    except:
        state = 'down'

    try:
        hostname = scan_result['scan'][host]['hostnames'][0]['name']
    except:
        hostname = None

    print_green("[+] ")
    print("IP address:", host)
    print_green("[+] ")
    print("Hostname:", hostname)
    if state == 'up':
        print_green("[+] ")
    else:
        print_red("[-] ")
    print("State:", state, "\n")
    psql_statement = "UPDATE host SET state = '{0}', hostname = '{1}', reserved = false, priority = false, recently_added = true, last_scan = NOW() WHERE ip_addr = '{2}'".format(state,hostname,host)
    cursor.execute(psql_statement)
    database.commit()

    try:
        for port in  scan_result['scan'][host]['tcp'].keys():
            name = '-'
            product = '-'
            version = '-'
            info = '-'
            state = '-'
            protocol = 'tcp'
            try:
                name = scan_result['scan'][host]['tcp'][port]['name']
            except:
                pass
            try:
                product = scan_result['scan'][host]['tcp'][port]['product']
            except:
                pass
            try:
                version = scan_result['scan'][host]['tcp'][port]['version']
            except:
                pass
            try:
                info = scan_result['scan'][host]['tcp'][port]['extrainfo']
            except:
                pass
            try:
                state = scan_result['scan'][host]['tcp'][port]['state']
            except:
                pass
            print_blue("[*] ")
            print("Host:",host,"Port:",port,"State:",state,"Name:",name,"Product:",product,"Version:",version)
            try:
                psql_statement = "INSERT INTO service (host, port, protocol, name, product, version, info, state) VALUES ('{0}',{1},'{2}','{3}','{4}','{5}','{6}','{7}') ON CONFLICT (host,port) DO UPDATE SET protocol = EXCLUDED.protocol, name = EXCLUDED.name, product = EXCLUDED.product, version = EXCLUDED.version, info = EXCLUDED.info, state = EXCLUDED.state".format(host,port,protocol,name,product,version,info,state)
                cursor.execute(psql_statement)
                database.commit()
            except:
                pass
    except:
        pass
    cursor.close()
    database.close()
    free_host(host)


def find_scannable_hosts():
    #Find 32 hosts to scan that are not reserved
    database = create_database_connection()
    cursor = create_database_cursor(database)
    psql_statement = "SELECT id, ip_addr FROM host WHERE reserved = false ORDER BY priority DESC, recently_added DESC, last_scan ASC FETCH FIRST {0} ROWS only".format(1)
    cursor.execute(psql_statement)
    hosts = cursor.fetchall()

    #Set hosts to reserved
    for row in hosts:
        psql_statement = "UPDATE host SET reserved = true WHERE id = {0}".format(row[0])
        cursor.execute(psql_statement)
        database.commit()
        return row[1]

def free_host(host):
    database = create_database_connection()
    cursor = create_database_cursor(database)
    psql_statement = "UPDATE host set reserved = false, recently_added = false, priority = false WHERE ip_addr = '{0}'".format(host)
    cursor.execute(psql_statement)
    database.commit()

def scans_comlete(scanner_list):
    index = 0
    for session in scanner_list:
        if not session.still_scanning():
            return int(index)
        index = index + 1




#####COLORS#####
def print_red(text):
    print("\033[91m {}\033[00m" .format(text), end = '')

def print_green(text):
    print("\033[92m {}\033[00m" .format(text), end = '')

def print_blue(text):
    print("\033[96m {}\033[00m" .format(text), end = '')

def print_positive(text):
    print_green("[+] ")
    print(text)

def print_neutral(text):
    print_blue("[*] ")
    print(text)

def print_negative(text):
    print_red("[-] ")
    print(text)



######################Main######################
while True:
    scanner_list = []

    for num in range(hosts_pr_session):
        scanner_list.append(nmap.PortScannerAsync())
        scanner_list[num].scan(hosts=find_scannable_hosts(), arguments = '-A -p-', callback=write_to_db)

    while True:
        i = scans_comlete(scanner_list)
        if i is not None:
            scanner_list[i].scan(hosts=find_scannable_hosts(), arguments = '-A -p-', callback=write_to_db)
