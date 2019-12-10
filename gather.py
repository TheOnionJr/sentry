import nmap, psycopg2, datetime, yaml, sys

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

    #Find id
    psql_statement = "SELECT id from host WHERE ip_addr = "
    state = ''
    hostname = ''
    try:
        state = scan_result['scan'][host]['status']['state']
    except:
        state = 'down'
    try:
        hostname = scan_result['scan'][host]['hostnames'[0]]['name']
    except:
        hostname = None
    print(state,hostname)
    psql_statement = "UPDATE host SET state = '{0}', hostname = '{1}', reserved = false, priority = false, recently_added = true, last_scan = NOW() WHERE ip_addr = '{2}'".format(state,hostname,host)
    cursor.execute(psql_statement)

    try:
        for port in  scan_result['scan'][host]['tcp'].keys():
            name = ''
            product = ''
            version = ''
            info = ''
            state = ''
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
            psql_statement = "INSER INTO service (host, port, protocol, name, product, version, info, state) VALUES ('{0}',{1},{2},{3},{4},{5},{6},{7}) ON CONFLICT (host,port) UPDATE SET protocol = EXCLUDED.protocol, name = EXCLUDED.name, product = EXCLUDED.product, version = EXCLUDED.version, info = EXCLUDED.info, state = EXCLUDED.state".format(host,port,protocol,name,product,version,info,state)
            cursor.execute(psql_statement)
    except:
        pass
    database.commit()
    cursor.close()
    database.close()

def find_scannable_hosts(hosts_pr_session):
    #Find 32 hosts to scan that are not reserved
    database = create_database_connection()
    cursor = create_database_cursor(database)
    psql_statement = "SELECT id, ip_addr FROM host WHERE reserved = false ORDER BY priority DESC, recently_added DESC, last_scan ASC FETCH FIRST {0} ROWS only".format(hosts_pr_session)
    cursor.execute(psql_statement)
    hosts = cursor.fetchall()

    #Set hosts to reserved
    for row in hosts:
        psql_statement = "UPDATE host SET reserved = true WHERE id = {0}".format(row[0])
        cursor.execute(psql_statement)

    database.commit()
    return hosts

def scans_still_running(scanner_list):
    session_still_running = False
    for session in scanner_list:
        if session.still_scanning():
            session_still_running = True
    return session_still_running



#####COLORS#####
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

######################Main######################
while True:
    scanner_list = []
    hosts = find_scannable_hosts(hosts_pr_session)

    for num in range(hosts_pr_session):
        scanner_list.append(nmap.PortScannerAsync())
        scanner_list[num].scan(hosts=hosts[num][1], arguments = '-A -p-', callback=write_to_db)

    while scans_still_running(scanner_list):
        time.sleep(2)
