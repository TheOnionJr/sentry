import nmap, psycopg2, datetime, yaml, sys, time

#############Functions###############
def get_conf_var(var_name_list):
    var_value_list = []
    with open('config.yaml', 'r') as file:
        doc = yaml.load(file, Loader=yaml.FullLoader)
    for variable in var_name:
        var_value_list.append(doc[variable])
    return var_value_list

def create_database_connection():
    var_value_list = get_conf_var(var_name_list = ['host','database','user','password'])
    db_host = var_value_list[0]
    db_name = var_value_list[1]
    db_user = var_value_list[2]
    db_pass = var_value_list[3]
    return psycopg2.connect(host=db_host,database=db_name,user=db_user,password=db_user_password)

def create_database_cursor(database):
    return database.cursor()

def write_to_db(host, scan_result):
    #Create database connection:
    database = create_database_connection()
    cursor = create_database_cursor(database)

    state = ''
    hostname = ''

    print_positive(host)
    try:
        hostname = print_positive(scan_result['scan'][host]['hostnames'][0]['name'])
    except:
        hostname = None
    try:
        state = print_positive(scan_result['scan'][host]['status']['state'])
    except:
        state = 'down'

    update_host(host,state,hostname)
    protocols = ['tcp','udp']
    try:
        for protocol in protocols:
            try:
                for port in  scan_result['scan'][host][protocol].keys():
                    key_list = []
                    try:
                        key_list[0] = scan_result['scan'][host]['tcp'][port]['name']
                    except:
                        key_list[0] = None
                    try:
                        key_list[1] = scan_result['scan'][host]['tcp'][port]['product']
                    except:
                        key_list[1] = None
                    try:
                        key_list[2] = scan_result['scan'][host]['tcp'][port]['version']
                    except:
                        key_list[2] = None
                    try:
                        key_list[3] = scan_result['scan'][host]['tcp'][port]['extrainfo']
                    except:
                        key_list[3] = None
                    try:
                        key_list[4] = scan_result['scan'][host]['tcp'][port]['state']
                    except:
                        key_list[4] = None
                    print_blue("[*] ")
                    print("Host:",host,"Port:",port,"State:",state,"Name:",key_list[0],"Product:",key_list[1],"Version:",key_list[2])
                    try:
                        psql_statement = "INSERT INTO service (host, port, protocol, name, product, version, info, state) VALUES ('{0}',{1},'{2}','{3}','{4}','{5}','{6}','{7}') ON CONFLICT (host,port) DO UPDATE SET protocol = EXCLUDED.protocol, name = EXCLUDED.name, product = EXCLUDED.product, version = EXCLUDED.version, info = EXCLUDED.info, state = EXCLUDED.state".format(host,port,protocol,key_list[0],key_list[1],key_list[2],key_list[3],key_list[4])
                        cursor.execute(psql_statement)
                        database.commit()
                    except:
                        pass
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

def update_host(host,hostname,state):
    psql_statement = "UPDATE host SET state = '{0}', hostname = '{1}', reserved = false, priority = false, recently_added = true, last_scan = NOW() WHERE ip_addr = '{2}'".format(state,hostname,host)
    cursor.execute(psql_statement)
    database.commit()

def scans_comlete(scanner_list):
    index = 0
    for session in scanner_list:
        if not session.still_scanning():
            return int(index)
        index = index + 1



#####PRINT FUNCTIONS#####
def print_positive(variable):
    print_green("[+] ")
    print(variable)
    return variable

def print_neutral(variable):
    print_blue("[*] ")
    print(variable)
    return variable

def print_negative(variable):
    print_red("[-] ")
    print(variable)
    return variable


#####COLORS#####
def print_red(text):
    print("\033[91m {}\033[00m" .format(text), end = '')

def print_green(text):
    print("\033[92m {}\033[00m" .format(text), end = '')

def print_blue(text):
    print("\033[96m {}\033[00m" .format(text), end = '')





######################Main######################
hosts_pr_session = get_conf_var(args = ['hosts_pr_session'])
while True:
    scanner_list = []
    arguments = '-sS -sU -A -p-'
    for num in range(hosts_pr_session):
        scanner_list.append(nmap.PortScannerAsync())
        scanner_list[num].scan(hosts=find_scannable_hosts(), arguments = arguments, callback=write_to_db)

    while True:
        i = scans_comlete(scanner_list)
        if i is not None:
            scanner_list[i].scan(hosts=find_scannable_hosts(), arguments = arguments, callback=write_to_db)
