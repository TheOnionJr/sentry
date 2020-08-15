CREATE TABLE auto_system (
  id SERIAL NOT NULL,
  name varchar(250),
  PRIMARY KEY (id)
);

CREATE TABLE host (
  id SERIAL NOT NULL,
  ip_addr varchar(15) UNIQUE,
  auto_sys SERIAL,
  state varchar(10),
  last_scan timestamp DEFAULT NOW(),
  os_name varchar(255),
  os_flavour varchar(10),
  hostname varchar(255),
  reserved boolean DEFAULT false,
  priority boolean DEFAULT false,
  recently_added boolean DEFAULT true,
  PRIMARY KEY (id),
);

CREATE TABLE service (
  id SERIAL NOT NULL,
  state varchar(10),
  host varchar(15) NOT NULL,
  port int,
  protocol varchar(10),
  name varchar(255),
  product varchar(255),
  version varchar(255),
  info varchar(255),
  PRIMARY KEY (host,port),
  FOREIGN KEY (host) REFERENCES host(ip_addr)
);

CREATE TABLE script (
  id SERIAL NOT NULL,
  service_id int NOT NULL,
  index varchar(250),
  result TEXT,
  PRIMARY KEY (id),
  FOREIGN KEY (service_id) REFERENCES service(id)
);
