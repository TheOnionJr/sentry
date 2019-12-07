CREATE TABLE auto_system (
  id SERIAL NOT NULL,
  name varchar(250),
  PRIMARY KEY (id)
);

CREATE TABLE host (
  id SERIAL NOT NULL,
  ip_addr varchar(15),
  auto_sys SERIAL,
  state varchar(10),
  last_scan varchar(255),
  os_name varchar(255),
  os_flavour varchar(10),
  hostname varchar(255),
  PRIMARY KEY (id),
  FOREIGN KEY (auto_sys) REFERENCES auto_system(id)
);

CREATE TABLE service (
  id SERIAL NOT NULL,
  state varchar(10),
  host SERIAL NOT NULL,
  port int,
  protocol varchar(10),
  name varchar(255),
  product varchar(255),
  version varchar(255),
  info varchar(255),
  PRIMARY KEY (id),
  FOREIGN KEY (host) REFERENCES host(id)
);
