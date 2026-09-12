"""Curated list of commonly-scanned TCP ports for the native scanner.

This is a pragmatic, hand-curated set covering well-known services,
common web/proxy ports, and frequently-exposed infrastructure ports
(databases, remote access, container/orchestration APIs). It is *not*
a reproduction of nmap's proprietary frequency-ranked ``--top-ports``
list - the Nmap adapter (Task 4) asks nmap itself for its top-1000
ports rather than duplicating that data here.
"""

COMMON_PORTS: list[int] = [
    21,  # FTP
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS
    69,  # TFTP
    80,  # HTTP
    88,  # Kerberos
    110,  # POP3
    111,  # rpcbind
    113,  # ident
    119,  # NNTP
    123,  # NTP
    135,  # MSRPC
    137,  # NetBIOS Name Service
    138,  # NetBIOS Datagram
    139,  # NetBIOS Session (SMB)
    143,  # IMAP
    161,  # SNMP
    162,  # SNMP trap
    179,  # BGP
    194,  # IRC
    389,  # LDAP
    427,  # SLP
    443,  # HTTPS
    445,  # SMB
    465,  # SMTPS
    500,  # IKE/IPsec
    512,  # rexec
    513,  # rlogin
    514,  # syslog / rsh
    515,  # LPD/printer
    520,  # RIP
    548,  # AFP
    554,  # RTSP
    587,  # SMTP submission
    593,  # HTTP RPC Ep Map
    631,  # IPP/CUPS
    636,  # LDAPS
    646,  # LDP
    691,  # MS Exchange routing
    860,  # iSCSI
    873,  # rsync
    902,  # VMware ESXi
    989,  # FTPS data
    990,  # FTPS control
    993,  # IMAPS
    995,  # POP3S
    1025,  # NFS/MS RPC
    1026,  # MS RPC
    1027,  # MS RPC
    1080,  # SOCKS proxy
    1099,  # Java RMI
    1194,  # OpenVPN
    1214,  # Kazaa
    1241,  # Nessus
    1311,  # Dell OpenManage
    1337,  # WASTE / misc
    1352,  # Lotus Notes
    1433,  # MSSQL
    1434,  # MSSQL Monitor
    1521,  # Oracle DB
    1589,  # Cisco VQP
    1701,  # L2TP
    1723,  # PPTP
    1755,  # MS Media Server
    1812,  # RADIUS
    1813,  # RADIUS accounting
    1883,  # MQTT
    1900,  # UPnP/SSDP
    2000,  # Cisco SCCP
    2049,  # NFS
    2082,  # cPanel
    2083,  # cPanel SSL
    2086,  # WHM
    2087,  # WHM SSL
    2095,  # Webmail
    2096,  # Webmail SSL
    2181,  # ZooKeeper
    2222,  # DirectAdmin/alt SSH
    2375,  # Docker (unencrypted)
    2376,  # Docker (TLS)
    2483,  # Oracle DB (SSL)
    2484,  # Oracle DB
    2601,  # Zebra/Quagga
    2604,  # Zebra/Quagga
    3000,  # common dev/web app
    3128,  # Squid proxy
    3268,  # LDAP GC
    3269,  # LDAPS GC
    3283,  # Apple Remote Desktop
    3306,  # MySQL
    3389,  # RDP
    3690,  # SVN
    4040,  # Spark UI / common web app
    4369,  # Erlang port mapper
    4443,  # alt HTTPS
    4444,  # Metasploit/common backdoor
    4505,  # SaltStack
    4506,  # SaltStack
    4567,  # common web app
    4664,  # Google Desktop
    5000,  # UPnP/common dev/web app
    5001,  # common dev/web app
    5060,  # SIP
    5061,  # SIP TLS
    5222,  # XMPP
    5269,  # XMPP server-to-server
    5353,  # mDNS
    5432,  # PostgreSQL
    5555,  # Android ADB/common
    5601,  # Kibana
    5672,  # AMQP/RabbitMQ
    5900,  # VNC
    5901,  # VNC alt
    5984,  # CouchDB
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    6000,  # X11
    6379,  # Redis
    6443,  # Kubernetes API
    6660,  # IRC
    6666,  # IRC/misc
    6667,  # IRC
    6697,  # IRC SSL
    7000,  # Cassandra
    7001,  # Cassandra SSL / WebLogic
    7077,  # Spark master
    7199,  # Cassandra JMX
    7474,  # Neo4j HTTP
    7687,  # Neo4j Bolt
    8000,  # common dev/web app
    8008,  # common HTTP alt
    8080,  # HTTP proxy/common web app
    8081,  # common web app
    8086,  # InfluxDB
    8088,  # common web app
    8089,  # Splunk
    8090,  # common web app
    8091,  # Couchbase
    8140,  # Puppet
    8161,  # ActiveMQ
    8172,  # web deploy
    8200,  # Vault
    8222,  # common web app
    8300,  # Consul
    8333,  # Bitcoin
    8443,  # HTTPS alt
    8500,  # Consul UI
    8530,  # WSUS
    8531,  # WSUS SSL
    8834,  # Nessus web
    8888,  # common dev/web app
    9000,  # SonarQube/common dev
    9001,  # Tor/common dev
    9042,  # Cassandra CQL
    9090,  # Prometheus
    9092,  # Kafka
    9100,  # printer/JetDirect
    9200,  # Elasticsearch
    9300,  # Elasticsearch transport
    9418,  # git
    9999,  # common dev/web app
    10000,  # Webmin
    11211,  # Memcached
    15672,  # RabbitMQ management
    27017,  # MongoDB
    27018,  # MongoDB shard
    50000,  # SAP/common
]

PORT_NAMES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    113: "ident",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    194: "irc",
    389: "ldap",
    427: "slp",
    443: "https",
    445: "smb",
    465: "smtps",
    500: "ike",
    512: "exec",
    513: "login",
    514: "syslog",
    515: "printer",
    520: "rip",
    548: "afp",
    554: "rtsp",
    587: "submission",
    593: "http-rpc-epmap",
    631: "ipp",
    636: "ldaps",
    646: "ldp",
    691: "msexchange-routing",
    860: "iscsi",
    873: "rsync",
    902: "vmware-esxi",
    989: "ftps-data",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1025: "nfs-or-msrpc",
    1026: "msrpc",
    1027: "msrpc",
    1080: "socks",
    1099: "java-rmi",
    1194: "openvpn",
    1214: "kazaa",
    1241: "nessus",
    1311: "dell-openmanage",
    1337: "waste",
    1352: "lotusnotes",
    1433: "mssql",
    1434: "mssql-monitor",
    1521: "oracle",
    1589: "cisco-vqp",
    1701: "l2tp",
    1723: "pptp",
    1755: "ms-media-server",
    1812: "radius",
    1813: "radius-acct",
    1883: "mqtt",
    1900: "upnp",
    2000: "cisco-sccp",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2086: "whm",
    2087: "whm-ssl",
    2095: "webmail",
    2096: "webmail-ssl",
    2181: "zookeeper",
    2222: "ssh-alt",
    2375: "docker",
    2376: "docker-ssl",
    2483: "oracle-ssl",
    2484: "oracle-tcps",
    2601: "zebra",
    2604: "zebra",
    3000: "http-alt",
    3128: "squid-proxy",
    3268: "ldap-gc",
    3269: "ldaps-gc",
    3283: "apple-remote-desktop",
    3306: "mysql",
    3389: "rdp",
    3690: "svn",
    4040: "spark-ui",
    4369: "epmd",
    4443: "https-alt",
    4444: "krb524/backdoor",
    4505: "saltstack-master",
    4506: "saltstack-return",
    4567: "http-alt",
    4664: "google-desktop",
    5000: "upnp/http-alt",
    5001: "http-alt",
    5060: "sip",
    5061: "sip-tls",
    5222: "xmpp-client",
    5269: "xmpp-server",
    5353: "mdns",
    5432: "postgresql",
    5555: "adb",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5901: "vnc-alt",
    5984: "couchdb",
    5985: "winrm",
    5986: "winrm-ssl",
    6000: "x11",
    6379: "redis",
    6443: "kubernetes-api",
    6660: "irc",
    6666: "irc-alt",
    6667: "irc",
    6697: "irc-ssl",
    7000: "cassandra",
    7001: "cassandra-ssl",
    7077: "spark-master",
    7199: "cassandra-jmx",
    7474: "neo4j-http",
    7687: "neo4j-bolt",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8086: "influxdb",
    8088: "http-alt",
    8089: "splunk",
    8090: "http-alt",
    8091: "couchbase",
    8140: "puppet",
    8161: "activemq",
    8172: "web-deploy",
    8200: "vault",
    8222: "http-alt",
    8300: "consul-server",
    8333: "bitcoin",
    8443: "https-alt",
    8500: "consul-ui",
    8530: "wsus",
    8531: "wsus-ssl",
    8834: "nessus-web",
    8888: "http-alt",
    9000: "sonarqube",
    9001: "tor-orport",
    9042: "cassandra-cql",
    9090: "prometheus",
    9092: "kafka",
    9100: "jetdirect",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    9418: "git",
    9999: "http-alt",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq-management",
    27017: "mongodb",
    27018: "mongodb-shard",
    50000: "sap",
}
