PRO_MODBUS = "Modbus"
PRO_HART_IP = "Hart/IP"
PRO_FINS = "FINS"
PRO_ADS_AMS = "ADS/AMS"
PRO_BACNET_APDU = "BACnet-APDU"
PRO_S7 = "S7COMM"
PRO_SV = "IEC61850/SV"
PRO_GOOSE = "IEC61850/GOOSE"
PRO_MMS = "IEC61850/MMS"
PRO_IEC104 = "IEC104"
PRO_CIP = "CIP"
PRO_ENIP = "ENIP"
PRO_DNP3 = "DNP3"
PRO_OPCUA = "OpcUA"
PRO_OPCDA = "OpcDA"
PRO_OPCAE = "OpcAE"
PRO_UMAS = "Umas"
PRO_FOX = "Fox"
PRO_PROFINET = "Profinet"
PRO_PROFINET_DCP = "Profinet/DCP"
PRO_PROFINET_IO = "Profinet/IO"
PRO_PROFINET_RT = "Profinet/RT"
PRO_PROFINET_IRT = "Profinet/IRT"
PRO_PROFINET_PTCP = "Profinet/PTCP"

PRO_ETHERNET = "Ethernet"
PRO_IP = "IP"
PRO_TCP = "TCP"
PRO_UDP = "UDP"

GROUP_NAME_DICT = dict(
    Admin='管理员',
    Security_Engineer='安全工程师',
    Auditor='审计员',
    Config_Engineer='配置工程师',
)

# 资产类型
TYPE_UNKNOWN = 0
FIRE_WALL = 1
AUDITOR = 2
GATEKEEPER = 3
IDS = 4
IPS = 5
SCANNER = 6

EXCHANGER = 7
ROUTER = 8

WORKSERVER = 9
WORKSTATION = 10
SERVER = 11

PLC = 12

DEV_TEMP_TYPE_CHOICES = (
    (FIRE_WALL, '防火墙'),
    (AUDITOR, '审计'),
    (GATEKEEPER, '网闸'),
    (IDS, 'IDS'),
    (IPS, 'IPS'),
    (SCANNER, '漏洞扫描'),
    (EXCHANGER, '交换机'),
    (ROUTER, '路由器'),
    (WORKSERVER, '工作主机'),
    (WORKSTATION, '工作站'),
    (SERVER, '服务器'),
    (PLC, 'PLC'),
    (TYPE_UNKNOWN, '其他'),
)

# 资产类别
CATEGORY_Security = 1
CATEGORY_Communication = 2
CATEGORY_Sever = 3
CATEGORY_Control = 4
CATEGORY_Other = 99

CATEGORY_CHOICE = (
    (CATEGORY_Security, '安全资产'),
    (CATEGORY_Communication, '网络资产'),
    (CATEGORY_Sever, '主机资产'),
    (CATEGORY_Control, '工控资产'),
)

CATEGORY_DICT = {
    '安全资产': 'security',
    '网络资产': 'network',
    '主机资产': 'server',
    '工控资产': 'control',
}

TYPE_DICT = {
    '防火墙': 'firewall',
    '审计': 'audit',
    '网闸': 'gatekeeper',
    'IDS': 'ids',
    'IPS': 'ips',
    '漏洞扫描': 'scanner',
    '其他': 'other',
}

# Rsyslog facility和对应的编号
SYSLOG_FACILITY = {
    0: 'kern',
    1: 'user',
    2: 'mail',
    3: 'daemon',
    4: 'auth',
    5: 'syslog',
    6: 'lpr',
    9: 'cron',
    10: 'authpriv',
    11: 'ftp',
    16: 'local0',
    17: 'local1',
    18: 'local2',
    19: 'local3',
    20: 'local4',
    21: 'local5',
    22: 'local6',
    23: 'local7',
}

NETWORK_STATUS = {
    'success': 0,
    'failure': 1,
    'link beat detected': 2,
    'unplugged': 3,
}
