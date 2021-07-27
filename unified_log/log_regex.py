"""
日志解析规则库
"""
regex_dict = {
    'auth': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
            r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?: '
            r'(.*?(from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<src_port>\d+)).*?'
            r'|.*?)',
    'authpriv': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
                r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
                r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?: '
                r'(.*?(from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<src_port>\d+)).*?'
                r'|.*?)',
    'kern': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
            r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?: '
            r'.*?IN=(?P<in_network>.*?) OUT=(?P<out_network>.*?) MAC=(?P<src_mac>.*?) '
            r'SRC=(?P<src_ip>.*?) DST=(?P<dst_ip>.*?) .*?'
            r'PROTO=(?P<protocol>.*?) SPT=(?P<src_port>\d+) DPT=(?P<dst_port>\d+)',
    'daemon': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
              r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
              r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?: '
              r'(.*?Connection from (?P<protocol>.*?): '
              r'\[(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})]:(?P<src_port>\d+)->'
              r'\[(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})]:(?P<dst_port>\d+).*?'
              r'|.*?)',
    'cron': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
            r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?',
    'syslog': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
              r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
              r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?'
              r'(.*?connect to (?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<dst_port>\d+).*?|.*?)',
    'audit-alarm': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
                   r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
                   r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?'
                   r'\{devid: (?P<device_id>\d+), date: (?P<audit_date>.*?), '
                   r'dname: (?P<device_name>.*?), logtype: (?P<audit_logtype>\d+), '
                   r'pri: (?P<audit_pri>\d+), mod: (?P<audit_mod>.*?), '
                   r'src_ip: (?P<src_ip>.*?), src_mac: (?P<src_mac>.*?), '
                   r'dst_mac: (?P<dst_mac>.*?), src_port: (?P<src_port>.*?), '
                   r'dst_ip: (?P<dst_ip>.*?), dst_port: (?P<dst_port>\d+), '
                   r'protocol: (?P<protocol>.*?), dsp_msg: (?P<audit_msg>.*?)}',
    'nginx': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<hostname>.*?) '
             r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<facility>\d{1,2}) '
             r'(?P<level>\d{1,2}).*?((?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - '
             r'(?P<remote_user>.*?) \[(?P<nginx_date>.*?)] "(?P<request>.*?)" '
             r'(?P<status_code>\d*) (?P<body_bytes_sent>\d*) "(?P<http_referer>.*?)" '
             r'"(?P<http_user_agent>.*?)"|(?P<nginx_date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?'
             r'client: (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?request: '
             r'"(?P<request>.*?)", upstream: "(?P<upstream>.*?)", '
             r'host: "(?P<host>.*?)"(, referrer: "(?P<http_referer>.*?)")?|'
             r'(?P<nginx_date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?'
             r'(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<src_port>\d*)|'
             r'(?P<nginx_date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?)',
    'mail': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
            r'(?P<facility>\d{1,2}) (?P<level>\d{1,2})'
            r'(.*?\[(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})]|.*?)',
    'ftp': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
           r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
           r'(?P<facility>\d{1,2}) (?P<level>\d{1,2})'
           r'(.*?host=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|.*?)',
    'huawei_switch': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
                     r' (?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                     r' (?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?'
                     r'(Ip=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),'
                     r' VpnName=(?P<vpn_name>.*?), User=(?P<user>.*?), '
                     r'AuthenticationMethod="(?P<auth_method>.*?)", '
                     r'Command="(?P<command>.*?)"|UserName=(?P<user>.*?), '
                     r'IPAddress=(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), '
                     r'VpnName=(?P<vpn_name>.*?)(, Info=(?P<info>.*?)\)| ?\))|'
                     r'DEVICEMAC:(?P<dst_mac>.*?);DEVICENAME:(?P<device_name>.*?);'
                     r'USER:(?P<user>.*?);MAC:(?P<src_mac>.*?);IPADDRESS:'
                     r'(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?)',
    'database_postgres': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
                         r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                         r' (?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?((LOG:.*?address "'
                         r'(?P<src_ip>.*?)", port (?P<src_port>\d+).*?|STATEMENT:  '
                         r'(?P<sql>.*)|(ERROR|FATAL|LOG):  (?P<error>.*))|]  (?P<sql>.*))',
}

ASUS_ROUTER = {
    'kern': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
            r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?',
    'user': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
            r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?wlceventd_proc_event.*?: '
            r'(?P<in_network>.*?): \w+ (?P<src_mac>.*?), status: (?P<status_code>\d+), '
            r'reason: (?P<reason>.*)',
    'daemon': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<hostname>.*?)'
              r' (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<facility>\d{1,2}) '
              r'(?P<level>\d{1,2})(.*?(?P<DHCP>DHCPDISCOVER).*? (?P<src_mac>.*?) '
              r'(?P<device_name>.*)|.*?(?P<DHCP>DHCPOFFER).*? '
              r'(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<dst_mac>.*?)'
              r' (?P<device_name>.*)|.*?(?P<DHCP>DHCPREQUEST).*? '
              r'(?P<requested_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<src_mac>.*?) '
              r'(?P<device_name>.*)|.*?(?P<DHCP>DHCPACK).*? '
              r'(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<dst_mac>.*?)'
              r' (?P<device_name>.*)|.*?)',
    'authpriv': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
                r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
                r'(?P<facility>\d{1,2}) (?P<level>\d{1,2})'
                r'(.*?from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):'
                r'(?P<src_port>\d+)|.*?)',
    'local0': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
              r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
              r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?'
              r'((.*?Function: (?P<function>.*?) Source: (?P<source>.*?) .*?)|.*?)',
}

WINDOWS = {
    'local0': r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
              r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
              r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*? '
              r'((.*?Exe: (?P<application>.*?exe).*?)|(.*?(sid:(?P<sid>.*?))? '
              r'Function: (?P<function>.*?) Source: (?P<source>.*))|.*?)',
}
