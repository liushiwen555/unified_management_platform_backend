import regex as re

import pytest

from unified_log.log_process import LogProcess
from unified_log.tests.test_log_process import BaseTest
from unified_log.log_regex import regex_dict


@pytest.mark.django_db
class Rule(BaseTest):
    rule = None
    pattern = None
    target = []

    def test_rule(self, log, target):
        result = self.pattern.match(log).groupdict()
        process = LogProcess(log)
        process.process()
        process.save()

        for i, t in enumerate(self.target):
            assert result.get(t) == target[i]


class TestAuthRule(Rule):
    rule = (r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
            r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?: '
            r'(.*?(from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<src_port>\d+)).*?'
            r'|.*?)')
    pattern = re.compile(rule)
    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'src_ip',
              'src_port']

    logs = [
        '2020-10-14 10:05:27 ubuntu 192.168.0.58 4 6 systemd-logind[892]:  Removed session 11.',
        '2020-10-14 18:05:20 bolean 192.168.0.58 4 6 sshd[16224]:  pam_unix(sshd:session): session closed for user bolean',
        '2020-10-14 18:06:51 bolean 192.168.0.58 4 6 sshd[15813]:  Received disconnect from 192.168.0.40 port 53566:11: disconnected by user'
    ]

    @pytest.mark.parametrize(
        'log, target',
        [
            (logs[0],
             ['2020-10-14 10:05:27', 'ubuntu', '192.168.0.58', '4', '6', None,
              None]),
            (logs[1],
             ['2020-10-14 18:05:20', 'bolean', '192.168.0.58', '4', '6', None,
              None]),
            (logs[2],
             ['2020-10-14 18:06:51', 'bolean', '192.168.0.58', '4', '6',
              '192.168.0.40', '53566']),
        ]
    )
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestAuthPrivRule(Rule):
    rule = (r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
            r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?: '
            r'(.*?(from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<src_port>\d+)).*?'
            r'|.*?)')
    pattern = re.compile(rule)
    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'src_ip',
              'src_port']

    logs = [
        '2020-10-14 18:05:20 bolean 192.168.0.58 10 6 sshd[16224]:  pam_unix(sshd:session): session closed for user bolean',
    ]

    @pytest.mark.parametrize(
        'log, target',
        [
            (logs[0],
             ['2020-10-14 18:05:20', 'bolean', '192.168.0.58', '10', '6', None,
              None]),
        ]
    )
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestKernRule(Rule):
    pattern = re.compile(regex_dict['kern'])

    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'src_ip',
              'src_port', 'src_mac', 'dst_ip', 'dst_port',
              'in_network', 'out_network', 'protocol']
    logs = [
        '2020-11-09 09:29:20 bolean 192.168.0.58 0 4 kernel: [424986.231722] [UFW BLOCK] IN=enp2s0 OUT= MAC=33:33:00:00:00:01:00:0c:29:a0:0c:6b:86:dd SRC=fe80:0000:0000:0000:020c:29ff:fea0:0c6b DST=ff02:0000:0000:0000:0000:0000:0000:0001 LEN=64 TC=0 HOPLIMIT=1 FLOWLBL=591183 PROTO=UDP SPT=8612 DPT=8612 LEN=24'
    ]

    targets = [
        (logs[0], ['2020-11-09 09:29:20', 'bolean', '192.168.0.58', '0', '4',
                   'fe80:0000:0000:0000:020c:29ff:fea0:0c6b',
                   '8612', '33:33:00:00:00:01:00:0c:29:a0:0c:6b:86:dd',
                   'ff02:0000:0000:0000:0000:0000:0000:0001', '8612',
                   'enp2s0', '', 'UDP'])
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super(TestKernRule, self).test_rule(log, target)


class TestDaemonRule(Rule):
    pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
        r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
        r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?: '
        r'(.*?Connection from (?P<protocol>.*?): '
        r'\[(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})]:(?P<src_port>\d+)->'
        r'\[(?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})]:(?P<dst_port>\d+).*?'
        r'|.*?)'
    )

    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'protocol',
              'src_ip', 'src_port', 'dst_ip', 'dst_port']

    logs = [
        '2020-10-20 13:53:36 bolean 192.168.0.58 3 6 snmpd[900]:  message repeated 5 times: [ Connection from UDP: [192.168.0.58]:35479->[192.168.0.58]:161]',
        "2020-10-20 13:52:48 bolean 192.168.0.58 3 6 supervisord[1500]:  2020-10-20 13:52:48,630 INFO spawned: 'snmp_check' with pid 13806",
        '2020-10-20 14:04:16 bolean 192.168.0.58 3 6 snmpd[900]:  Connection from UDP: [192.168.1.205]:58491->[255.255.255.255]:161',
        '2020-10-20 14:17:02 bolean 192.168.0.58 3 6 supervisord[1500]:  2020-10-20 14:17:02,124 INFO success: snmp_check entered RUNNING state, process has stayed up for > than 3 seconds (startsecs)',
    ]

    @pytest.mark.parametrize(
        'log, target',
        [
            (logs[0], ['2020-10-20 13:53:36', 'bolean', '192.168.0.58', '3',
                       '6', 'UDP', '192.168.0.58', '35479', '192.168.0.58',
                       '161']),
            (logs[1], ['2020-10-20 13:52:48', 'bolean', '192.168.0.58', '3',
                       '6', None, None, None, None, None]),
            (logs[2], ['2020-10-20 14:04:16', 'bolean', '192.168.0.58', '3',
                       '6', 'UDP', '192.168.1.205', '58491', '255.255.255.255',
                       '161']),
            (logs[3], ['2020-10-20 14:17:02', 'bolean', '192.168.0.58', '3',
                       '6', None, None, None, None, None]),
        ]
    )
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestSyslogRule(Rule):
    pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
        r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
        r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?'
        r'(.*?connect to (?P<dst_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<dst_port>\d+).*?|.*?)'
    )
    target = ['timestamp', 'hostname', 'ip', 'facility', 'level',
              'src_ip', 'src_port', 'dst_ip', 'dst_port']
    logs = [
        '2020-10-21 09:34:50 bolean 192.168.0.58 5 6 rsyslogd:   [origin software="rsyslogd" swVersion="8.32.0" x-pid="2430" x-info="http://www.rsyslog.com"] start',
        "2020-10-20 06:25:04 bolean 192.168.0.58 5 3 rsyslogd:  cannot connect to 192.168.0.41:514: No route to host [v8.32.0 try http://www.rsyslog.com/e/2027 ]",
        "2020-10-20 06:25:03 bolean 192.168.0.58 5 3 rsyslogd:   message repeated 260 times: [cannot connect to 192.168.0.41:514: No route to host [v8.32.0 try http://www.rsyslog.com/e/2027 ]]",
    ]

    @pytest.mark.parametrize(
        'log, target',
        [
            (logs[0],
             ['2020-10-21 09:34:50', 'bolean', '192.168.0.58', '5', '6', None,
              None, None, None]),
            (logs[1],
             ['2020-10-20 06:25:04', 'bolean', '192.168.0.58', '5', '3', None,
              None, '192.168.0.41', '514']),
            (logs[2],
             ['2020-10-20 06:25:03', 'bolean', '192.168.0.58', '5', '3', None,
              None, '192.168.0.41', '514']),
        ]
    )
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestAuditLogRule(Rule):
    pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
        r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
        r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?'
        r'\{devid: (?P<device_id>\d+), date: (?P<audit_date>.*?), '
        r'dname: (?P<device_name>.*?), logtype: (?P<audit_logtype>\d+), '
        r'pri: (?P<audit_pri>\d+), mod: (?P<audit_mod>.*?), '
        r'src_ip: (?P<src_ip>.*?), src_mac: (?P<src_mac>.*?), '
        r'dst_mac: (?P<dst_mac>.*?), src_port: (?P<src_port>.*?), '
        r'dst_ip: (?P<dst_ip>.*?), dst_port: (?P<dst_port>\d+), '
        r'protocol: (?P<protocol>.*?), dsp_msg: (?P<audit_msg>.*?)}'
    )

    logs = [
        '2020-10-10 16:35:22 bolean 192.168.0.58 16 6 [BGA]:  {devid: 12, date: 2020/10/10 16:35:10, dname: BoleanAudit, logtype: 361, pri: 3, mod: BoleanAudit, src_ip: ff02::1:3, src_mac: 33:33:00:01:00:03, dst_mac: , src_port: 63066, dst_ip: , dst_port: 5355, protocol: UDP, dsp_msg: \u68c0\u6d4b\u5230\u65b0\u8bbe\u5907 ff02::1:3 \u4e0e  fe80::7d89:ce2f:8dc6:8c90 \u8fdb\u884c\u5f02\u5e38\u901a\u4fe1}',
        '2020-10-10 16:35:22 bolean 192.168.0.58 16 6 [BGA]:  {devid: 12, date: 2020/10/10 16:35:10, dname: BoleanAudit, logtype: 361, pri: 3, mod: BoleanAudit, src_ip: ff02::1:3, src_mac: 33:33:00:01:00:03, dst_mac: 11:22:33:44:55, src_port: 63066, dst_ip: 102.10.1.1, dst_port: 5355, protocol: UDP, dsp_msg: \u68c0\u6d4b\u5230\u65b0\u8bbe\u5907 ff02::1:3 \u4e0e  fe80::7d89:ce2f:8dc6:8c90 \u8fdb\u884c\u5f02\u5e38\u901a\u4fe1}'
    ]

    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'device_id',
              'audit_date', 'device_name', 'audit_logtype', 'audit_pri',
              'audit_mod', 'src_ip', 'src_mac', 'dst_mac', 'src_port', 'dst_ip',
              'dst_port', 'protocol', 'audit_msg']
    targets = [
        (logs[0],
         ['2020-10-10 16:35:22', 'bolean', '192.168.0.58', '16', '6', '12',
          '2020/10/10 16:35:10', 'BoleanAudit', '361', '3', 'BoleanAudit',
          'ff02::1:3', '33:33:00:01:00:03', '', '63066', '', '5355', 'UDP',
          '\u68c0\u6d4b\u5230\u65b0\u8bbe\u5907 ff02::1:3 \u4e0e  fe80::7d89:ce2f:8dc6:8c90 \u8fdb\u884c\u5f02\u5e38\u901a\u4fe1']),
        (logs[1],
         ['2020-10-10 16:35:22', 'bolean', '192.168.0.58', '16', '6', '12',
          '2020/10/10 16:35:10', 'BoleanAudit', '361', '3', 'BoleanAudit',
          'ff02::1:3', '33:33:00:01:00:03', '11:22:33:44:55', '63066',
          '102.10.1.1', '5355', 'UDP',
          '\u68c0\u6d4b\u5230\u65b0\u8bbe\u5907 ff02::1:3 \u4e0e  fe80::7d89:ce2f:8dc6:8c90 \u8fdb\u884c\u5f02\u5e38\u901a\u4fe1']),
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestNginxLog(Rule):
    pattern = re.compile(regex_dict['nginx'])

    logs = [
        '2020-10-21 16:07:52 bolean 192.168.0.58 17 6 nginx_access_log:  192.168.0.204 - - [21/Oct/2020:16:07:52 +0800] "POST /center/serverinfo HTTP/1.1" 405 166 "-" "Python-urllib/2.7"',
        '2020-10-21 16:09:42 bolean 192.168.0.58 17 6 nginx_access_log:  192.168.0.153 - - [21/Oct/2020:16:09:42 +0800] "GET /api/v2/home/newest_alert/ HTTP/1.1" 200 1421 "https://192.168.0.58:8443/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.80 Safari/537.36"',
        '2020-10-21 16:34:57 bolean 192.168.0.58 17 6 bolean:  2020/10/19 11:12:14 [emerg] 5857#5857: invalid server name or wildcard *.*.*.* on 0.0.0.0:8443',
        '2020-10-21 16:34:57 bolean 192.168.0.58 17 6 bolean:  2020/10/19 11:13:36 [error] 5968#5968: invalid PID number "" in "/run/nginx.pid"',
        '2020-10-21 16:34:57 bolean 192.168.0.58 17 6 bolean:  2020/06/12 10:06:42 [error] 1295#1295: *1249547 connect() failed (111: Connection refused) while connecting to upstream, client: 10.0.3.38, server: *.*.*.*, request: "POST /api/v2/user/login/ HTTP/1.1", upstream: "http://127.0.0.1:9004/api/v2/user/login/", host: "192.168.0.57:8443", referrer: "https://192.168.0.57:8443/login"',
    ]

    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'src_ip',
              'remote_user', 'nginx_date', 'request', 'status_code',
              'body_bytes_sent',
              'http_referer', 'http_user_agent', 'upstream', 'src_port', 'host']
    targets = [
        (logs[0], ['2020-10-21 16:07:52', 'bolean', '192.168.0.58', '17', '6',
                   '192.168.0.204',
                   '-', '21/Oct/2020:16:07:52 +0800',
                   'POST /center/serverinfo HTTP/1.1', '405', '166', '-',
                   'Python-urllib/2.7',
                   None, None, None]),
        (logs[1], ['2020-10-21 16:09:42', 'bolean', '192.168.0.58', '17', '6',
                   '192.168.0.153',
                   '-', '21/Oct/2020:16:09:42 +0800',
                   'GET /api/v2/home/newest_alert/ HTTP/1.1', '200', '1421',
                   'https://192.168.0.58:8443/login',
                   'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.80 Safari/537.36',
                   None, None, None]),
        (logs[2],
         ['2020-10-21 16:34:57', 'bolean', '192.168.0.58', '17', '6', '0.0.0.0',
          None, '2020/10/19 11:12:14', None, None, None, None, None,
          None, '8443', None]),
        (logs[3],
         ['2020-10-21 16:34:57', 'bolean', '192.168.0.58', '17', '6', None,
          None, '2020/10/19 11:13:36', None, None, None, None, None,
          None, None, None]),
        (logs[4],
         ['2020-10-21 16:34:57', 'bolean', '192.168.0.58', '17', '6',
          '10.0.3.38',
          None, '2020/06/12 10:06:42', 'POST /api/v2/user/login/ HTTP/1.1',
          None, None, 'https://192.168.0.57:8443/login', None,
          'http://127.0.0.1:9004/api/v2/user/login/', None,
          '192.168.0.57:8443']),

    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestMailLog(Rule):
    pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
        r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
        r'(?P<facility>\d{1,2}) (?P<level>\d{1,2})'
        r'(.*?\[(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})]|.*?)'
    )

    logs = [
        '2020-10-14 10:05:27 ubuntu 192.168.0.58 2 6 systemd-logind[892]: j2A1pvT01251: lost input channel from [211.158.29.126] to MTA after mail]]',
        '2020-10-14 10:05:27 ubuntu 192.168.0.58 2 6 systemd-logind[892]: v176OZoC048313: <2323//qqq@centos_4a_full>... User unknown]]',
        '2020-10-14 10:05:27 ubuntu 192.168.0.58 2 6 systemd-logind[892]:  t152vKqJ008240: collect: unexpected close on connection from [10.20.36.5], sender=<nagios@loalhost>',
        '2020-10-14 10:05:27 ubuntu 192.168.0.58 2 6 systemd-logind[892]:  [ID 801593 mail.warning] j2I4bXYp029707: collect: premature EOM: Connection reset by [10.20.56.63]',
        '2020-10-14 10:05:27 ubuntu 192.168.0.58 2 6 systemd-logind[892]:  j4T54c1K021074: lost input channel from [10.21.106.224] to MTA after mail',
        '2020-10-14 10:05:27 ubuntu 192.168.0.58 2 6 systemd-logind[892]:  rejecting connections on daemon MTA: load average: 55',
    ]
    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'src_ip']

    targets = [
        (logs[0], ['2020-10-14 10:05:27', 'ubuntu', '192.168.0.58', '2', '6',
                   '211.158.29.126']),
        (logs[1],
         ['2020-10-14 10:05:27', 'ubuntu', '192.168.0.58', '2', '6', None]),
        (logs[2], ['2020-10-14 10:05:27', 'ubuntu', '192.168.0.58', '2', '6',
                   '10.20.36.5']),
        (logs[3], ['2020-10-14 10:05:27', 'ubuntu', '192.168.0.58', '2', '6',
                   '10.20.56.63']),
        (logs[4], ['2020-10-14 10:05:27', 'ubuntu', '192.168.0.58', '2', '6',
                   '10.21.106.224']),
        (logs[5],
         ['2020-10-14 10:05:27', 'ubuntu', '192.168.0.58', '2', '6', None]),
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestFTPLog(Rule):
    pattern = re.compile(regex_dict['ftp'])

    logs = [
        '2020-10-14 10:05:27 ubuntu 192.168.0.58 11 6 systemd-logind[892]:  pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=root rhost=10.20.1.105 user=root',
    ]

    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'src_ip']

    targets = [
        (logs[0], ['2020-10-14 10:05:27', 'ubuntu', '192.168.0.58', '11', '6',
                   '10.20.1.105']),
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestHuaWeiSwitchLog(Rule):
    pattern = re.compile(regex_dict['huawei_switch'])

    logs = [
        '2020-10-23 03:17:45 HUAWEI 192.168.0.58 23 6 %%01SHELL/6/DISPLAY_CMDRECORD(s)[204]: Recorded display command information. (Task=We0, Ip=192.168.1.122, VpnName=, User=admin, AuthenticationMethod="Local-user", Command="display license state")',
        '2020-10-23 03:17:51 HUAWEI 192.168.0.58 23 5 %%01SHELL/5/CMDRECORD(s)[206]: Recorded command information. (Task=We0, Ip=192.168.1.122, VpnName=, User=admin, AuthenticationMethod="Local-user", Command="quit")',
        '2020-10-23 03:18:23 HUAWEI 192.168.0.58 23 5 %%01HTTP/5/HANDSHAKE_TIMEOUT(s)[208]: HTTP user handshake timed out. ( UserName=admin, IPAddress=192.168.1.122, VpnName= )',
        '2020-10-23 03:18:23 HUAWEI 192.168.0.58 23 5 %%01CM/5/USER_OFFLINERESULT(s)[209]: [USER_INFO_OFFLINE]DEVICEMAC:f4-79-60-05-c2-50;DEVICENAME:HUAWEI;USER:admin;MAC:ff-ff-ff-ff-ff-ff;IPADDRESS:192.168.1.122;TIME:1603423103;ZONE:UTC+0800;DAYLIGHT:false;ERRCODE:90;RESULT:Idle cut;EXTENDINFO:NULL;CIB ID:5;ACCESS TYPE:HTTP;',
        '2020-10-23 03:18:25 HUAWEI 192.168.0.58 23 3 %%01HTTP/3/LOGINFAIL(s)[212]: User login failed. (UserName=admin, IPAddress=192.168.1.122, VpnName=hello, Info=Failed to authenticate the user)',
        '2020-10-23 03:21:28 HUAWEI 192.168.0.58 23 5 %%01SHELL/5/CMDRECORD(s)[225]: Recorded command information. (Task=We0, Ip=192.168.1.122, VpnName=, User=admin, AuthenticationMethod="Local-user", Command="quit")',
    ]

    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'src_ip',
              'user',
              'vpn_name', 'auth_method', 'command', 'src_mac', 'dst_mac',
              'device_name', 'info']
    targets = [
        (logs[0], ['2020-10-23 03:17:45', 'HUAWEI', '192.168.0.58', '23', '6',
                   '192.168.1.122', 'admin',
                   '', 'Local-user', 'display license state', None, None, None,
                   None]),
        (logs[1], ['2020-10-23 03:17:51', 'HUAWEI', '192.168.0.58', '23', '5',
                   '192.168.1.122', 'admin',
                   '', 'Local-user', 'quit', None, None, None, None]),
        (logs[2], ['2020-10-23 03:18:23', 'HUAWEI', '192.168.0.58', '23', '5',
                   '192.168.1.122', 'admin',
                   '', None, None, None, None, None, None]),
        (logs[3], ['2020-10-23 03:18:23', 'HUAWEI', '192.168.0.58', '23', '5',
                   '192.168.1.122', 'admin',
                   None, None, None, 'ff-ff-ff-ff-ff-ff', 'f4-79-60-05-c2-50',
                   'HUAWEI', None]),
        (logs[4], ['2020-10-23 03:18:25', 'HUAWEI', '192.168.0.58', '23', '3',
                   '192.168.1.122', 'admin',
                   'hello', None, None, None, None, None,
                   'Failed to authenticate the user']),
        (logs[5], ['2020-10-23 03:21:28', 'HUAWEI', '192.168.0.58', '23', '5',
                   '192.168.1.122', 'admin',
                   '', 'Local-user', 'quit', None, None, None, None]),
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestPostgresRule(Rule):
    pattern = re.compile(regex_dict['database_postgres'])

    logs = [
        '2020-10-23 15:32:31 bolean 192.168.0.58 18 6 postgres[32056]:  [1-1] 2020-10-23 15:32:31.504 CST [32056] LOG:  listening on IPv6 address "::1", port 5432',
        '2020-10-23 15:32:31 bolean 192.168.0.58 18 6 postgres[32056]:  [2-1] 2020-10-23 15:32:31.505 CST [32056] LOG:  listening on IPv4 address "127.0.0.1", port 5432',
        '2020-10-23 15:32:31 bolean 192.168.0.58 18 6 postgres[32056]:  [2-1] 2020-10-23 15:00:01.775 CST [30186] u_backend@d_backend STATEMENT:  SELECT "packet_protocolsetting"."id", "packet_protocolsetting"."protocol_run_mode", "packet_protocolsetting"."protocol_enabled" FROM "packet_protocolsetting" WHERE "packet_protocolsetting"."id" = 1',
        '2020-10-23 15:32:31 bolean 192.168.0.58 18 6 postgres[32056]:  [2-1] 2020-10-23 15:05:02.305 CST [30485] u_backend@d_backend ERROR:  relation "packet_protocolsetting" does not exist at character 134',
        '2020-10-23 15:32:31 bolean 192.168.0.58 18 6 postgres[32056]:  [2-1] 2020-10-23 15:32:30.893 CST [1551] bolean@unified_management_platform FATAL:  terminating connection due to administrator command',
        '2020-11-06 14:59:51 bolean 192.168.0.58 18 4 postgres[8217]:  [40443-5]  "unified_log_logprocessrule"."category", "unified_log_logprocessrule"."type", "unified_log_logprocessrule"."brand", "unified_log_logprocessrule"."hardware", "unified_log_logprocessrule"."status", "unified_log_logprocessrule"."add", "unified_log_logprocessrule"."update_time", "unified_log_logprocessrule"."pattern", "unified_log_logprocessrule"."example", "unified_log_logprocessrule"."log_type", "unified_log_logprocessrule"."mark" FROM "base_app_device" LEFT OUTER JOIN "unified_log_logprocesstemplate" ON ("base_app_device"."log_template_id" = "unified_log_logprocesstemplate"."id") LEFT OUTER JOIN "unified_log_logprocessrule" ON ("unified_log_logprocesstemplate"."local2_id" = "unified_log_logprocessrule"."id") WHERE "base_app_device"."ip" = \'192.168.0.58\'::inet',

    ]

    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'src_ip',
              'src_port', 'sql', 'error']

    targets = [
        (logs[0],
         ['2020-10-23 15:32:31', 'bolean', '192.168.0.58', '18', '6', '::1',
          '5432', None, None]),
        (logs[1], ['2020-10-23 15:32:31', 'bolean', '192.168.0.58', '18', '6',
                   '127.0.0.1', '5432', None, None]),
        (logs[2],
         ['2020-10-23 15:32:31', 'bolean', '192.168.0.58', '18', '6', None,
          None,
          'SELECT "packet_protocolsetting"."id", "packet_protocolsetting"."protocol_run_mode", "packet_protocolsetting"."protocol_enabled" FROM "packet_protocolsetting" WHERE "packet_protocolsetting"."id" = 1',
          None]),
        (logs[3],
         ['2020-10-23 15:32:31', 'bolean', '192.168.0.58', '18', '6', None,
          None, None,
          'relation "packet_protocolsetting" does not exist at character 134']),
        (logs[4],
         ['2020-10-23 15:32:31', 'bolean', '192.168.0.58', '18', '6', None,
          None, None, 'terminating connection due to administrator command']),
        (logs[5],
         ['2020-11-06 14:59:51', 'bolean', '192.168.0.58', '18', '4', None,
          None, '"unified_log_logprocessrule"."category", "unified_log_logprocessrule"."type", "unified_log_logprocessrule"."brand", "unified_log_logprocessrule"."hardware", "unified_log_logprocessrule"."status", "unified_log_logprocessrule"."add", "unified_log_logprocessrule"."update_time", "unified_log_logprocessrule"."pattern", "unified_log_logprocessrule"."example", "unified_log_logprocessrule"."log_type", "unified_log_logprocessrule"."mark" FROM "base_app_device" LEFT OUTER JOIN "unified_log_logprocesstemplate" ON ("base_app_device"."log_template_id" = "unified_log_logprocesstemplate"."id") LEFT OUTER JOIN "unified_log_logprocessrule" ON ("unified_log_logprocesstemplate"."local2_id" = "unified_log_logprocessrule"."id") WHERE "base_app_device"."ip" = \'192.168.0.58\'::inet',
          None])
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)
