import regex as re
import pytest

from unified_log.log_regex import ASUS_ROUTER
from unified_log.tests.test_rule.test_log_rule import Rule


class TestUserRule(Rule):
    pattern = re.compile(ASUS_ROUTER['user'])
    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'in_network',
              'src_mac', 'status_code', 'reason']

    logs = [
        '2020-10-26 09:22:10 RT-AC5300-1F50-1007E32-C 192.168.0.130 1 5 syslog:  WLCEVENTD wlceventd_proc_event(420): eth3: Auth 1C:BF:C0:CA:D1:59, status: 0, reason: d11 RC reserved (0)',
        '2020-10-26 09:22:15 RT-AC5300-1F50-1007E32-C 192.168.0.130 1 5 syslog:  WLCEVENTD wlceventd_proc_event(401): eth3: Disassoc 1C:BF:C0:CA:D1:59, status: 0, reason: Disassociated because sending station is leaving (or has left) BSS (8)'
    ]

    targets = [
        (logs[0], ['2020-10-26 09:22:10', 'RT-AC5300-1F50-1007E32-C', '192.168.0.130', '1', '5', 'eth3', '1C:BF:C0:CA:D1:59', '0', 'd11 RC reserved (0)']),
        (logs[1], ['2020-10-26 09:22:15', 'RT-AC5300-1F50-1007E32-C', '192.168.0.130', '1', '5', 'eth3', '1C:BF:C0:CA:D1:59', '0', 'Disassociated because sending station is leaving (or has left) BSS (8)']),
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestKernLog(Rule):
    pattern = re.compile(ASUS_ROUTER['kern'])
    target = ['timestamp', 'hostname', 'ip', 'facility', 'level']

    logs = [
        '2020-10-23 17:07:07 RT-AC5300-1F50-1007E32-C 192.168.0.130 0 6 rc_service:  httpd 352:notify_rc restart_firewall'
    ]

    targets = [
        (logs[0], ['2020-10-23 17:07:07', 'RT-AC5300-1F50-1007E32-C', '192.168.0.130', '0', '6'])
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestDaemonLog(Rule):
    pattern = re.compile(ASUS_ROUTER['daemon'])
    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'src_ip',
              'dst_ip', 'src_mac', 'dst_mac', 'DHCP', 'requested_ip', 'device_name']

    logs = [
        '2020-10-23 17:10:16 RT-AC5300-1F50-1007E32-C 192.168.0.130 3 4 miniupnpd[21786]:  SendNATPMPPublicAddressChangeNotification: cannot get public IP address, stopping',
        '2020-10-26 11:12:38 RT-AC5300-1F50-1007E32-C 192.168.0.130 3 6 dnsmasq-dhcp[343]:  DHCPDISCOVER(br0) b8:7b:c5:36:c8:b5 ',
        '2020-10-26 11:12:38 RT-AC5300-1F50-1007E32-C 192.168.0.130 3 6 dnsmasq-dhcp[343]:  DHCPOFFER(br0) 192.168.3.74 b8:7b:c5:36:c8:b5 ',
        '2020-10-26 11:12:43 RT-AC5300-1F50-1007E32-C 192.168.0.130 3 6 dnsmasq-dhcp[343]:  DHCPREQUEST(br0) 192.168.3.74 b8:7b:c5:36:c8:b5 ',
        '2020-10-26 11:12:43 RT-AC5300-1F50-1007E32-C 192.168.0.130 3 6 dnsmasq-dhcp[343]:  DHCPACK(br0) 192.168.3.74 b8:7b:c5:36:c8:b5 iPhone-2qi',

    ]

    targets = [
        (logs[0], ['2020-10-23 17:10:16', 'RT-AC5300-1F50-1007E32-C', '192.168.0.130', '3', '4', None,
                   None, None, None, None, None, None]),
        (logs[1], ['2020-10-26 11:12:38', 'RT-AC5300-1F50-1007E32-C', '192.168.0.130', '3', '6', None,
                   None, 'b8:7b:c5:36:c8:b5', None, 'DHCPDISCOVER', None, '']),
        (logs[2], ['2020-10-26 11:12:38', 'RT-AC5300-1F50-1007E32-C', '192.168.0.130', '3', '6', None,
                   '192.168.3.74', None, 'b8:7b:c5:36:c8:b5', 'DHCPOFFER', None, '']),
        (logs[3], ['2020-10-26 11:12:43', 'RT-AC5300-1F50-1007E32-C', '192.168.0.130', '3', '6', None,
                   None, 'b8:7b:c5:36:c8:b5', None, 'DHCPREQUEST', '192.168.3.74', '']),
        (logs[4], ['2020-10-26 11:12:43', 'RT-AC5300-1F50-1007E32-C', '192.168.0.130', '3', '6', None,
                   '192.168.3.74', None, 'b8:7b:c5:36:c8:b5', 'DHCPACK', None, 'iPhone-2qi']),
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestAuthprivLog(Rule):
    pattern = re.compile(ASUS_ROUTER['authpriv'])
    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'src_ip', 'src_port']

    logs = [
        '2020-10-23 17:08:43 RT-AC5300-1F50-1007E32-C 192.168.0.130 10 4 dropbear[23979]:  Login attempt for nonexistent user from 192.168.3.94:56967',
        '2020-10-23 17:13:41 RT-AC5300-1F50-1007E32-C 192.168.0.130 10 6 dropbear[23979]:  Exit before auth: Timeout before auth'
    ]

    targets = [
        (logs[0], ['2020-10-23 17:08:43', 'RT-AC5300-1F50-1007E32-C', '192.168.0.130', '10', '4', '192.168.3.94', '56967']),
        (logs[1], ['2020-10-23 17:13:41', 'RT-AC5300-1F50-1007E32-C', '192.168.0.130', '10', '6', None, None]),
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)


class TestLocal0Log(Rule):
    pattern = re.compile(ASUS_ROUTER['local0'])
    target = ['timestamp', 'hostname', 'ip', 'facility', 'function', 'source']
    logs = [
        '2020-11-25 15:33:45 DESKTOP-I1ER8FP 192.168.0.130 16 6 EvntSLog ServicePackageRundownNotificationImpl microsoft.windowscommunicationsapps_16005.13228.41011.0_x64__8wekyb3d8bbwe+ppleae38af2e007f4358a809ac99a64a67c1, sid:S-1-5-21-1908817775-4189964435-2237258811-1001 Function: ServicePackageRundownNotificationImpl Source: onecoreuap\enduser\winstore\licensemanager\lib\service.cpp (2347)',
        '2020-11-25 15:33:45 DESKTOP-I1ER8FP 192.168.0.130 16 5 EvntSLog 0x1cbdaeaec80: 12644: 6EA6FC2E-9305-586B-3411-02826D151533: Dispatch: Key:Unregistered => Key:Valid',
        '2020-11-25 15:33:45 DESKTOP-I1ER8FP 192.168.0.130 16 6 EvntSLog Adding lease {A7E08B8B-AD4B-AF00-EBCC-1AA29A833CE9} to results Function: ClipStorage::GetLeaseDocumentsForKeyDocument Source: onecoreuap\enduser\winstore\licensemanager\lib\clipstorage.cpp (400)',
    ]
    targets = [
        (logs[0], ['2020-11-25 15:33:45', 'DESKTOP-I1ER8FP', '192.168.0.130', '16', 'ServicePackageRundownNotificationImpl', 'onecoreuap\\enduser\\winstore\\licensemanager\\lib\\service.cpp']),
        (logs[1], ['2020-11-25 15:33:45', 'DESKTOP-I1ER8FP', '192.168.0.130', '16', None, None]),
        (logs[2], ['2020-11-25 15:33:45', 'DESKTOP-I1ER8FP', '192.168.0.130', '16', 'ClipStorage::GetLeaseDocumentsForKeyDocument', 'onecoreuap\\enduser\\winstore\\licensemanager\\lib\\clipstorage.cpp']),
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)
