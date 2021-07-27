import regex as re
import pytest

from unified_log.log_regex import WINDOWS
from unified_log.tests.test_rule.test_log_rule import Rule


class TestDaemonRule(Rule):
    pattern = re.compile(WINDOWS['local0'])

    target = ['timestamp', 'hostname', 'ip', 'facility', 'level', 'application', 'function', 'source', 'sid']

    logs = [
        '2019-10-04 21:33:46 DESKTOP-I1ER8FP 10.0.11.25 16 6 EvntSLog ApplicationResourceManagement MRT APIs informational ',
        '2019-03-14 10:11:20 DESKTOP-I1ER8FP 10.0.11.25 16 6 EvntSLog Exe: C:\\Users\\Bolean\\Downloads\\matlab_R2018b_win64.exe ResolverName: DetectorShim_Win32Exception',
        '2020-11-26 09:58:22 DESKTOP-I1ER8FP 10.0.11.25 16 6 EvntSLog Invoking license manager because license/lease polling time up: PFN Microsoft.MicrosoftOfficeHub_18.2008.12711.0_x64__8wekyb3d8bbwe Function: InvokeLicenseManagerRequired Source: onecoreuap\enduser\winstore\licensemanager\apisethost\activationapis.cpp (331)',
        '2020-11-26 09:57:52 DESKTOP-I1ER8FP 10.0.11.25 16 6 EvntSLog ServicePackageRundownNotificationImpl Microsoft.MicrosoftOfficeHub_18.2008.12711.0_x64__8wekyb3d8bbwe+Microsoft.MicrosoftOfficeHub, sid:S-1-5-21-1908817775-4189964435-2237258811-1001 Function: ServicePackageRundownNotificationImpl Source: onecoreuap\enduser\winstore\licensemanager\lib\service.cpp (2347)',
    ]

    targets = [
        (logs[0], ['2019-10-04 21:33:46', 'DESKTOP-I1ER8FP', '10.0.11.25', '16', '6', None, None, None, None]),
        (logs[1], ['2019-03-14 10:11:20', 'DESKTOP-I1ER8FP', '10.0.11.25', '16', '6', 'C:\\Users\\Bolean\\Downloads\\matlab_R2018b_win64.exe', None, None, None]),
        (logs[2], ['2020-11-26 09:58:22', 'DESKTOP-I1ER8FP', '10.0.11.25', '16', '6', None, 'InvokeLicenseManagerRequired', 'onecoreuap\\enduser\\winstore\\licensemanager\x07pisethost\x07ctivationapis.cpp (331)', None]),
        (logs[3], ['2020-11-26 09:57:52', 'DESKTOP-I1ER8FP', '10.0.11.25', '16', '6', None, 'ServicePackageRundownNotificationImpl', 'onecoreuap\\enduser\\winstore\\licensemanager\\lib\\service.cpp (2347)', 'S-1-5-21-1908817775-4189964435-2237258811-1001'])
    ]

    @pytest.mark.parametrize('log, target', targets)
    def test_rule(self, log, target):
        super().test_rule(log, target)
