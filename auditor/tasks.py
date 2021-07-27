from __future__ import absolute_import, unicode_literals

from datetime import datetime

from auditor.bolean_auditor import AuditorSynchronize, AuditorSynchronizeLog
from base_app.models import Device
from utils.runnable import TaskRun

HTTP = 'https'
PORT = 443
GET_SEC_ALERT_API = 'v2/unified-management/sec-alert/'
GET_SYS_ALERT_API = 'v2/unified-management/sys-alert/'
GET_LOG_API = 'v2/unified-management/log/'
APPLY_STRATEGIES_API = 'v2/unified-management/strategy/'


def get_audit_log_task():
    auditors = Device.objects.filter(type=Device.AUDITOR,
                                     register_status=Device.REGISTERED)
    for auditor in auditors:
        # 同步黑名单告警到告警威胁
        sec_sync = AuditorSynchronize(auditor)
        sec_sync.synchronize()
        # 同步审计日志
        log_sync = AuditorSynchronizeLog(auditor)
        log_sync.synchronize()
        auditor.save(update_fields=['audit_sec_alert_max_id',
                                    'audit_sys_alert_max_id',
                                    'audit_log_max_id'])


class AuditorLogTask(TaskRun):
    @classmethod
    def run(cls, current: datetime):
        auditors = Device.objects.filter(type=Device.AUDITOR,
                                         register_status=Device.REGISTERED)
        for auditor in auditors:
            # 同步黑名单告警到告警威胁
            sec_sync = AuditorSynchronize(auditor, current)
            sec_sync.synchronize()
            # 同步审计日志
            log_sync = AuditorSynchronizeLog(auditor)
            log_sync.synchronize()
            auditor.save(update_fields=['audit_sec_alert_max_id',
                                        'audit_sys_alert_max_id',
                                        'audit_log_max_id'])
