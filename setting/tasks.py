import subprocess
from datetime import datetime, timedelta

from celery import shared_task

from log.models import UnifiedForumLog
from setting.models import Setting
from setting.system_check import CPUCheck, MemoryCheck, DiskCheck
from statistic.models import clean_register
from utils.runnable import TaskRun
from snmp.models import SNMPData


class DiskCheckTask(TaskRun):
    @classmethod
    def run(cls, current: datetime):
        setting, _ = Setting.objects.get_or_create(id=1)
        check = DiskCheck(setting)
        check.run()


@shared_task
def cpu_memory_alert_task():
    setting_rec, _ = Setting.objects.get_or_create(id=1)

    cpu_check = CPUCheck(setting_rec.cpu_alert_percent)
    memory_check = MemoryCheck(setting_rec.memory_alert_percent)
    cpu_check.check()
    memory_check.check()


@shared_task
def set_time(ntp: str):
    """
    set time by execute shell command.
    :param ntp: ntp时间同步服务器
    :return:
    """
    subprocess.run(['ntpdate', '-u', ntp], check=True)


class StatisticDataCleanTask(TaskRun):
    """
    模块：安全态势和运营态势的历史数据删除任务
    更新周期：1天
    描述：需要根据用户在系统管理里设置的清理时间，清理n个月前的数据
    """
    @classmethod
    def run(cls, current: datetime):
        classes = clean_register.get_all()
        classes.append(SNMPData)
        clean, _ = Setting.objects.get_or_create(id=1)
        duration = clean.security_center * 30

        delete_time = current - timedelta(days=duration)

        for clz in classes:
            clz.objects.filter(update_time__lte=delete_time).delete()
        UnifiedForumLog.objects.create(
            type=UnifiedForumLog.TYPE_SECURITY,
            content=f'定时清理{clean.security_center}个月前的安全中心统计数据',
            result=True,
            category=UnifiedForumLog.CATEGORY_SYSTEM,
            ip='127.0.0.1'
        )


if __name__ == '__main__':
    set_time.delay(datetime(2020, 9, 27, 10))