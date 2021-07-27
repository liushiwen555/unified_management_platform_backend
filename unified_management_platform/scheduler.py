import os
import logging

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE",
                      "unified_management_platform.settings")
django.setup()

from django.utils import timezone
from django.db import connections
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.jobstores.redis import RedisJobStore
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED
from apscheduler.executors.pool import ThreadPoolExecutor

from statistic.tasks import MainViewTask, AssetsCenterTask, MonitorCenterTask, \
    LogCenterTask, LogStatisticTask, LogStatisticDayTask, LogDstIPTopFiveTask, \
    LogCategoryDistributionTask, LogPortDistributionTask, DeviceLogCountTask, \
    SystemRunningTask, AssetsIPDistributionTask, ExternalIPTopTask, \
    AuditorProtocolSynchronizeTask, ProtocolIPRankTask, ProtocolPortRankTask, \
    AttackIPStatisticTask, AlertWeekTrendTask, AttackIPRankTask
from log.tasks import check_device_status_task
from auditor.tasks import AuditorLogTask
from setting.tasks import DiskCheckTask
from utils.unified_redis import IPDuplicateCleanTask
from setting.tasks import StatisticDataCleanTask

logging.basicConfig()
logger = logging.getLogger('apscheduler')
logger.setLevel(logging.INFO)

jobstores = {
    'default': RedisJobStore(jobs_key='dispatched_jobs',
                             run_times_key='dispatch_running',
                             host='localhost', port=6379)
}

executors = {
    'default': ThreadPoolExecutor(20)
}

job_defaults = {
    'coalesce': False,
    'max_instances': 1
}


def close_connections(event):
    connections.close_all()


scheduler = BlockingScheduler(jobstores=jobstores, executors=executors,
                              job_defaults=job_defaults)
scheduler.add_listener(close_connections, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR)


def auditor_alert_synchronize():
    """
    审计事件和日志同步，1分钟同步一次
    :return:
    """
    current = timezone.now()
    current = current.replace(second=0, microsecond=0)
    AuditorLogTask.run(current)


def ip_duplicate_clean_task():
    """
    清理IP重复判断服务的hyperloglog数据
    :return:
    """
    current = timezone.now()
    current = current.replace(second=0, microsecond=0)
    IPDuplicateCleanTask.run(current)


def auditor_protocol_synchronize():
    """
    1分钟间隔执行任务
    同步协议审计，统计外联IP，端口排名，IP排名，IP攻击，IP地图
    :return:
    """
    current = timezone.now()
    current = current.replace(second=0, microsecond=0)
    AuditorProtocolSynchronizeTask.run(current)


def task_run_every_60_minutes():
    current = timezone.now()
    current = current.replace(second=0, microsecond=0)
    MainViewTask.run(current)
    AssetsCenterTask.run(current)
    LogStatisticTask.run(current)
    LogCategoryDistributionTask.run(current)
    LogPortDistributionTask.run(current)
    LogDstIPTopFiveTask.run(current)
    DeviceLogCountTask.run(current)


def task_run_every_30_minutes():
    current = timezone.now()
    current = current.replace(second=0, microsecond=0)
    MonitorCenterTask.run(current)


def task_run_every_10_minutes():
    current = timezone.now()
    current = current.replace(second=0, microsecond=0)
    LogCenterTask.run(current)


def task_run_every_day():
    current = timezone.now()
    current = current.replace(second=0, microsecond=0)
    LogStatisticDayTask.run(current)
    DiskCheckTask.run(current)
    AssetsIPDistributionTask.run(current)
    ExternalIPTopTask.run(current)
    ProtocolIPRankTask.run(current)
    AttackIPRankTask.run(current)
    ProtocolPortRankTask.run(current)
    AttackIPStatisticTask.run(current)
    AlertWeekTrendTask.run(current)


def clean_statistic_data():
    """
    定时清理安全中心的统计数据
    """
    current = timezone.now()
    current = current.replace(second=0, microsecond=0)
    StatisticDataCleanTask.run(current)


def task_run_every_minute():
    current = timezone.now()
    current = current.replace(second=0, microsecond=0)
    # snmp_task(current)


def task_run_every_2_minutes():
    check_device_status_task()


def task_run_every_5_seconds():
    current = timezone.now()
    SystemRunningTask.run(current)


# 这里的数据都是本地时间，不是UTC时间
scheduler.add_job(task_run_every_60_minutes, id='task_run_every_60_minutes',
                  max_instances=1, trigger='cron', hour='*/1',
                  replace_existing=True)
scheduler.add_job(auditor_protocol_synchronize,
                  id='auditor_protocol_synchronize',
                  max_instances=1, trigger='cron', minute='*/1',
                  replace_existing=True)
scheduler.add_job(task_run_every_30_minutes, id='task_run_every_30_minutes',
                  max_instances=1, trigger='cron', minute='*/30',
                  replace_existing=True)
scheduler.add_job(task_run_every_10_minutes, id='task_run_every_10_minutes',
                  max_instances=1, trigger='cron', minute='*/10',
                  replace_existing=True)
scheduler.add_job(task_run_every_day, id='task_run_every_day',
                  max_instances=1, trigger='cron', hour='0', minute='30',
                  replace_existing=True)
scheduler.add_job(ip_duplicate_clean_task, id='ip_duplicate_clean_task',
                  max_instances=1, trigger='cron', hour='0', minute='30',
                  replace_existing=True)
scheduler.add_job(task_run_every_5_seconds, id='task_run_every_5_seconds',
                  max_instances=1, trigger='cron', second='*/5',
                  replace_existing=True)
scheduler.add_job(auditor_alert_synchronize, id='auditor_alert_synchronize',
                  max_instances=1, trigger='cron', minute='*/1',
                  replace_existing=True)
scheduler.add_job(task_run_every_2_minutes, id='task_run_every_2_minutes',
                  max_instances=1, trigger='cron', minute='*/2',
                  replace_existing=True)

if __name__ == '__main__':
    scheduler.start()
