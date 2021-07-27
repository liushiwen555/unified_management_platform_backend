import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import django
from django.db import connections

os.environ.setdefault("DJANGO_SETTINGS_MODULE",
                      "unified_management_platform.settings")
django.setup()

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from snmp.snmp_run import SNMPClient
from base_app.models import Device


logger = logging.getLogger('snmp_task')


def snmp_task():
    pool = ThreadPoolExecutor(20)
    while True:
        current = timezone.now()
        logger.info('开始执行性能采集任务')
        devices = []
        for d in Device.objects.all():
            if check_should_snmp(d):
                devices.append(d)

        tasks = [pool.submit(snmp_run, device, current) for device in devices]
        cnt = 0
        for t in tasks:
            cnt += 1
            t.result()
        time.sleep(30)


def check_should_snmp(device: Device) -> bool:
    """
    只要有当前时间超过采集周期才能执行任务
    :param device: 需要snmp查数据的资产
    :return True or False用于判断是否要执行snmp任务
    """
    try:
        setting = device.snmpsetting
    except ObjectDoesNotExist:
        return False
    if not (setting and device.monitor and setting.template):
        return False
    return (timezone.now() - setting.last_run_time).total_seconds() >= 60


def snmp_run(device: Device, current: datetime):
    try:
        # 间隔采数间隔10s
        _snmp_run(device, current)
    except Exception as e:
        logger.error(e)
        logger.error('资产: {}, 资产ID: {}'.format(device.name, device.id))
    finally:
        connections.close_all()


def _snmp_run(device: Device, current: datetime):
    # 间隔采数间隔10s
    snmp_client = SNMPClient(device, interval=10, current=current)
    snmp_client.snmp_get()
    snmp_client.save_data()


if __name__ == '__main__':
    snmp_task()
