from __future__ import absolute_import, unicode_literals

import requests
from celery import shared_task
from celery.signals import task_postrun
from django.utils import timezone

from auditor.audit_requests import auditor_apply_strategies, auditor_sync_strategies
from base_app.models import Device, StrategyTemplate
from firewall.firewall_requests import FirewallRequests, firewall_apply_strategies
from utils.core.exceptions import CustomError

HTTP = 'https'
PORT = 443
AUDITOR_HEARTBEAT_API = 'v2/unified-management/heartbeat'


@shared_task
def device_heartbeat_task():
    auditors = Device.objects.filter(type=Device.AUDITOR).exclude(status=Device.NOT_REGISTERED)
    for auditor in auditors:
        try:
            response = requests.get('{}://{}:{}/{}'.format(HTTP, auditor.ip, PORT, AUDITOR_HEARTBEAT_API),
                                    headers={'secret': auditor.secret}, verify=False)
            auditor.status = Device.ONLINE
        except requests.exceptions.HTTPError:
            if response:
                if response.status_code == CustomError.status_code \
                        and int(response.json()['error']) == CustomError.DEVICE_NOT_REGISTERED:
                    auditor.status = Device.NOT_REGISTERED

        except requests.exceptions.RequestException as e:
            auditor.status = Device.OFFLINE
        auditor.save(update_fields=['status'])
    firewalls = Device.objects.filter(type=Device.FIRE_WALL).exclude(status=Device.NOT_REGISTERED)
    for firewall in firewalls:
        try:
            request = FirewallRequests(firewall)
            request.heart_beat()
            firewall.status = Device.ONLINE

        except requests.exceptions.RequestException as e:
            firewall.status = Device.OFFLINE
        firewall.save(update_fields=['status'])


@shared_task
def apply_strategies_task(device_id):
    device = Device.objects.get(id=device_id)
    if device.type == Device.FIRE_WALL:
        firewall_apply_strategies(device)
    elif device.type == Device.AUDITOR:
        auditor_apply_strategies(device)


@shared_task
def batch_apply_strategies_task(ids):
    for device_id in ids:
        device = Device.objects.get(id=device_id)
        device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_APPLYING
        device.save(update_fields=['strategy_apply_status'])
        if device.type == Device.FIRE_WALL:
            firewall_apply_strategies(device)
        elif device.type == Device.AUDITOR:
            auditor_apply_strategies(device)


@shared_task
def sync_strategies_task(device_id):
    device = Device.objects.get(id=device_id)
    if device.type == Device.FIRE_WALL:
        # firewall_sync_strategies(device)
        pass
    elif device.type == Device.AUDITOR:
        auditor_sync_strategies(device)


@shared_task
def batch_sync_strategies_task(ids):
    for device_id in ids:
        device = Device.objects.get(id=device_id)
        if device.type == Device.FIRE_WALL:
            # firewall_sync_strategies(device)
            pass
        elif device.type == Device.AUDITOR:
            auditor_sync_strategies(device)


@shared_task
def deploy_to_device_task(temp_id: int, dev_ids: list, dev_type: int):
    template = StrategyTemplate.objects.get(id=temp_id)
    devices = Device.objects.filter(id__in=dev_ids, type=dev_type)
    for device in devices:
        try:
            apply_strategies_task(device.id)
            device.apply_time = timezone.now()
            device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_APPLIED
        except CustomError:
            device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_FAILED
        device.template_name = '来自{}的策略'.format(template.name)
        device.save(update_fields=['strategy_apply_status', 'apply_time', 'template_name'])
    template.apply_time = timezone.now()
    template.save(update_fields=['apply_time'])


@task_postrun.connect(sender=apply_strategies_task)
def apply_strategies_handler(state=None, args=None, **kwargs):
    device_id = args[0]
    device = Device.objects.get(id=device_id)
    if state == 'SUCCESS':
        device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_APPLIED
        device.apply_time = timezone.now()
    elif state == 'FAILURE':
        device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_FAILED
    device.save(update_fields=['strategy_apply_status', 'apply_time'])


