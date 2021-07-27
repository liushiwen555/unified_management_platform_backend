import json

import requests
from requests.exceptions import RequestException, HTTPError

from auditor.models import AuditWhiteListStrategy, AuditBlackListStrategy, AuditIPMACBondStrategy
from auditor.serializers import ApplyStrategySerializer
from base_app.models import Device
from utils.core.exceptions import CustomError

HTTP = 'https'
PORT = 443
REBOOT_API = 'v2/unified-management/reboot/'
UN_REGISTER_API = 'v2/unified-management/unregister/platform/'
APPLY_STRATEGIES_API = 'v2/unified-management/strategy/'
SYNC_STRATEGIES_API = 'v2/unified-management/auditor_strategy/'
IP_CHANGE_API = 'v2/unified-management/ip/'


def reboot(serializer):

    auditors = Device.objects.filter(id__in=serializer.data['dev_ids'], status=Device.ONLINE)
    failed_ids = []
    for auditor in auditors:
        try:
            response = requests.post('{}://{}:{}/{}'.format(HTTP, auditor.ip, PORT, REBOOT_API),
                                     headers={'secret': auditor.secret}, verify=False)
            response.raise_for_status()
            # TODO 即使接口调用成功了，也会把auditor.id加入failed_ids，这样的话最后都会报错
            failed_ids.append(auditor.id)
        except HTTPError:
            failed_ids.append(auditor.id)
        except RequestException:
            pass
    if failed_ids:
        raise CustomError({'error': CustomError.BATCH_OPERATION_PART_FAIL,'failed_ids': failed_ids})


def un_register(serializer):
    auditors = Device.objects.filter(id__in=serializer.data['dev_ids'], status=Device.ONLINE)
    failed_ids = []
    for auditor in auditors:
        try:
            response = requests.post('{}://{}:{}/{}'.format(HTTP, auditor.ip, PORT, UN_REGISTER_API),
                                     headers={'secret': auditor.secret}, verify=False)
            response.raise_for_status()
            auditor.status = Device.NOT_REGISTERED
            auditor.save()
        except RequestException:
            failed_ids.append(auditor.id)
    if failed_ids:
        raise CustomError({'error': CustomError.BATCH_OPERATION_PART_FAIL,'failed_ids': failed_ids})


def auditor_apply_strategies(auditor):

    whitelist = AuditWhiteListStrategy.objects.filter(device=auditor)
    blacklist = AuditBlackListStrategy.objects.filter(device=auditor)
    ip_mac = AuditIPMACBondStrategy.objects.filter(device=auditor)
    strategies = ApplyStrategySerializer({'whitelist': whitelist, 'blacklist': blacklist, 'device': ip_mac})
    try:
        response = requests.post('{}://{}:{}/{}'
                                 .format(HTTP, auditor.ip, PORT, APPLY_STRATEGIES_API),
                                 json=strategies.data, headers={'secret': auditor.secret}, verify=False)
        response.raise_for_status()
    except RequestException as e:
        raise CustomError({'error': CustomError.APPLY_STRATEGY_FAIL})


def auditor_sync_strategies(auditor):

    try:
        response = requests.get('{}://{}:{}/{}'
                                 .format(HTTP, auditor.ip, PORT, SYNC_STRATEGIES_API),
                                headers={'secret': auditor.secret}, verify=False)

        res = json.loads(response.content.decode(encoding='utf-8'))

        AuditWhiteListStrategy.objects.filter(device=auditor).delete()
        AuditBlackListStrategy.objects.filter(device=auditor).delete()
        AuditIPMACBondStrategy.objects.filter(device=auditor).delete()

        serializer = ApplyStrategySerializer(data=res)
        serializer.is_valid(raise_exception=True)
        serializer.save(device_id=auditor.id)
        response.raise_for_status()
    except RequestException as e:
        raise CustomError({'error': CustomError.SYNC_STRATEGY_FAIL})


def ip_change(ip):
    devices = Device.objects.filter(status=Device.ONLINE)
    for device in devices:
        try:
            response = requests.put('{}://{}:{}/{}'.format(HTTP, device.ip, PORT, IP_CHANGE_API), json={'ip': ip},
                                    headers={'secret': device.secret}, verify=False)
        except requests.exceptions.RequestException as e:
            # TODO 和润新确认，记录log或告警
            pass
