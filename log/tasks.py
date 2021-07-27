import os
from concurrent.futures import ThreadPoolExecutor

from celery import shared_task
from django.contrib.auth import get_user_model
from django.utils import timezone

from base_app.models import Device
from log.models import UnifiedForumLog
from log.security_event import UnModifiedPasswordEvent, AssetsOfflineEvent
from setting.models import Setting
from statistic.serializers import MonitorCenterSerializer, \
    AssetsCenterSerializer, DeviceDistributionSerializer, AssetsIPSerializer, DeviceCountSerializer, RiskDeviceTopFiveSerializer
from user.models import UserExtension
from utils.helper import send_websocket_message

User = get_user_model()


def get_pwd_log_data(user: User, pwd_modified_duration: int):
    data = dict(
        category=UnifiedForumLog.CATEGORY_SYSTEM,
        type=UnifiedForumLog.TYPE_AUTH_SECURITY,
        user=user.username,
        group=user.group.name,
        content='当前密码使用达到{}天'.format(pwd_modified_duration),
        ip='127.0.0.1',
    )
    return data


def ping_status(host):
    cmd = 'ping  -c 2 -t 5 {}'.format(host)
    result = os.popen(cmd).read()
    if 'ttl' in result:
        return True
    else:
        return False


# 检查 dvice 的状态，并更改其是否可以产生告警信息
def update_device_alert_status(d: Device):

    last_status = d.status
    ping_status_now = ping_status(d.ip)
    d.alert_status = False

    if last_status == Device.ONLINE:
        if not ping_status_now:
            d.alert_status = True
            d.status = Device.OFFLINE
    if ping_status_now:
        d.status = Device.ONLINE
    d.save(update_fields=['alert_status', 'status'])


@shared_task
def check_user_pwd_modified():
    setting, exists = Setting.objects.get_or_create(id=1)
    pwd_modified_duration = setting.change_psw_duration # 天
    all_users = User.objects.all()

    for user in all_users:
        user_ext = UserExtension.objects.filter(name=user.username)

        if user_ext.count() > 0:
            user_ext = user_ext[0]
            user_last_change_pwd = user_ext.last_change_psd
            timedelta = (timezone.now() - user_last_change_pwd).days
            if timedelta > pwd_modified_duration:
                # 记录安全告警
                user.un_modify_passwd = True
                user.save(update_fields=['un_modify_passwd'])
                # 记录本机日志
                log = get_pwd_log_data(user, pwd_modified_duration)
                UnifiedForumLog.objects.create(**log)
    event = UnModifiedPasswordEvent()
    event.generate()


def check_device_status_task():
    all_devices = Device.objects.all()
    pool = ThreadPoolExecutor(20)

    tasks = []
    for dev in all_devices:
        tasks.append(pool.submit(device_offline_event, dev))
    for t in tasks:
        t.result()
    # 心跳检查之后推送最新的资产数据
    serializer = MonitorCenterSerializer(Device.objects.all())
    assets_serializer = AssetsCenterSerializer(Device.objects.all())
    message = {
        'message': 'main',
        'data': {
            'monitor_center': serializer.data,
            'assets_center': assets_serializer.data,
        }
    }
    send_websocket_message('main', message)

    assets = {
        'message': 'assets',
        'data': {
            'category_distribution': DeviceDistributionSerializer(Device.objects.all()).data,
            'total': DeviceCountSerializer(Device.objects.all()).data,
            'ip_distribution': AssetsIPSerializer(Device.objects.all()).data,
            'risk_top_five': RiskDeviceTopFiveSerializer(Device.objects.all()).data,
        }
    }
    send_websocket_message('assets', assets)


def device_offline_event(device: Device):
    update_device_alert_status(device)
    if device.alert_status:
        event = AssetsOfflineEvent(device=device)
        event.generate()
