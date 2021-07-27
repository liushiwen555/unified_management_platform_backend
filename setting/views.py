import configparser
import datetime
import time

import psutil
from django.conf import settings
from django.utils import timezone
from django.utils.decorators import method_decorator
from drf_yasg.utils import swagger_auto_schema
from netifaces import ifaddresses, AF_INET, gateways
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from auditor import audit_requests
from log.models import DeviceAllAlert, UnifiedForumLog
from setting.models import Setting, Location
from setting.serializers import IPInfoSerializer, TimeInfoSerializer, \
    SettingSerializer, IPLimitSerializer, DiskSerializer, NTPSettingSerializer, \
    SystemInfoSerializer, SystemSecuritySerializer, ThemeSerializer, LocationSerializer, SecurityCenterCleanSerializer
from setting.tasks import set_time
from user.serializers import PasswordSerializer
from utils.core.exceptions import CustomError
from utils.core.mixins import MultiMethodAPIViewMixin
from utils.core.permissions import IsConfiEngineer, IsAdmin
from utils.helper import bytes2human
from utils.os_operate import set_ip, reboot
from log.security_event import RebootEvenLog


class ProductInfoView(APIView):
    permission_classes = (IsConfiEngineer,)

    @method_decorator(swagger_auto_schema(
        deprecated=True,
        operation_summary='此接口的数据已经整合到/setting/reboot/里'
    ))
    def get(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: read and return information of device from file, the file path is set as settings.DEVICE_INFO_PATH.
          response:
            200:
              description: return information of device
              response:
                examples1:
                  {
                      "model": model  /# product model,
                      "serial_no": 12  /# product serial number,
                      "version": v2  /# product serial number,
                  }
        """

        config = configparser.ConfigParser()
        config.read(settings.PRODUCT_INFO_PATH)
        data = {
            'model': config['basic']['model'],
            'serial_no': config['basic']['serial_no'],
            'version': config['basic']['version'],
        }

        return Response(data, status=status.HTTP_200_OK)


class IPInfoView(GenericAPIView):
    permission_classes = (IsConfiEngineer,)
    serializer_class = IPInfoSerializer

    def get(self, request, *args, **kwargs):
        gateway = gateways()['default'][AF_INET][0]
        if settings.DEBUG:
            address = \
            ifaddresses('en0').setdefault(AF_INET, [{'addr': 'No IP addr'}])[0][
                'addr']
            net_mask = \
            ifaddresses('en0').setdefault(AF_INET, [{'addr': 'No IP addr'}])[0][
                'netmask']
        else:
            address = ifaddresses(settings.MGMT).setdefault(AF_INET, [
                {'addr': 'No IP addr'}])[0]['addr']
            net_mask = ifaddresses(settings.MGMT).setdefault(AF_INET, [
                {'addr': 'No IP addr'}])[0]['netmask']
        serializer = IPInfoSerializer(
            {'address': address, 'net_mask': net_mask, 'gateway': gateway})
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        serializer = IPInfoSerializer(data=request.data)
        if request.META.get('SERVER_NAME') == 'testserver':
            # 判断请求是否是来自于测试服务器
            return Response(status=status.HTTP_200_OK)
        else:
            serializer.is_valid(raise_exception=True)
            audit_requests.ip_change(serializer.validated_data['address'])
            set_ip(settings.MGMT, **serializer.validated_data)
            return Response(status=status.HTTP_200_OK)


class TimeInfoView(MultiMethodAPIViewMixin, GenericAPIView):
    permission_classes = (IsConfiEngineer, )
    serializer_class = TimeInfoSerializer
    serializer_method_classes = {
        'GET': TimeInfoSerializer,
        'POST': NTPSettingSerializer,
    }
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_description='获取当前本机时间',
        responses={'200': TimeInfoSerializer()},
    ))
    def get(self, request, *args, **kwargs):
        return Response({'now': timezone.localtime().isoformat()},
                        status=status.HTTP_200_OK)

    @method_decorator(swagger_auto_schema(
        responses={'200': TimeInfoSerializer()},
        operation_description='使用ntp校时服务器校时'
    ))
    def post(self, request, *args, **kwargs):
        """
        使用ntp校时服务器校时
        """
        serializer = self.get_serializer(data=request.data)
        if request.META.get('SERVER_NAME') == 'testserver':
            # 用来判断请求是否是来自于测试服务器
            return Response(status=status.HTTP_200_OK)
        else:
            serializer.is_valid(raise_exception=True)
            try:
                result = set_time.delay(serializer.data['ntp'])
                result.get(10)
            except Exception:
                raise CustomError(error_code=CustomError.NTP_SETTING_ERROR)
            return Response({'now': timezone.localtime().isoformat()},
                            status=status.HTTP_200_OK)


class SettingView(GenericAPIView):
    permission_classes = (IsConfiEngineer,)
    serializer_class = SettingSerializer
    pagination_class = None
    filter_backends = []

    def get(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description:  返回当前设置信息
          response:
            201:
              description: 200
        """
        setting_rec, created = Setting.objects.get_or_create(id=1)
        serializer = SettingSerializer(setting_rec)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        patch:
          request:
            description:  修改设置信息
          response:
            201:
              description: 200
        """
        setting_rec, created = Setting.objects.get_or_create(id=1)
        serializer = SettingSerializer(setting_rec, data=request.data,
                                       partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


class IPLimitView(GenericAPIView):
    permission_classes = (IsConfiEngineer,)
    serializer_class = IPLimitSerializer
    filter_backends = []
    pagination_class = None

    def get(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description:  返回当前设置信息
        """
        setting_rec, created = Setting.objects.get_or_create(id=1)
        serializer = IPLimitSerializer(setting_rec)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        patch:
          request:
            description:  修改 ip 限制相关设置信息
        """
        setting_rec, created = Setting.objects.get_or_create(id=1)
        serializer = IPLimitSerializer(setting_rec, data=request.data,
                                       partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


class RebootView(MultiMethodAPIViewMixin, GenericAPIView):
    permission_classes = (IsConfiEngineer,)
    serializer_class = PasswordSerializer
    serializer_method_classes = {
        'GET': SystemInfoSerializer,
        'POST': PasswordSerializer,
    }

    @method_decorator(swagger_auto_schema(
        responses={'200': SystemInfoSerializer()},
        operation_description='获取当前系统的上次开机时间，本次运行时长，设备型号，'
                              '序列号，软件版本',
        operation_summary='获取本机信息'
    ))
    def get(self, request, *args, **kwargs):
        boot_timestamp = psutil.boot_time()
        boot_time_utc = datetime.datetime.fromtimestamp(boot_timestamp,
                                                        tz=timezone.utc)
        boot_time = timezone.localtime(boot_time_utc).isoformat()

        run_time_seconds = time.time() - boot_timestamp
        run_time_days, days_mod = divmod(run_time_seconds, 24 * 3600)
        run_time_hours, hours_mod = divmod(days_mod, 3600)
        run_time_minutes = hours_mod // 60
        run_time = [run_time_days, run_time_hours, run_time_minutes]

        config = configparser.ConfigParser()
        config.read(settings.PRODUCT_INFO_PATH)
        data = {
            'model': config['basic']['model'],
            'serial_no': config['basic']['serial_no'],
            'version': config['basic']['version'],
            'boot_time': boot_time,
            'run_time': run_time
        }
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description: 重启产品
          response:
            201:
              description: 重启产品成功
              response:
                examples1:
                    {'success': False}
            499:
              description: 重启产品失败
              response:
                examples1:
                    {'error': 1006}
        """
        serializer = PasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not request.user.check_password(
                serializer.validated_data['password']):
            UnifiedForumLog.reboot_log(request)
            raise CustomError({'error': CustomError.ADMIN_PSW_ERROR})
        UnifiedForumLog.reboot_log(request, success=True)
        event = RebootEvenLog(content='设备重启')
        event.generate()
        if settings.DEBUG or settings.TEST:
            return Response({'success': True})

        reboot()

        return Response({'success': False}, status=status.HTTP_200_OK)


class ResetView(APIView):
    permission_classes = (IsConfiEngineer,)

    def post(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description: 重置产品
          response:
            201:
              description: 重置产品成功
              response:
                examples1:
                    {'success': False}
            499:
              description: 重置产品失败
              response:
                examples1:
                    {'error': 1006}
        """

        serializer = PasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if not request.user.check_password(
                serializer.validated_data['password']):
            raise CustomError({'error': CustomError.ADMIN_PSW_ERROR})

        return Response(status=status.HTTP_200_OK)


class DiskView(GenericAPIView):
    """
    Disk setting view:
     GET: get disk usage information.
     POST: modify disk alert threshold and disk auto clean threshold.
    """
    permission_classes = (IsConfiEngineer,)
    serializer_class = DiskSerializer

    @method_decorator(swagger_auto_schema(
        deprecated=True
    ))
    def get(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description:  返回当前存储报警设置和存储使用情况
          response:
            200:
              description: 存储报警设置和存储使用情况
              response:
                examples1:
                          {
                            "disk_alert_percent": 80,
                            "disk_clean_percent": 90,
                            "used": "289.19GB",
                            "percent": "61.0%",
                            "total": "476.74GB"
                          }
        """

        setting_rec, created = Setting.objects.get_or_create()
        serializer = DiskSerializer(setting_rec)
        disk_usage = psutil.disk_usage('/')
        data = serializer.data
        data.update(used=bytes2human(disk_usage.used),
                    percent='{}%'.format(disk_usage.percent),
                    total=bytes2human(disk_usage.total))
        return Response(data, status=status.HTTP_200_OK)

    @method_decorator(swagger_auto_schema(
        deprecated=True
    ))
    def patch(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        patch:
          request:
            description: 修改设置信息
        """
        setting_rec, created = Setting.objects.get_or_create()
        serializer = DiskSerializer(setting_rec, data=request.data,
                                    partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


class SystemSecurityView(GenericAPIView):
    permission_classes = (IsConfiEngineer,)
    serializer_class = SystemSecuritySerializer
    pagination_class = None
    filter_backends = []

    def get(self, request, *args, **kwargs):
        setting_rec, created = Setting.objects.get_or_create()
        serializer = self.get_serializer(setting_rec)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        setting_rec, created = Setting.objects.get_or_create()
        serializer = self.get_serializer(setting_rec, data=request.data,
                                         partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


class ThemeSettingView(MultiMethodAPIViewMixin, GenericAPIView):
    serializer_class = ThemeSerializer
    permission_classes = (IsAdmin, )
    permission_method_classes = {
        'GET': [],
        'PATCH': (IsAdmin, )
    }
    pagination_class = None

    def get(self, request, *args, **kwargs):
        setting, created = Setting.objects.get_or_create()
        serializer = self.get_serializer(setting)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        setting, created = Setting.objects.get_or_create()
        serializer = self.get_serializer(setting, data=request.data,
                                         partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


class LocationView(GenericAPIView):
    serializer_class = LocationSerializer
    permission_classes = (IsConfiEngineer,)
    pagination_class = None
    queryset = Location.objects.all()

    def get(self, request):
        instance = self.get_queryset().first()
        serializer = self.get_serializer(instance)

        return Response(serializer.data)

    @method_decorator(swagger_auto_schema(
        operation_summary='客户地理位置',
        operation_description='前端只需要传city参数即可'
    ))
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class SecurityCenterCleanView(GenericAPIView):
    """
    设置安全中心数据删除的周期
    """
    serializer_class = SecurityCenterCleanSerializer
    permission_classes = (IsConfiEngineer, )

    def get(self, request, *args, **kwargs):
        setting, created = Setting.objects.get_or_create()
        serializer = self.get_serializer(setting)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        setting, created = Setting.objects.get_or_create()
        serializer = self.get_serializer(setting, data=request.data,
                                         partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)