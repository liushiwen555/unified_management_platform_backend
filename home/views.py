import datetime

import dateutil.parser
import psutil
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from auditor.models import AuditSecAlert, AuditSysAlert, AuditLog
from auditor.serializers import AuditSecAlertNoticeSerializer
from base_app.models import Device
from firewall.models import FirewallSecEvent, FirewallSysEvent
from firewall.serializers import FirewallSecEventNoticeSerializer
from log.models import DeviceAllAlert
from log.serializers import DeviceAlertHomeSerializer
from utils.core.permissions import IsSecurityEngineer
from utils.statistics import stat_count, gen_time_list


class SysUsageView(APIView):
    permission_classes = (IsSecurityEngineer,)

    def get(self, request, *args, **kwargs):
        """
        return information of system.
        now:             current local time.
        cpu_percent:     cpu usage percentage.
        memory_percent:  memory usage percentage.
        disk_percent:    disk usage percentage.
        port_stats:      status of monitor port.
        """
        now = timezone.localtime().isoformat()
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage('/').percent
        port_stats = psutil.net_if_stats()[settings.MGMT].isup
        data = {
            'now': now,
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'disk_percent': disk_percent,
            'port_stats': port_stats
        }

        return Response(data, status=status.HTTP_200_OK)


class EventStatView(APIView):
    """
    request params:
    hours                    hours, int, choices=(1, 24, 72)

    return event statistics data.
    traffic_stat_by_time:    [item1, item2, ...], item {'time': isotime, 'traffic': '12B'}
    """
    permission_classes = (IsSecurityEngineer,)

    def get(self, request, *args, **kwargs):
        hours = request.query_params.get('hours')

        try:
            hours = int(hours)
        except (TypeError, ValueError):
            return Response(status=status.HTTP_404_NOT_FOUND)
        end_time = timezone.now()
        if hours == 1 or hours == 24 or hours == 72:
            time_delta = datetime.timedelta(hours=hours)
            start_time = end_time - time_delta
            interval = time_delta/12
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)
        time_list = gen_time_list(start_time, end_time, interval)
        auditor_sec_alert_stat = []
        auditor_sys_alert_stat = []
        auditor_log_stat = []
        firewall_sec_event_stat = []
        firewall_sys_event_stat = []

        auditors = Device.objects.filter(type=Device.AUDITOR).order_by('-registered_time')[0:6]
        firewalls = Device.objects.filter(type=Device.FIRE_WALL).order_by('-registered_time')[0:6]
        for auditor in auditors:
            sec_alert_queryset = AuditSecAlert.objects.filter(last_at__gte=start_time, last_at__lt=end_time)
            sys_alert_queryset = AuditSysAlert.objects.filter(occurred_time__gte=start_time, occurred_time__lt=end_time)
            log_queryset = AuditLog.objects.filter(occurred_time__gte=start_time, occurred_time__lt=end_time)

            sec_alert_stat_by_time = stat_count(sec_alert_queryset, 'last_at', time_list)
            sys_alert_stat_by_time = stat_count(sys_alert_queryset, 'occurred_time', time_list)
            log_stat_by_time = stat_count(log_queryset, 'occurred_time', time_list)
            auditor_sec_alert_stat.append({auditor.name: sec_alert_stat_by_time})
            auditor_sys_alert_stat.append({auditor.name: sys_alert_stat_by_time})
            auditor_log_stat.append({auditor.name: log_stat_by_time})

        for firewall in firewalls:
            sec_event_queryset = FirewallSecEvent.objects.filter(occurred_time__gte=start_time,
                                                                 occurred_time__lt=end_time)
            sys_event_queryset = FirewallSysEvent.objects.filter(occurred_time__gte=start_time,
                                                                 occurred_time__lt=end_time)
            sec_event_stat_by_time = stat_count(sec_event_queryset, 'occurred_time', time_list)
            sys_event_stat_by_time = stat_count(sys_event_queryset, 'occurred_time', time_list)
            firewall_sec_event_stat.append({firewall.name: sec_event_stat_by_time})
            firewall_sys_event_stat.append({firewall.name: sys_event_stat_by_time})

        result = {
            'auditor_sec_alert_stat': auditor_sec_alert_stat,
            'auditor_sys_alert_stat': auditor_sys_alert_stat,
            'auditor_log_stat': auditor_log_stat,
            'firewall_sec_event_stat': firewall_sec_event_stat,
            'firewall_sys_event_stat': firewall_sys_event_stat
        }

        return Response(result, status=status.HTTP_200_OK)


class SecAlertView(APIView):
    """
    接收GET请求，返回最新安全告警记录
    GET请求的参数：
    :param request:
    :return:    [obj, ]，每个obj包括：
                TerminalLog ('id', 'category', 'level', 'content', 'last_at')
    """
    permission_classes = (IsSecurityEngineer,)

    def get(self, request, *args, **kwargs):
        dev_type = request.query_params.get('dev_type')
        try:
            dev_type = int(dev_type)
        except (TypeError, ValueError):
            raise ValidationError({'dev_type': ['dev_type is required and must be a valid int']})
        # if dev_type not in [Device.FIRE_WALL, Device.AUDITOR, Device.GUARD]:
        if dev_type not in [Device.FIRE_WALL, Device.AUDITOR]:
            return Response(status=status.HTTP_404_NOT_FOUND)
        if dev_type == Device.AUDITOR:
            audit_sec_alerts = AuditSecAlert.objects.filter(is_read=False).order_by('-occurred_time')[0:10]
            audit_sec_alerts_serializers = AuditSecAlertNoticeSerializer(audit_sec_alerts, many=True)
            return Response(audit_sec_alerts_serializers.data)
        elif dev_type == Device.FIRE_WALL:
            queryset = FirewallSecEvent.objects.filter(is_read=False).order_by('-occurred_time')[0:10]
            serializer = FirewallSecEventNoticeSerializer(queryset, many=True)
            return Response(serializer.data)


class DeviceStasticInfoView(APIView):
    permission_classes = (IsSecurityEngineer,)

    def get(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 资产统计信息
          response:
            200:
              description: 返回首页资产统计信息
              response:
                examples1:
                          {
                            "device_count": [
                                {
                                    "category": 1,
                                    "count": 8,
                                    "percent": 0
                                },
                                {
                                    "category": 2,
                                    "count": 7,
                                    "percent": 0
                                },
                                {
                                    "category": 3,
                                    "count": 2,
                                    "percent": 0
                                },
                                {
                                    "category": 4,
                                    "count": 3,
                                    "percent": 0
                                }
                            ],
                            "device_statistics": [
                                {
                                    "category": 1,
                                    "alert_count": 5,
                                    "ip_mac_bond_per": 0,
                                    "online_per": 0
                                },
                                {
                                    "category": 2,
                                    "alert_count": 6,
                                    "ip_mac_bond_per": 0,
                                    "online_per": 0
                                },
                                {
                                    "category": 3,
                                    "alert_count": 2,
                                    "ip_mac_bond_per": 0,
                                    "online_per": 0
                                },
                                {
                                    "category": 4,
                                    "alert_count": 3,
                                    "ip_mac_bond_per": 0,
                                    "online_per": 0
                                }
                            ]
                        }
        """

        dev_category_list = list((k) for k, v in Device.CATEGORY_CHOICE)


        dev_count = {}
        dev_count_list = []
        dev_all_count = Device.objects.all().count()

        for cate in dev_category_list:
            r = {}
            count = Device.objects.filter(category=cate).count()
            r['category'] = cate
            r['count'] = count
            if dev_all_count == 0:
                percent = 0
            else:
                percent = round(100*count/dev_all_count)
            r['percent'] = percent
            dev_count_list.append(r)

        dev_count['device_count'] = dev_count_list

        dev_alert_count = {}
        dev_alert_count_list = []

        for cate in dev_category_list:
            r = {}
            dev_cate = Device.objects.filter(category=cate)
            dev_alert_in_dev_cate = DeviceAllAlert.objects.filter(device__category=cate)
            dev_cate_count = dev_cate.count()
            dev_alert_in_dev_cate_count = dev_alert_in_dev_cate.count()

            ip_mac_bond_count = dev_cate.filter(ip_mac_bond=True).count()
            online_count = dev_cate.filter(status=Device.ONLINE).count()

            ip_mac_per = (100
                          if dev_cate_count == 0
                          else round(100 * ip_mac_bond_count / dev_cate_count))
            online_per = (100
                          if dev_cate_count == 0
                          else round(100 * online_count / dev_cate_count))

            r['category'] = cate
            r['alert_count'] = dev_alert_in_dev_cate_count
            r['ip_mac_bond_per'] = ip_mac_per
            r['online_per'] = online_per

            dev_alert_count_list.append(r)

        dev_alert_count['device_statistics'] = dev_alert_count_list

        final_r = dev_count
        final_r.update(dev_alert_count)
        return Response(final_r)


class DeviceAlertInfo(APIView):
    permission_classes = (IsSecurityEngineer,)

    def get(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 首页告警统计信息
          response:
            200:
              description: 返回首页告警统计信息
              response:
                examples1:
                          {
                                "total_count":100 /# 总告警数量,
                                "unresolved_count":100 /# 总告警未处理数量,
                                "unresolved_high_level_count":100 /# 总告警未处理高危数量,
                                "last_7_resolved_per":100 /# 7 天告警处理比例,
                                "last_24_resolved_per":100 /# 24 小时告警处理比例,
                                "resolved_per":100 /# 总告警处理比例,
                          }
        """
        total_count = DeviceAllAlert.objects.count()
        unresolved_count = DeviceAllAlert.objects.filter(status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()
        unresolved_high_level_count = DeviceAllAlert.objects.filter(status_resolved=DeviceAllAlert.STATUS_UNRESOLVED, level=DeviceAllAlert.LEVEL_HIGH).count()

        last_24 = timezone.localtime() - datetime.timedelta(days=1)
        last_24_alert = DeviceAllAlert.objects.filter(occurred_time__gte=last_24).count()
        last_24_alert_unresolved = DeviceAllAlert.objects.filter(occurred_time__gte=last_24, status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()

        last_7 = timezone.localtime() - datetime.timedelta(days=7)
        last_7_alert = DeviceAllAlert.objects.filter(occurred_time__gte=last_7).count()
        last_7_alert_unresolved = DeviceAllAlert.objects.filter(occurred_time__gte=last_7, status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()

        if last_7_alert_unresolved == 0:
            last_7_resolved_per = 100
        else:
            last_7_resolved_per = round(100* (last_7_alert-last_7_alert_unresolved)/last_7_alert)

        if last_24_alert_unresolved == 0:
            last_24_resolved_per = 100
        else:
            last_24_resolved_per = round(100*(last_24_alert-last_24_alert_unresolved)/last_24_alert)

        if unresolved_count == 0:
            resolved_per = 100
        else:
            resolved_per = round(100*(total_count-unresolved_count)/total_count)

        r = dict(
            total_count=total_count,
            unresolved_count=unresolved_count,
            unresolved_high_level_count=unresolved_high_level_count,
            last_7_resolved_per=last_7_resolved_per,
            last_24_resolved_per=last_24_resolved_per,
            resolved_per=resolved_per,
        )

        return Response(r)


class TopFiveAlertInfo(APIView):
    permission_classes = (IsSecurityEngineer,)

    def get(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: top 5 告警类型信息
          response:
            200:
              description: top 5 告警类型信息，只会显示 5 种信息
              response:
                examples1:
                      {
                        "account_manage": 11 /# 账号管理类型告警数量,
                        "device_manage": 4 /# 本机设置类型告警数量,
                        "monitor_assets": 3 /# 监控资产类型告警数量,
                        "strategt_manage": 1 /# 策略管理类型告警数量,
                        "login_logout": 1 /# 登录登出类型告警数量,
                        "all_assets": 0 /# 全部资产类型告警数量,
                        "auditor_blacklist_alert": 0 /# 黑名单告警类型告警数量,
                        "auditor_whitelist_alert": 0 /# 白名单告警类型告警数量,
                        "auditor_device_error": 0 /# 资产异常告警类型告警数量,
                        "auditor_running_alert": 0 /# 运行告警类型告警数量,
                        "auditor_running_log": 0 /# 运行日志类型告警数量,
                        "firewall_event": 0 /# 防火墙事件类型告警数量，
                      }
        """
        type_list = list(k for k, v in DeviceAllAlert.TYPE_CHOICES)

        r_ = []
        for type_ in type_list:
            r = {'type': type_}
            t = DeviceAllAlert.objects.filter(type=type_).count()
            all_count = DeviceAllAlert.objects.all().count()

            per = 0 if all_count == 0 else round(100 * t / all_count)

            r['percent'] = per
            r_.append(r)

        sorted_r = sorted(r_, key=lambda x: x.get('percent'), reverse=True)
        sorted_r_return = sorted_r[0:5] if len(sorted_r) >= 5 else sorted_r
        return Response(sorted_r_return)


class NewAlertInfo(GenericAPIView):
    serializer_class = DeviceAlertHomeSerializer
    permission_classes = (IsSecurityEngineer,)

    def get(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取最新的 10 条告警信息,不足十条就全部返回
          response:
            200:
                description: 最新的 10 条告警信息,不足十条就全部返回
                response:
                    examples1:
                          [{
                            "id": 52,
                            "occurred_time": "2020-04-15T15:19:01.288512+08:00",
                            "sec_desc": "Tough want we church apply sea. Bit remain director your."
                          },]
        """

        device_alert_count = DeviceAllAlert.objects.count()
        device_alert = DeviceAllAlert.objects.all().order_by('occurred_time')
        device_alert_ordered = DeviceAllAlert.objects.order_by('-occurred_time')

        device_alert = (device_alert_ordered[0:10]
                        if device_alert_count >= 10
                        else device_alert)

        data = DeviceAlertHomeSerializer(device_alert, many=True).data
        return Response(data)


class AlertQueryInfo(APIView):
    permission_classes = (IsSecurityEngineer,)

    def _get_alert_count_by_time(self, time):

        now = time
        zero_today = now - datetime.timedelta(hours=now.hour, minutes=now.minute, seconds=now.second,
                                              microseconds=now.microsecond)
        last_zero_today = zero_today + datetime.timedelta(hours=24, minutes=00, seconds=00)
        alert_in_time = DeviceAllAlert.objects.filter(occurred_time__lt=last_zero_today, occurred_time__gt=zero_today).count()

        return alert_in_time

    def get(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 根据前端提供的 query 返回查询的数据结果，待前端提高查询的关键词
          response:
            200:
              description: 待补充，响应数据待补充
        """
        period = self.request.query_params.get('period')
        custom_period_start_time = self.request.query_params.get('start_time')
        custom_period_end_time = self.request.query_params.get('end_time')

        if period in ['1', '7', '30', '3']:
            period = int(period)

        if period == 1:
            period = 24
            current_time = timezone.localtime()
            first_point = current_time - datetime.timedelta(hours=period)
            total_alert = DeviceAllAlert.objects.filter(occurred_time__lt=current_time, occurred_time__gt=first_point)
            total_count = total_alert.count()
            unread_count = total_alert.filter(status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()

            query_alert = []

            i = 0
            while i < 24:
                middle_point = first_point
                end_point = middle_point + datetime.timedelta(hours=1)
                device_alert_count = DeviceAllAlert.objects.filter(occurred_time__lt=end_point, occurred_time__gt=middle_point).count()
                first_point = end_point
                i += 1
                query_alert.append(device_alert_count)

            r = {
                'alert_query_info': query_alert,
                'total_count': total_count,
                'unread_count': unread_count
            }
            return Response(r)

        if period in [3, 7, 30]:
            current_time = timezone.localtime()

            first_point = current_time - datetime.timedelta(days=(period))

            total_alert = DeviceAllAlert.objects.filter(occurred_time__lt=current_time, occurred_time__gt=first_point)
            total_count = total_alert.count()
            unread_count = total_alert.filter(status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()

            query_alert = []

            i = 1
            while i < period+1:
                first_point = first_point + datetime.timedelta(days=1)
                alert_in_point_count = self._get_alert_count_by_time(first_point)
                query_alert.append(alert_in_point_count)
                i += 1

            r = {
                'alert_query_info': query_alert,
                'total_count': total_count,
                'unread_count': unread_count,
            }

            return Response(r)

        if custom_period_start_time and custom_period_end_time:

            s_time = custom_period_start_time
            e_time = custom_period_end_time
            s_time = dateutil.parser.parse(s_time)
            e_time = dateutil.parser.parse(e_time)
            period_days = (e_time - s_time).days + 1

            first_point = e_time - datetime.timedelta(days=(period_days))

            total_alert = DeviceAllAlert.objects.filter(occurred_time__lt=e_time, occurred_time__gt=s_time)
            total_count = total_alert.count()
            unread_count = total_alert.filter(status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()

            query_alert = []

            i = 0
            while i < period_days:
                first_point = first_point + datetime.timedelta(days=1)
                alert_in_point_count = self._get_alert_count_by_time(first_point)
                query_alert.append(alert_in_point_count)
                i += 1

            r = {
                'alert_query_info': query_alert,
                'total_count': total_count,
                'unread_count': unread_count,
            }

            return Response(r)
