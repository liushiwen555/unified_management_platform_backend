import psutil
from django.conf import settings
from psycopg2 import connect

from base_app.models import TerminalLog
from log.models import UnifiedForumLog, DeviceAllAlert, SecurityEvent
from log.security_event import DiskEvent, DiskCleanEvent
from setting.models import Setting
from unified_log.elastic import client as elastic_client
from utils.helper import get_subclasses


class DiskCheck(object):
    def __init__(self, setting: Setting, test=False):
        self.alert_threshold = setting.disk_alert_percent
        self.clean_threshold = setting.disk_clean_percent
        self.test = test

    def run(self):
        self.generate_alarm()

    def generate_alarm(self):
        percent = self.get_percent()
        self.generate_event(percent)
        self.generate_log(percent)
        self.do_clean(percent)

    def get_percent(self) -> float:
        return psutil.disk_usage('/').percent

    def generate_event(self, percent):
        if percent > self.alert_threshold:
            event = DiskEvent(percent=percent)
            event.generate()

        if percent > self.clean_threshold:
            event = DiskCleanEvent(percent=percent)
            event.generate()

    def generate_log(self, percent):
        if percent > self.alert_threshold:
            data = {
                'type': UnifiedForumLog.TYPE_STORAGE,
                'content': f'存储空间使用率达到{self.alert_threshold}%',
                'result': True,
                'category': UnifiedForumLog.CATEGORY_SYSTEM,
                'ip': '127.0.0.1'  # 本地 ip 地址
            }
            UnifiedForumLog.objects.create(**data)

        if percent > self.clean_threshold:
            data = {
                'type': UnifiedForumLog.TYPE_STORAGE,
                'content': f'存储空间使用率达到{self.clean_threshold}%，释放存储空间',
                'result': True,
                'category': UnifiedForumLog.CATEGORY_SYSTEM,
                'ip': '127.0.0.1'  # 本地 ip 地址
            }
            UnifiedForumLog.objects.create(**data)

    def do_clean(self, percent):
        if percent < self.clean_threshold or self.test:
            return None
        connection_parameters = {
            'host': settings.DATABASES.get('default').get('HOST'),
            'port': settings.DATABASES.get('default').get('PORT'),
            'database': settings.DATABASES.get('default').get('NAME'),
            'user': settings.DATABASES.get('default').get('USER'),
            'password': settings.DATABASES.get('default').get('PASSWORD'),
        }

        conn = connect(**connection_parameters)
        conn.autocommit = True
        log_list = [UnifiedForumLog, DeviceAllAlert, SecurityEvent]
        log_list.extend(get_subclasses(TerminalLog))
        # 达到存储使用覆盖阈值后，需要删除告警管理和日志管理各10%的历史数据
        # 删除postgres里的数据
        for model in log_list:
            table_name = model.objects.model._meta.db_table

            # Delete the earliest 10% rows of model.
            if model.objects.count() > 1:
                min_id = model.objects.earliest('id').id
                max_id = model.objects.latest('id').id
                mid_id = min_id + int((max_id - min_id) * 0.1)
                with conn.cursor() as cursor:
                    model_del_statement = 'DELETE FROM {} WHERE id BETWEEN {} AND {};'. \
                        format(table_name, min_id, mid_id)

                    cursor.execute(model_del_statement)
        # 清理elasticsearch的日志内容
        elastic_client.delete_index_by_percent('log-*', 0.1)
