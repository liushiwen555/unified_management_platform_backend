import os
import re
import time
from abc import ABC, abstractmethod
from typing import List, Union, Dict, Tuple

import django
from django.utils import timezone
from pysnmp.hlapi import *

os.environ.setdefault("DJANGO_SETTINGS_MODULE",
                      "unified_management_platform.settings")
django.setup()

from base_app.models import Device
from snmp.models import SNMPRule, SNMPSetting, SNMPData, SNMPTemplate
from utils.core.exceptions import SNMPError
from log.tasks import ping_status
from log.security_event import AssetsCPUEvent, AssetsMemoryEvent, AssetsDiskEvent, ProcessEvent

AUTH_PROTOCOLS = {
    SNMPSetting.AUTH_SHA: usmHMAC128SHA224AuthProtocol,
    SNMPSetting.AUTH_MD5: usmHMACMD5AuthProtocol,
}

PRIV_PROTOCOLS = {
    SNMPSetting.PRIV_DES: usmDESPrivProtocol,
    SNMPSetting.PRIV_3DES: usm3DESEDEPrivProtocol,
    SNMPSetting.PRIV_AES128: usmAesCfb128Protocol,
    SNMPSetting.PRIV_AES192: usmAesCfb192Protocol,
    SNMPSetting.PRIV_AES256: usmAesCfb256Protocol,
}

pattern = re.compile(r'.*? = (.*?: )?(.*)')
pattern_disk = re.compile(r'.*? = (\w+: )?(.*)')


class AbstractSNMPClient(ABC):

    @abstractmethod
    def snmp_get(self):
        pass

    @abstractmethod
    def cmd_parameters(self):
        pass

    @abstractmethod
    def notify(self, result) -> Dict:
        pass

    def get_result(self, response: str):
        groups = pattern.match(response).groups()
        return groups[-1]

    def safe_divide(self, a, b, precision=2):
        try:
            res = round(a / b, precision)
        except ZeroDivisionError:
            res = 0
        return res


class SNMPConfig(object):
    def __init__(self):
        self._config = {}

    def register(self, oid: Union[str, List], method: str, name: str):
        def wrapper(cls: AbstractSNMPClient):
            self._config[name] = {
                'method': method,
                'client': cls,
                'oid': oid,
            }
            return cls

        return wrapper

    def get_config(self, name: str):
        return self._config.get(name, {'method': 'get', 'client': GetClient,
                                       'oid': []})


snmp_config = SNMPConfig()


class SNMPClient(AbstractSNMPClient):
    def __init__(self, device: Device, interval=1, current=None):
        self._engine = SnmpEngine()
        self._device: Device = device
        tmp = Device.objects.select_related(
            'snmpsetting', 'snmpsetting__template').only(
            'snmpsetting', 'snmpsetting__template').get(
            id=self._device.id)
        self._setting: SNMPSetting = tmp.snmpsetting
        self._template: SNMPTemplate = tmp.snmpsetting.template
        self._rules: List[SNMPRule] = self._template.rules.all()
        self._oids = []
        self._watchers = {}
        self._interval = interval
        self._result = {}
        self._processed = False
        self._active = None
        self.current = current

        self.set_current_run_time()

    def set_current_run_time(self):
        if not self.current:
            self.current = timezone.now()
        self._setting.last_run_time = self.current
        self._setting.save()

    def snmp_get(self) -> Dict:
        """
        ???????????????snmp_get??????
        ????????????
            1. ????????????walk????????????????????????????????????????????????OID???Client????????????
            2. ????????????get?????????????????????????????????????????????????????????????????????oid?????????SNMPClient
               ?????????_oids????????????????????????
        :return: [{'name': '????????????', 'data': 'xxx'}, ...]
        """
        if not self.is_device_active():
            self._processed = True
            return {}

        for rule in self._rules:
            config = snmp_config.get_config(rule.field)
            client = config['client']  # ??????????????????????????????????????????Client???
            temp = client(rule, self, self._interval).snmp_get()
            if temp:
                self._result.update(temp)
        if self._oids:
            # ??????get????????????snmp_get????????????????????????????????????oid?????????SNMPClient???oids
            # ????????????????????????_snmp_get????????????
            self._result.update(self.snmp_batch_get(self._oids))
        self._processed = True  # ???????????????????????????
        return self.result

    @property
    def result(self):
        return self._result

    def is_device_active(self) -> bool:
        """
        ?????????????????????????????????ping????????????????????????
        """
        if self._active is None:
            self._active = ping_status(self._device.ip)
        return self._active

    def save_data(self):
        if not self._processed:
            raise SNMPError('???????????????SNMP?????????????????????snmp_get()')
        data = SNMPData(device=self._device, **self.result)
        data.save()

        self.check_device_healthy()

    def check_device_healthy(self):
        """
        ??????????????????????????????
        ??????CPU????????????80
        ????????????????????????80
        ??????????????????????????????80
        :return:
        """
        cpu = AssetsCPUEvent(self._result.get('cpu_in_use', 0),
                             device=self._device)
        cpu.generate()
        memory = AssetsMemoryEvent(self._result.get('memory_in_use', 0),
                                   device=self._device)
        memory.generate()
        partition_usage = self._result.get('partition_usage', [])
        for p in partition_usage:
            partition = AssetsDiskEvent(p['percent'], device=self._device,
                                        partition=p['name'])
            partition.generate()
        process = ProcessEvent(self._result.get('process_count', 0),
                               self.current, device=self._device)
        process.generate()

    def snmp_batch_get(self, oids: List[Tuple[str, ObjectType]]) -> Dict:
        """
        ???????????????_oids????????????snmp-get??????????????????GetClient??????????????????????????????????????????
        ???????????????_oid????????????
        :param oids:
        :return: [{'name': 'xxx', 'data': 13}, {'name': 'xxxx', 'data': 23}]
        """
        iterator = getCmd(
            *self.cmd_parameters(),
            *[o[1] for o in oids],
        )
        result = {}

        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication:
            print(error_indication)
        else:
            if error_status:  # SNMP agent errors
                print('%s at %s' % (error_status.prettyPrint(), var_binds[
                    int(error_index) - 1] if error_index else '?'))
            else:
                for i, var_bind in enumerate(
                        var_binds):  # SNMP response contents
                    res = ' = '.join([x.prettyPrint() for x in var_bind])
                    temp = {
                        'name': oids[i][0],
                        'data': self.get_result(res),
                    }
                    if temp['data'] == 'No Such Object currently exists at this OID':
                        continue
                    result.update(self.notify(temp))
        return result

    def notify(self, result: Dict) -> Dict:
        """
        ?????????Client??????????????????????????????????????????
        ???????????????????????????????????????????????????
        ?????????????????????????????????????????????????????????????????????????????????/???/??????????????????
        :param result: ????????????snmp????????????????????????
        :return: ???????????????client???????????????????????????
        """
        client: AbstractSNMPClient = self._watchers.get(result['name'])
        if not client:
            return {result['name']: result['data']}
        else:
            return client.notify(result)

    def register(self, oid: Tuple[str, ObjectType]):
        """
        GetClient??????snmp_get???????????????oid?????????SNMPClient????????????SNMPClient????????????
        :param oid: ???'name', OID)
        """
        self._oids.append(oid)

    def register_watcher(self, name: str, client: AbstractSNMPClient):
        self._watchers[name] = client

    def cmd_parameters(self) -> List:
        """
        ?????????snmp???????????????get???next???????????????
        getCmd(
            SNMPEngine(),
            CommunityData(),
            UdpTransportTarget(),
            ContextData(),
        )
        :return:
        """
        return [
            self._engine,
            self._authentication(),
            self._transport_target(),
            ContextData(),
        ]

    def _transport_target(self):
        return UdpTransportTarget((self._device.ip, self._setting.port))

    def _authentication(self) -> Union[CommunityData, UsmUserData]:
        if self._setting.version in [SNMPSetting.SNMP_V1, SNMPSetting.SNMP_V2]:
            return self._community()
        else:
            if self._setting.security_level == SNMPSetting.NO_AUTH_NO_PRIV:
                return self._no_auth_no_priv()
            elif self._setting.security_level == SNMPSetting.AUTH_NO_PRIV:
                return self._auth_no_priv()
            else:
                return self._auth_priv()

    def _community(self) -> CommunityData:
        """
        SNMP V1/V2?????????????????????
        """
        return CommunityData(self._setting.community)

    def _no_auth_no_priv(self) -> UsmUserData:
        """
        SNMP V3?????????????????????????????????????????????
        """
        return UsmUserData(userName=self._setting.username)

    def _auth_no_priv(self) -> UsmUserData:
        """
        SNMP V3??????????????????????????????????????????????????????
        """
        return UsmUserData(
            userName=self._setting.username,
            authKey=self._setting.auth_password,
            authProtocol=AUTH_PROTOCOLS[self._setting.auth]
        )

    def _auth_priv(self) -> UsmUserData:
        """
        SNMP V3?????????????????????????????????????????????
        """
        return UsmUserData(
            userName=self._setting.username,
            authKey=self._setting.auth_password,
            privKey=self._setting.priv_password,
            authProtocol=AUTH_PROTOCOLS[self._setting.auth],
            privProtocol=PRIV_PROTOCOLS[self._setting.priv],
        )


class BaseClient(AbstractSNMPClient):
    def __init__(self, rule: SNMPRule, client: SNMPClient, *args, **kwargs):
        self.rule = rule
        self.client = client

    def snmp_get(self):
        """
        ???oid?????????SNMPClient???????????????????????????????????????????????????????????????????????????????????????
        ?????????????????????Dict???????????????
        """
        self.client.register(
            (self.rule.field, ObjectType(ObjectIdentity(self.rule.oid[0]))))

    def snmp_batch_get(self, oids: List[Tuple[str, ObjectType]]):
        """
        ????????????oid?????????
        :param oids: [('name', 'oid'), ...]
        :return:
        """
        return self.client.snmp_batch_get(oids)

    def snmp_walk(self) -> List:
        """
        walk?????????????????????????????????????????????oid????????????????????????????????????????????????????????????
        SNMPClient
        :return: [['oid.1', 'oid.2', 'oid.3'], ...]
        """
        iterator = nextCmd(
            *self.cmd_parameters(),
            *[ObjectType(ObjectIdentity(i)) for i in self.rule.oid],
            lexicographicMode=False
        )
        result = []

        for errorIndication, errorStatus, errorIndex, varBinds in iterator:
            if errorIndication:
                print(errorIndication)
            else:
                if errorStatus:  # SNMP agent errors
                    print('%s at %s' % (errorStatus.prettyPrint(), varBinds[
                        int(errorIndex) - 1] if errorIndex else '?'))
                else:
                    one = []
                    for varBind in varBinds:  # SNMP response contents
                        res = ' = '.join([x.prettyPrint() for x in varBind])
                        one.append(self.get_result(res))
                    result.append(one)
        return result

    def cmd_parameters(self):
        return self.client.cmd_parameters()

    def notify(self, result: Dict) -> Dict:
        return {result['name']: result['data']}


@snmp_config.register('.1.3.6.1.2.1.1.1.0', 'get', 'system_info')
@snmp_config.register('.1.3.6.1.2.1.1.5.0', 'get', 'hostname')
class GetClient(BaseClient):
    pass


@snmp_config.register('.1.3.6.1.2.1.25.1.1.0', 'get', 'system_runtime')
class SystemRunTimeClient(BaseClient):
    DAY = 60 * 60 * 24
    HOUR = 60 * 60
    MINUTE = 60

    def snmp_get(self):
        super().snmp_get()
        self.client.register_watcher(self.rule.field, self)

    def notify(self, result: Dict) -> Dict:
        if not result:
            return {}
        duration = result['data']

        return {self.rule.field: self.calculate_runtime(duration)}

    def calculate_runtime(self, duration) -> str:
        t = int(duration) / 100
        day, t = divmod(t, self.DAY)
        hour, t = divmod(t, self.HOUR)
        minute, second = divmod(t, self.MINUTE)

        return f'{int(day)},{int(hour)},{int(hour)},{int(minute)}'


@snmp_config.register(['.1.3.6.1.4.1.2021.13.15.1.1.2',  # ????????????
                       '.1.3.6.1.4.1.2021.13.15.1.1.5',  # ?????????????????? KB
                       '.1.3.6.1.4.1.2021.13.15.1.1.6'],  # ?????????????????? KB
                      'walk', 'disk_info')
class DiskClient(BaseClient):
    def __init__(self, rule, client, interval=1):
        super().__init__(rule, client)
        self._interval = interval

    def snmp_get(self) -> Dict[str, List]:
        start = time.time()
        result1 = self.snmp_walk()
        time.sleep(self._interval)
        result2 = self.snmp_walk()
        end = time.time()
        if result1 and result2:
            result = self.calculate_disk(result1, result2, (end-start))
            return {self.rule.field: result}
        else:
            return {}

    def calculate_disk(self, result1: List, result2: List, interval: float):
        result = []
        for i in range(len(result1)):
            r1, r2 = result1[i], result2[i]
            result.append(
                {
                    'name': r1[0],
                    'read': self.safe_divide(int(r2[1]) - int(r1[1]),  interval),
                    'write': self.safe_divide(int(r2[2]) - int(r1[2]), interval),
                }
            )
        return result


@snmp_config.register('.1.3.6.1.2.1.25.3.3.1.2', 'walk', 'cpu_usage')
class CPUUsageClient(BaseClient):
    def snmp_get(self) -> Dict:
        result = self.snmp_walk()
        if not result:
            return {}
        cpu_cores = len(result)
        cpu_usage = self.calculate_usage(result)
        return {
            'cpu_in_use': round(cpu_usage, 2),
            'cpu_cores': cpu_cores
        }

    def calculate_usage(self, cpu_usage):
        """
        ????????????????????????????????????????????????????????????
        :param cpu_usage: [['18'], ['11'], ['4'], ['10']]
        :return: ???????????????
        """
        total = 0
        for i in cpu_usage:
            total += int(i[0])
        return self.safe_divide(total, len(cpu_usage))


@snmp_config.register('.1.3.6.1.2.1.25.4.2.1.2', 'walk', 'process_count')
class ProcessClient(BaseClient):
    def snmp_get(self) -> Dict[str, int]:
        result = self.snmp_walk()
        if not result:
            return {}
        return {self.rule.field: len(result)}


@snmp_config.register(['.1.3.6.1.4.1.2021.4.5.0',  # ?????????
                       '.1.3.6.1.4.1.2021.4.6.0',  # ????????????
                       '.1.3.6.1.4.1.2021.4.14.0',  # buffer??????
                       '.1.3.6.1.4.1.2021.4.15.0',  # cache??????
                       '.1.3.6.1.4.1.2021.4.3.0',  # swap?????????
                       '.1.3.6.1.4.1.2021.4.4.0'  # swap????????????
                       ], 'get', 'memory_usage')
class MemoryUsage(BaseClient):
    """
    ???????????????????????????????????????????????????psutil????????????????????????
    https://serverfault.com/questions/640459/snmp-memory-values-do-not-match-free
    """

    def snmp_get(self) -> Dict:
        oids = [
            ('total_memory', ObjectType(ObjectIdentity(self.rule.oid[0]))),
            ('avail_memory', ObjectType(ObjectIdentity(self.rule.oid[1]))),
            ('buffer_memory', ObjectType(ObjectIdentity(self.rule.oid[2]))),
            ('cache_memory', ObjectType(ObjectIdentity(self.rule.oid[3]))),
            ('total_swap_memory', ObjectType(ObjectIdentity(self.rule.oid[4]))),
            ('avail_swap_memory', ObjectType(ObjectIdentity(self.rule.oid[5]))),
        ]
        result = self.snmp_batch_get(oids)
        if not result:
            return {}
        return self.calculate_usage(result)

    def calculate_usage(self, result) -> Dict:
        for key, value in result.items():
            result[key] = int(value) / 1024
        memory_used = self.get_memory_used(result)
        swap_memory_used = result['total_swap_memory'] - result[
            'avail_swap_memory']
        new_result = {
            'memory_used': int(memory_used),
            'memory_in_use': self.safe_divide(
                memory_used * 100, result['total_memory'], 2),
            'swap_memory_used': int(swap_memory_used),
            'swap_memory_in_use': self.safe_divide(
                swap_memory_used * 100, result['total_swap_memory'], 2)
        }
        new_result.update({
            'total_memory': int(result['total_memory']),
            'total_swap_memory': int(result['total_swap_memory']),
        })
        return new_result

    def get_memory_used(self, result: Dict) -> float:
        """
        ????????????????????????????????????
        total - avail - cache - buffer
        :param result: snmp????????????????????????
        :return: used memory
        """
        free = (result['avail_memory'] + result['buffer_memory'] +
                result['cache_memory'])
        return result['total_memory'] - free


@snmp_config.register(['.1.3.6.1.4.1.2021.9.1.2',
                       '.1.3.6.1.4.1.2021.9.1.6',
                       '.1.3.6.1.4.1.2021.9.1.8'], 'walk', 'partition_usage')
class DiskPartitionUsageClient(BaseClient):
    def snmp_get(self) -> Dict[str, List]:
        disk_usage = self.snmp_walk()
        if not disk_usage:
            return {}
        return self.calculate_disk_usage(disk_usage)

    def calculate_disk_usage(self, disk_usage) -> Dict:
        partition_set = set()
        result = []
        disk_in_use = 0
        disk_total = 0
        disk_used = 0
        for one in disk_usage:
            if one[0] in partition_set:
                continue
            partition_set.add(one[0])
            temp = {
                'name': one[0],
                'total': round(int(one[1]) / 1024, 2),
                'used': round(int(one[2]) / 1024, 2),
            }
            disk_total += temp['total']
            disk_used += temp['used']
            if temp['name'] == '/':
                disk_in_use = self.safe_divide(
                    temp['used'] * 100, temp['total'], 2)
            temp['percent'] = self.safe_divide(
                temp['used'] * 100, temp['total'], 2)
            result.append(temp)


        return {self.rule.field: result, 'disk_in_use': disk_in_use,
                'disk_total': disk_total, 'disk_used': disk_used}


@snmp_config.register(['.1.3.6.1.2.1.31.1.1.1.1',
                       '.1.3.6.1.2.1.2.2.1.10',
                       '.1.3.6.1.2.1.2.2.1.16'], 'walk', 'network_usage')
class NetworkUsageClient(BaseClient):
    NON_PHYSICAL_INTERFACE = ['lo', 'docker', 'br', 'veth']

    def __init__(self, rule, client, interval=1):
        super().__init__(rule, client)
        self._interval = interval

    def snmp_get(self) -> Dict:
        start_time = time.time()
        result1 = self.snmp_walk()
        time.sleep(self._interval)
        result2 = self.snmp_walk()
        end_time = time.time()
        if result1 and result2:
            return self.calculate_network_usage(result1, result2,
                                                end_time-start_time)
        else:
            return {}

    def calculate_network_usage(self, result1: List[Dict],
                                result2: List[Dict], interval) -> Dict:
        result = []
        network_in_speed = 0
        network_out_speed = 0

        for i in range(len(result1)):
            r1, r2 = result1[i], result2[i]
            temp = {
                'name': r1[0],
                'in': self.safe_divide(
                    int(r2[1]) - int(r1[1]), interval * 1024, 2),  # KB
                'out': self.safe_divide(
                    int(r2[2]) - int(r1[2]), interval * 1024, 2),  # KB
            }
            result.append(temp)

            if self.is_physical_interface(temp['name']):
                network_in_speed += temp['in']
                network_out_speed += temp['out']
        return {
            self.rule.field: result,
            'network_in_speed': round(network_in_speed, 2),
            'network_out_speed': round(network_out_speed, 2),
        }

    @classmethod
    def is_physical_interface(cls, interface: str):
        """
        ??????????????????????????????????????????lo???docker??????????????????
        :param interface: ?????????
        :return:
        """
        for i in cls.NON_PHYSICAL_INTERFACE:
            if i in interface:
                return False
        if '_' in interface and len(interface.split('_')[-1]) <= 2:
            return False
        return True


@snmp_config.register(['.1.3.6.1.2.1.25.2.3.1.3',  # ????????????
                       '.1.3.6.1.2.1.25.2.3.1.4',  # ?????????
                       '.1.3.6.1.2.1.25.2.3.1.5',  # ?????????
                       '.1.3.6.1.2.1.25.2.3.1.6',  # ???????????????
                       ], 'walk', 'win_partition')
class WinPartitionUsage(BaseClient):
    DISK_NAME = re.compile(r'(\w+:).*')

    def snmp_get(self) -> Dict:
        result = self.snmp_walk()
        if not result:
            return {}
        data = []
        disk_total = 0
        used_total = 0
        for disk in result:
            # ['D:\\ Label:  Serial Number c475b122', '4096', '46862591', '13785807']
            # ['disk_name', '?????????', '?????????', '?????????']
            if 'Memory' in disk[0]:
                continue
            for i in range(1, len(disk)):
                disk[i] = int(disk[i])
            total = round(disk[1] * disk[2] / 1024 / 1024)
            used = round(disk[1] * disk[3] / 1024 / 1024)
            percent = self.safe_divide(disk[3] * 100, disk[2], 2)

            disk_total += total
            used_total += used

            data.append({
                'name': self.get_disk_name(disk[0]),
                'percent': percent,
                'total': total,
                'used': used,
            })

        return {'partition_usage': data, 'disk_total': disk_total,
                'disk_used': used_total,
                'disk_in_use': self.safe_divide(used_total * 100, disk_total, 2)}

    def get_result(self, response: str):
        return pattern_disk.match(response).groups()[-1]

    def get_disk_name(self, disk: str):
        """
        ???"D:\\ Label:  Serial Number c475b122"???????????????????????????????????????
        :param disk: "D:\\ Label:  Serial Number c475b122"
        :return: D:
        """
        try:
            return self.DISK_NAME.match(disk).groups()[0]
        except AttributeError:
            return '?????????'
        except IndexError:
            return '?????????'


@snmp_config.register(['.1.3.6.1.2.1.25.2.3.1.3',  # ????????????
                       '.1.3.6.1.2.1.25.2.3.1.4',  # ?????????
                       '.1.3.6.1.2.1.25.2.3.1.5',  # ?????????
                       '.1.3.6.1.2.1.25.2.3.1.6',  # ???????????????
                       ], 'walk', 'win_memory')
class WindowsMemoryUsage(BaseClient):
    def snmp_get(self):
        result = self.snmp_walk()
        data = {}
        for disk in result:
            for i in range(1, len(disk)):
                disk[i] = int(disk[i])

            if 'Physical' in disk[0]:
                data['total_memory'] = round(disk[1] * disk[2] / 1024 / 1024)
                data['memory_used'] = round(disk[1] * disk[3] / 1024 / 1024)
                data['memory_in_use'] = round(disk[3] / disk[2] * 100, 2)
            if 'Virtual' in disk[0]:
                data['total_swap_memory'] = round(
                    disk[1] * disk[2] / 1024 / 1024)
                data['swap_memory_used'] = round(
                    disk[1] * disk[3] / 1024 / 1024)
                data['swap_memory_in_use'] = round(disk[3] / disk[2] * 100, 2)
        return data


if __name__ == '__main__':
    d = Device.objects.get(id=72)
    snmp_client = SNMPClient(d, 10)
    import pprint
    res = snmp_client.snmp_get()
    pprint.pprint(res)
    snmp_client.save_data()
