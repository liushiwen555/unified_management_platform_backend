from typing import List, Set

from base_app.models import Device
from statistic.models import IPDistribution


class IPDistributionHelper(object):
    def __init__(self, ips=None):
        if not ips:
            self.ips: List[str] = list(Device.objects.values_list('ip', flat=True))
        else:
            self.ips = ips
        self.ip_set: Set[str] = set(self.ips)
        self.previous, _ = IPDistribution.objects.get_or_create(id=1)
        self.distribution = {}

    @property
    def count(self) -> int:
        """
        :return: 返回IP总数
        """
        return len(self.ip_set)

    @property
    def segments(self):
        return len(self.distribution)

    @property
    def ip_distribution(self):
        return self.distribution

    def analyze_distribution(self):
        for ip in self.ip_set:
            gateway = '.'.join(ip.split('.')[:3] + ['1/24'])
            if gateway in self.distribution:
                s = self.distribution[gateway]
                s['ip_count'] += 1
                s['used'].append(ip)
            else:
                self.distribution[gateway] = {
                    'gateway': gateway,
                    'ip_count': 1,
                    'update_count': 0,
                    'used': [ip],
                    'updated': [],
                }
        for gateway in self.distribution.keys():
            self.update_ip(gateway)

        return self.distribution

    def update_ip(self, gateway: str):
        """
        新增IP，以前没有的，现在有的
        :param gateway:
        :return:
        """
        previous = set(self.previous.ips.get(gateway, []))
        current = set(self.distribution[gateway]['used'])
        union = previous & current

        add = current - union
        delete = previous - union
        update = list(add | delete)

        self.distribution[gateway]['updated'] = update
        self.distribution[gateway]['update_count'] = len(update)
