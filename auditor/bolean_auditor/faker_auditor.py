from auditor.tests.data import protocol


class FakerAuditor(object):
    _faker_client = {}

    def get(self, uri, payload):
        clazz = self._faker_client[uri]
        return clazz.get(payload)

    def register(self, clazz):
        self._faker_client[clazz.uri] = clazz
        return clazz


faker_auditor = FakerAuditor()


@faker_auditor.register
class FakerProtocol(object):
    """
    实时协议分布
    """
    uri = 'v2/unified-management/proto-traffic-stat/'

    @classmethod
    def get(cls, payload):
        return protocol
