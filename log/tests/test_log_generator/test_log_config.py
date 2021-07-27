from django.test.testcases import TestCase

from log.log_content.log_generator import LogConfig, AdditionalInfoBeforeDelete


class LogGenerator:
    pass


class TestLogConfig(TestCase):
    test_url_name = 'test-register'

    def test_create_log_config(self):
        log1 = LogConfig()
        log2 = LogConfig()

        assert id(log1) == id(log2)

    def test_register_config(self):
        log = LogConfig()
        log.register(self.test_url_name, 'get')(LogGenerator)

        test_config = log.get_config()
        assert test_config[self.test_url_name]['GET'] == LogGenerator

        log.register(self.test_url_name, ['GET', 'POST'])(LogGenerator)

        assert len(test_config[self.test_url_name]) == 2
        assert test_config[self.test_url_name]['GET'] == LogGenerator
        assert test_config[self.test_url_name]['POST'] == LogGenerator

    def test_register_additional_info(self):
        log = LogConfig()
        addition = AdditionalInfoBeforeDelete()

        log.register(self.test_url_name, 'POST', additional_info=True)(
            LogGenerator)

        assert addition._config[self.test_url_name]['POST'] == LogGenerator
