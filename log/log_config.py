from log.log_content import log_config


"""
LOG_CONFIG_DICT结构为：
LOG_CONFIG_DICT{
    URL_NAME:{
        HTTP_METHOD: 生成log的类
    }
}
"""

LOG_CONFIG_DICT = log_config.get_config()


class ModelLog(object):

    def __init__(self):
        self.conf_dict = LOG_CONFIG_DICT

    def log(self, request, request_body, result, response, *args, **kwargs):
        try:
            # 获取url对应的name
            url_name = request.resolver_match.url_name
            method = request.method
            log_generator = self.conf_dict[url_name][method]
            log_generator_instance = log_generator(
                request, request_body, result, response, *args, **kwargs)
            log_generator_instance.generate_log()

        except Exception as e:
            # print(e)
            pass

        # url_name = request.resolver_match.url_name
        # method = request.method
        # log_generator = self.conf_dict[url_name][method]
        # log_generator_instance = log_generator(
        #     request, request_body, result, response, *args, **kwargs)
        # log_generator_instance.generate_log()