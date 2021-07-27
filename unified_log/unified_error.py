class LogProcessError(Exception):
    result = '日志解析完成'

    def __init__(self, msg: str):
        self.msg = msg

    def __str__(self):
        return self.msg + f', {self.result}'


class LogPreProcessError(Exception):
    """
    日志格式错误，无法解析最基础的信息
    """
    result = '日志未解析'

    def __init__(self, msg: str):
        self.msg = msg

    def __str__(self):
        return self.msg + f', {self.result}'
