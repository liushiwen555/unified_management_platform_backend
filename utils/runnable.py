from abc import ABC, abstractmethod
from datetime import datetime
from utils.helper import send_websocket_message


class TaskRun(ABC):
    @classmethod
    @abstractmethod
    def run(cls, current: datetime):
        pass


class TaskRunWebsocket(TaskRun):
    room_group_name = None
    websocket_type = 'unified_push'

    @classmethod
    @abstractmethod
    def run(cls, current: datetime):
        pass

    @classmethod
    def websocket_send(cls, message):
        if not cls.room_group_name:
            raise RuntimeError('未指定WebSocket推送的group——【room_group_name】')
        send_websocket_message(cls.room_group_name, message,
                               type_=cls.websocket_type)
