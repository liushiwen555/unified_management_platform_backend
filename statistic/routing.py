from django.urls import path

from statistic.consumers import SecurityConsumer, SystemRunningConsumer, \
    AttackConsumer, AbnormalConsumer, MainConsumer, AssetsCenterConsumer, \
    IPMAPConsumer, NetworkConsumer, LogCenterConsumer

statistic_websocket = [
    path('ws/statistic/security/', SecurityConsumer.as_asgi()),
    path('ws/statistic/running/', SystemRunningConsumer.as_asgi()),
    path('ws/statistic/attack/', AttackConsumer.as_asgi()),
    path('ws/statistic/abnormal/', AbnormalConsumer.as_asgi()),
    path('ws/statistic/main/', MainConsumer.as_asgi()),
    path('ws/statistic/assets/', AssetsCenterConsumer.as_asgi()),
    path('ws/statistic/ip_map/', IPMAPConsumer.as_asgi()),
    path('ws/statistic/network/', NetworkConsumer.as_asgi()),
    path('ws/statistic/log/', LogCenterConsumer.as_asgi()),
]
