from channels.routing import ProtocolTypeRouter, URLRouter


from statistic.routing import statistic_websocket

application = ProtocolTypeRouter({
    'websocket': URLRouter(statistic_websocket)
})