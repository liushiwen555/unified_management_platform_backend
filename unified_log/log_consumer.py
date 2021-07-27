import os
from threading import Thread

import django
from confluent_kafka import Consumer
from django.conf import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE",
                      "unified_management_platform.settings")
django.setup()

from unified_log.log_process import LogProcess
from unified_log.unified_error import LogProcessError
from elasticsearch_dsl import connections
from elasticsearch.helpers import bulk
from utils.counter import GlobalFactory


def create_consumer():
    consumer = Consumer({
        'bootstrap.servers': settings.KAFKA_BROKER,
        'group.id': 'test_partition',
        'enable.auto.commit': False,

    })

    consumer.subscribe(['unified-log'])
    return consumer


def consume_log(consumer: Consumer, counter_id: str):
    counter = GlobalFactory.get_count(
        key=counter_id,
        refresh=GlobalFactory.LOG_THRESHOLD)
    while True:
        buffer = []
        messages = consumer.consume(100, timeout=1)
        for msg in messages:
            if not msg:
                continue
            else:
                try:
                    raw_log = msg.value().decode('utf-8')
                except UnicodeDecodeError:
                    continue
            try:
                log = LogProcess(raw_log, counter)
                try:
                    log.process()
                except LogProcessError as e:
                    print(raw_log)
                    print(e)
                buffer.append(log.log)
            except Exception as e:
                print(raw_log)
                print(e)
        try:
            bulk(connections.get_connection(), [d.to_dict(True) for d in buffer])
            consumer.commit()
        except Exception as e:
            print(e)


def start_consume():
    total = settings.LOG_PARTITION
    consumers = [create_consumer() for _ in range(total)]
    threads = []

    for i in range(total):
        t = Thread(target=consume_log, args=(consumers[i], str(i) + '-'))
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()


if __name__ == '__main__':
    start_consume()
