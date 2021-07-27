from confluent_kafka import Producer
import time
import random
from utils.helper import Timeit


producer = Producer({
    'bootstrap.servers': '192.168.0.41:9092',
    'linger.ms': 10,
    'socket.receive.buffer.bytes':  1024 * 5,
})


def acked(err, msg):
    if err is not None:
        print("Failed to deliver message: {0}: {1}"
              .format(msg.value(), err.str()))
    else:
        print("Message produced: {0}".format(msg.value()))


while True:
    with Timeit():
        for _ in range(5):
            for _ in range(100):
                log = random.choice(
                    ['2020-10-14 16:51:36 bolean 192.168.0.58 10 6 sshd[16224]: pam_unix(sshd:session): session opened for user bolean by (uid=0)',
                    '2020-10-14 16:51:36 bolean 192.168.0.58 4 6 systemd-logind[888]: New session 1607 of user bolean.',
                    '2020-10-14 16:51:36 bolean 192.168.0.58 4 6 sshd[16224]: Accepted publickey for bolean from 192.168.0.40 port 56383 ssh2: RSA SHA256:jJdOqfelTunE7eAXI89e5pw0eWG1R3zhKn0etPdicVo',
                     '2020-10-14 16:51:34 bolean 192.168.0.58 10 6 sshd[16080]: pam_unix(sshd:session): session closed for user bolean']
                )
                producer.produce('unified-log', key=log.encode('utf-8'),
                                 value=log.encode('utf-8'), callback=acked)
            time.sleep(0.12)
        producer.poll(10)
