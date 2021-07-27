import threading
import time

from utils.counter import GlobalFactory, LocalFactory


class TestCounter:
    def test_create_counter(self):
        t1 = threading.Thread(target=GlobalFactory.get_count,
                              kwargs={'key': 'a'})
        t2 = threading.Thread(target=GlobalFactory.get_count,
                              kwargs={'key': 'b'})
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert GlobalFactory.exists(t1.ident)
        assert GlobalFactory.exists(t2.ident)

    def test_create_default_counter(self):
        """
        创建默认线程id的counter
        """
        t1 = threading.Thread(target=GlobalFactory.get_count)
        t2 = threading.Thread(target=GlobalFactory.get_count)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert GlobalFactory.exists(t1.ident)
        assert GlobalFactory.exists(t2.ident)

    def test_create_duplicate_counter(self):
        counter = GlobalFactory.get_count(key='a')

        _id = id(counter)

        counter2 = GlobalFactory.get_count(key='b')
        _id2 = id(counter2)
        assert _id == _id2

    def test_destroy(self):
        counter = GlobalFactory.get_count()

        counter.destroy()

        assert not GlobalFactory.exists(threading.current_thread().ident)

    def create_multi_factory(self):
        factory = GlobalFactory()
        factory.get_count()

    def test_create_multi_factory(self):
        t1 = threading.Thread(target=self.create_multi_factory)
        t2 = threading.Thread(target=self.create_multi_factory)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert GlobalFactory.exists(t1.ident)
        assert GlobalFactory.exists(t2.ident)
        GlobalFactory.destroy(t1.ident)
        GlobalFactory.destroy(t2.ident)

    def add(self):
        counter = GlobalFactory.get_count()
        for i in range(10000):
            counter.add(1)

    def test_add(self):
        t1 = threading.Thread(target=self.add)
        t2 = threading.Thread(target=self.add)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert GlobalFactory.get_count(t1.ident).value == 10000
        assert GlobalFactory.get_count(t2.ident).value == 10000
        GlobalFactory.destroy(t1.ident)
        GlobalFactory.destroy(t2.ident)

    def sub(self):
        counter = GlobalFactory.get_count()
        for i in range(1000):
            counter.sub(1)

        assert counter.value == -1000
        counter.destroy()

    def test_sub(self):
        t1 = threading.Thread(target=self.sub)
        t2 = threading.Thread(target=self.sub)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def test_refresh(self):
        counter = GlobalFactory.get_count(
            refresh=GlobalFactory.LOG_THRESHOLD)
        counter.add(4294966295)
        for i in range(1000):
            counter.add(1)

        assert counter.value == 0
        print(counter)
        print(counter.thread_id)


class TestLocalCounter:
    def test_create_counter(self):
        t1 = threading.Thread(target=LocalFactory.get_count,
                              kwargs={'key': 'a'})
        t2 = threading.Thread(target=LocalFactory.get_count,
                              kwargs={'key': 'a'})
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert LocalFactory.exists(t1.ident)
        assert LocalFactory.exists(t2.ident)

    def test_create_default_counter(self):
        """
        创建默认线程id的counter
        """
        t1 = threading.Thread(target=LocalFactory.get_count,)
        t2 = threading.Thread(target=LocalFactory.get_count,)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert LocalFactory.exists(t1.ident)
        assert LocalFactory.exists(t2.ident)

    def test_create_duplicate_counter(self):
        counter = LocalFactory.get_count(key='a')

        _id = id(counter)

        counter2 = LocalFactory.get_count(key='b')
        _id2 = id(counter2)
        assert _id == _id2

    def test_destroy(self):
        counter = LocalFactory.get_count()

        counter.destroy()

        assert not LocalFactory.exists(threading.current_thread().ident)

    def create_multi_factory(self):
        factory = LocalFactory()
        factory.get_count()
        time.sleep(1)

    def test_create_multi_factory(self):
        t1 = threading.Thread(target=self.create_multi_factory)
        t2 = threading.Thread(target=self.create_multi_factory)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert LocalFactory.exists(t1.ident)
        assert LocalFactory.exists(t2.ident)
        LocalFactory.destroy(t1.ident)
        LocalFactory.destroy(t2.ident)

    def add(self):
        counter = LocalFactory.get_count()
        for i in range(10000):
            counter.add(1)

        assert counter.value == 10000
        counter.destroy()

    def test_add(self):
        t1 = threading.Thread(target=self.add)
        t2 = threading.Thread(target=self.add)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def sub(self):
        counter = LocalFactory.get_count()
        for i in range(10000):
            counter.sub(1)

        assert counter.value == -10000
        counter.destroy()

    def test_sub(self):
        t1 = threading.Thread(target=self.sub)
        t2 = threading.Thread(target=self.sub)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def test_refresh(self):
        counter = LocalFactory.get_count(
            refresh=LocalFactory.LOG_THRESHOLD,)
        counter.add(4294966295)
        for i in range(1000):
            counter.add(1)
        c = counter.get_inner_counter()
        assert c.val == 0
        assert counter.value == 0
        print(counter)
        print(counter.thread_id)