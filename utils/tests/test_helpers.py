from datetime import datetime

import pytest
from django.utils import timezone

from utils.helper import get_next_day, get_today


class TestGetDay:
    def test_get_next_day(self):
        d = datetime(2020, 12, 2, 1)
        next_day = get_next_day(d)

        assert next_day == datetime(2020, 12, 3, 0, 0).astimezone()

        d = datetime(2020, 12, 2, 1).astimezone(timezone.utc)
        next_day = get_next_day(d)
        assert str(next_day) == '2020-12-02 16:00:00+00:00'

        d = datetime(2020, 12, 2, 0).astimezone(timezone.utc)
        next_day = get_next_day(d)
        assert str(next_day) == '2020-12-02 16:00:00+00:00'

    def test_get_today(self):
        d = datetime(2020, 12, 2, 1)
        today = get_today(d)

        assert today == datetime(2020, 12, 2, 0, 0).astimezone()

        d = datetime(2020, 12, 2, 1).astimezone(timezone.utc)
        today = get_today(d)
        assert str(today) == '2020-12-01 16:00:00+00:00'

        d = datetime(2020, 12, 2, 0).astimezone(timezone.utc)
        today = get_today(d)
        assert str(today) == '2020-12-01 16:00:00+00:00'


