import re

import pytest

from user.models import password_regex


pattern = re.compile(password_regex)


class TestPasswordValidator:
    @pytest.mark.parametrize('passwd', ['a1_', 'a1_'*6])
    def test_length(self, passwd):
        """
        测试密码长度不符合要求
        """
        res = pattern.match(passwd)

        assert res is None

    @pytest.mark.parametrize('passwd', ['aaaa....', '1111....', 'aaaa1111'])
    def test_character(self, passwd):
        """
        测试密码没有包含字母、数字、字符三种
        """
        res = pattern.match(passwd)

        assert res is None

    @pytest.mark.parametrize('passwd', ['asd1213+_{}'])
    def test_right_password(self, passwd):
        """
        测试符合要求的密码
        """
        res = pattern.match(passwd)

        assert res is not None

