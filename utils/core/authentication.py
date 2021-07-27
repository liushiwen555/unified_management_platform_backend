import random

import redis
from Crypto.Cipher import AES
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication, get_authorization_header

CHARSET = [chr(i) for i in range(256)]
r = redis.StrictRedis()


class TokenCipher:
    def __init__(self, key):
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, token):
        if settings.DEBUG and settings.ALLOW_TEST_LOGIN:
            return token
        if len(token) != 40:
            raise ValueError('Token must be 40 chars!')
        salt = ''.join(random.sample(CHARSET, 8))
        with_salt = token[:10] + salt[:2] + token[10:20] + salt[2:4] + token[20:30] + salt[4:6] + token[30:] + salt[6:]

        return self.cipher.encrypt(with_salt.encode('latin')).hex()

    def decrypt(self, text):
        if settings.DEBUG and settings.ALLOW_TEST_LOGIN:
            return text, ''.join(random.sample(CHARSET, 8))
        raw = bytes.fromhex(text)
        if len(raw) != 48:
            raise ValueError('Invalid token!')
        with_salt = self.cipher.decrypt(raw)
        token = (with_salt[:10]+with_salt[12:22]+with_salt[24:34]+with_salt[36:46]).decode('latin')
        salt = with_salt[10:12]+with_salt[22:24]+with_salt[34:36]+with_salt[46:]
        return token, salt


cipher = TokenCipher('Bl666666666666lB')


class EncryptedTokenAuthentication(TokenAuthentication):
    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            with_salt = auth[1].decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            token, salt = cipher.decrypt(with_salt)

        except (TypeError, ValueError):
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

        user, auth = self.authenticate_credentials(token)
        name = user.username
        if r.sadd(name, salt):  # salt没被用过，Redis返回1
            r.expire(name, 900)
            return user, auth
        else:  # salt已经存在，Redis返回0
            raise exceptions.AuthenticationFailed(_('Invalid token.'))