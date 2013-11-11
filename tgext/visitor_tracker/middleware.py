# -*- coding: utf-8 -*-
import datetime
from calendar import timegm
from email.utils import formatdate
import time
import logging

from codecs import utf_8_decode, utf_8_encode
from zope.interface import implementer
from repoze.who._compat import get_cookies
import repoze.who._auth_tkt as auth_tkt
from repoze.who.interfaces import IIdentifier, IMetadataProvider
from repoze.who.interfaces import IAuthenticator
from repoze.who._compat import get_cookies
import repoze.who._auth_tkt as auth_tkt
from repoze.who._compat import STRING_TYPES
from repoze.who._compat import u


log = logging.getLogger(__name__)

_NOW_TESTING = None  # unit tests can replace


def _utcnow():  #pragma NO COVERAGE
    """According to http://tools.ietf.org/html/rfc2616#section-3.3.1:

        All HTTP date/time stamps MUST be represented in Greenwich Mean Time
        (GMT), without exception. For the purposes of HTTP, GMT is exactly
        equal to UTC (Coordinated Universal Time).
    """
    if _NOW_TESTING is not None:
        return _NOW_TESTING
    return datetime.datetime.utcnow()


@implementer(IIdentifier)
class VisitorTracker(object):
    userid_type_decoders = {'int': int,
                            'unicode': lambda x: utf_8_decode(x)[0],
    }

    userid_type_encoders = {int: ('int', str),
    }
    try:
        userid_type_encoders[long] = ('int', str)
    except NameError: #pragma NO COVER Python >= 3.0
        pass
    try:
        userid_type_encoders[unicode] = ('unicode',
                                         lambda x: utf_8_encode(x)[0])
    except NameError: #pragma NO COVER Python >= 3.0
        pass

    def __init__(self, secret=None, cookie_name='visitor_tkt',
                 secure=False, include_ip=False,
                 timeout=None, reissue_time=None, user_id_checker=None,
                 visitor_id_creator=None, is_authenticated_checker=None,
                 **kwargs):
        self.secret = secret
        self.cookie_name = cookie_name
        self.include_ip = include_ip
        self.secure = secure
        if timeout and ((not reissue_time) or (reissue_time > timeout)):
            raise ValueError('When timeout is specified, reissue_time must '
                             'be set to a lower value')
        self.timeout = timeout
        self.reissue_time = reissue_time

        self.user_id_checker = user_id_checker
        self.visitor_id_creator = visitor_id_creator
        self.is_authenticated_checker = is_authenticated_checker

        self.extra_args = kwargs

    # IIdentifier
    def identify(self, environ):
        log.debug('identify')
        cookies = get_cookies(environ)
        cookie = cookies.get(self.cookie_name)
        got_new_user = False

        if self.is_authenticated_checker \
            and self.is_authenticated_checker(environ):
            log.debug('User is authenticated')
            return None

        if cookie is None or not cookie.value:
            log.debug('No visitor cookie')
            if not self.visitor_id_creator:
                return None

            timestamp, user_id, tokens, user_data = self.visitor_id_creator(
                environ)
            got_new_user = True

        if not got_new_user:
            if self.include_ip:
                remote_addr = environ['REMOTE_ADDR']
            else:
                remote_addr = '0.0.0.0'

            try:
                timestamp, user_id, tokens, user_data = auth_tkt.parse_ticket(
                    self.secret, cookie.value, remote_addr)
            except auth_tkt.BadTicket:
                log.debug('Bad ticket')
                return None

            if self.user_id_checker and not self.user_id_checker(user_id):
                log.debug('invalid user_id')
                return None

        if self.timeout and ( (timestamp + self.timeout) < time.time() ):
            log.debug('Timed out')
            return None

        userid_typename = 'userid_type:'
        user_data_info = user_data.split('|')
        for datum in filter(None, user_data_info):
            if datum.startswith(userid_typename):
                userid_type = datum[len(userid_typename):]
                decoder = self.userid_type_decoders.get(userid_type)
                if decoder:
                    user_id = decoder(user_id)

        environ['VISITOR_ID'] = user_id
        environ['VISITOR_TOKENS'] = tokens
        environ['VISITOR_DATA'] = user_data

        identity = {
            'timestamp': timestamp,
            'repoze.who.plugins.visitor_tracker.userid': user_id,
            'tokens': tokens,
            'userdata': user_data,
            'is_new_visitor': got_new_user,
            'max_age': self.timeout,
        }

        environ['visitor_identity'] = identity
        return None

    @staticmethod
    def remove_from_environ(environ):
        for key in ['VISITOR_ID', 'VISITOR_TOKENS', 'VISITOR_DATA',
                    'visitor_identity', ]:
            if key in environ:
                del environ[key]

    # IIdentifier
    def forget(self, environ, identity):
        raise NotImplementedError, 'Should never be called, ' \
                                   'but is needed for interface consistency.'

    # IIdentifier
    def remember(self, environ, identity):
        raise NotImplementedError, 'Should never be called, ' \
                                   'but is needed for interface consistency.'

    def _forget(self, environ, identity):
        log.debug('forgetting')
        self.remove_from_environ(environ)

        # return a set of expires Set-Cookie headers
        return self._get_cookies(environ, 'INVALID', 0)

    def _remember(self, environ, identity):
        log.debug('remembering')
        if self.include_ip:
            remote_addr = environ['REMOTE_ADDR']
        else:
            remote_addr = '0.0.0.0'

        cookies = get_cookies(environ)
        old_cookie = cookies.get(self.cookie_name)
        existing = cookies.get(self.cookie_name)
        old_cookie_value = getattr(existing, 'value', None)
        max_age = identity.get('max_age', None)

        timestamp, userid, tokens, userdata = None, '', (), ''

        if old_cookie_value:
            try:
                timestamp, userid, tokens, userdata = auth_tkt.parse_ticket(
                    self.secret, old_cookie_value, remote_addr)
            except auth_tkt.BadTicket:
                pass
        tokens = tuple(tokens)

        who_userid = identity['repoze.who.plugins.visitor_tracker.userid']
        log.debug('remembering: user_id=%r', who_userid)
        who_tokens = tuple(identity.get('tokens', ()))
        who_userdata = identity.get('userdata', '')

        encoding_data = self.userid_type_encoders.get(type(who_userid))
        if encoding_data:
            encoding, encoder = encoding_data
            who_userid = encoder(who_userid)
            # XXX we are discarding the userdata passed in the identity?
            who_userdata = 'userid_type:%s' % encoding

        old_data = (userid, tokens, userdata)
        new_data = (who_userid, who_tokens, who_userdata)

        if old_data != new_data or (self.reissue_time and
                                        ((timestamp + self.reissue_time)
                                             < time.time())):
            ticket = auth_tkt.AuthTicket(
                self.secret,
                who_userid,
                remote_addr,
                tokens=who_tokens,
                user_data=who_userdata,
                cookie_name=self.cookie_name,
                secure=self.secure)
            new_cookie_value = ticket.cookie_value()

            if old_cookie_value != new_cookie_value:
                # return a set of Set-Cookie headers
                return self._get_cookies(environ, new_cookie_value, max_age)

    def _get_cookies(self, environ, value, max_age=None):
        if max_age is not None:
            max_age = int(max_age)
            later = _utcnow() + datetime.timedelta(seconds=max_age)
            environ['VISITOR_NEW_EXPIRY_TIME'] = later
            # Wdy, DD-Mon-YY HH:MM:SS GMT
            expires = formatdate(timegm(later.timetuple()), usegmt=True)
            # the Expires header is *required* at least for IE7 (IE7 does
            # not respect Max-Age)
            max_age = "; Max-Age=%s; Expires=%s" % (max_age, expires)
        else:
            max_age = ''

        secure = ''
        if self.secure:
            secure = '; secure; HttpOnly'

        cur_domain = environ.get('HTTP_HOST', environ.get('SERVER_NAME'))
        cur_domain = cur_domain.split(':')[0] # drop port
        wild_domain = '.' + cur_domain
        cookies = [
            ('Set-Cookie', '%s="%s"; Path=/%s%s' % (
                self.cookie_name, value, max_age, secure)),
            ('Set-Cookie', '%s="%s"; Path=/; Domain=%s%s%s' % (
                self.cookie_name, value, cur_domain, max_age, secure)),
            ('Set-Cookie', '%s="%s"; Path=/; Domain=%s%s%s' % (
                self.cookie_name, value, wild_domain, max_age, secure))
        ]
        return cookies

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))
