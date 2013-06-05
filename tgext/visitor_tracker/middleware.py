# -*- coding: utf-8 -*-
import datetime
import time
from codecs import utf_8_decode, utf_8_encode
import logging

from webob import Request
from repoze.who._compat import get_cookies
import repoze.who._auth_tkt as auth_tkt

log = logging.getLogger(__name__)

_NOW_TESTING = None  # unit tests can replace


def _now():  #pragma NO COVERAGE
    if _NOW_TESTING is not None:
        return _NOW_TESTING
    return datetime.datetime.now()


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
                 visitor_creator=None):
        self.secret = secret
        self.cookie_name = cookie_name
        self.include_ip = include_ip
        self.secure = secure
        if timeout and ( (not reissue_time) or (reissue_time > timeout) ):
            raise ValueError('When timeout is specified, reissue_time must '
                             'be set to a lower value')
        self.timeout = timeout
        self.reissue_time = reissue_time

        self.user_id_checker = user_id_checker
        self.visitor_creator = visitor_creator

    # IIdentifier
    def identify(self, environ):
        log.debug('identify')
        cookies = get_cookies(environ)
        cookie = cookies.get(self.cookie_name)
        got_new_user = False

        if cookie is None or not cookie.value:
            log.debug('no visitor cookie')
            if not self.visitor_creator:
                return None

            timestamp, user_id, tokens, user_data = self.visitor_creator(environ)
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
                log.debug('bad ticket')
                return None

            if self.user_id_checker and not self.user_id_checker(user_id):
                log.debug('invalid user_id')
                return None

        if self.timeout and ( (timestamp + self.timeout) < time.time() ):
            log.debug('timed out')
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

        identity = {}
        identity['timestamp'] = timestamp
        identity['repoze.who.plugins.visitor_tracker.userid'] = user_id
        identity['tokens'] = tokens
        identity['userdata'] = user_data

        return identity

    def forget(self, environ, identity):
        log.debug('forgetting')
        # return a set of expires Set-Cookie headers
        return self._get_cookies(environ, 'INVALID', 0)

    def remember(self, environ, identity):
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
            ((timestamp + self.reissue_time) < time.time())):
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
            later = _now() + datetime.timedelta(seconds=max_age)
            # Wdy, DD-Mon-YY HH:MM:SS GMT
            expires = later.strftime('%a, %d %b %Y %H:%M:%S')
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

    def __call__(self, environ, request):
        identity = self.identify(environ)
        if identity:
            return self.remember(environ, identity)
        else:
            return self.forget(environ, identity)

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))


class VisitorTrackerMiddleware(object):
    def __init__(self, application, config,
                 tracker=VisitorTracker):
        self.application = application
        self.config = config

        if isinstance(tracker, type):
            self.tracker = tracker()
        else:
            self.tracker = tracker

    def _set_cookies(self, response, headers):
        log.debug('setting cookies')
        for key, value in headers:
            response.headers.add(key, value)
            
    def __call__(self, environ, start_response):
        request = Request(environ)

        headers = self.tracker(environ, request)

        response = request.get_response(self.application)

        if headers:
            self._set_cookies(response, headers)

        return response(environ, start_response)
