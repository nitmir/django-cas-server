# Copyright (C) 2014, Ming Chen
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is furnished
# to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

# This file is originated from https://github.com/python-cas/python-cas
# at commit ec1f2d4779625229398547b9234d0e9e874a2c9a
# some modifications have been made to be unicode coherent between python2 and python2

import six
from six.moves.urllib import parse as urllib_parse
from six.moves.urllib import request as urllib_request
from six.moves.urllib.request import Request
from uuid import uuid4
import datetime


class CASError(ValueError):
    pass


class ReturnUnicode(object):
    @staticmethod
    def u(string, charset):
        if not isinstance(string, six.text_type):
            return string.decode(charset)
        else:
            return string


class SingleLogoutMixin(object):
    @classmethod
    def get_saml_slos(cls, logout_request):
        """returns saml logout ticket info"""
        from lxml import etree
        try:
            root = etree.fromstring(logout_request)
            return root.xpath(
                "//samlp:SessionIndex",
                namespaces={'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"})
        except etree.XMLSyntaxError:
            pass


class CASClient(object):
    def __new__(self, *args, **kwargs):
        version = kwargs.pop('version')
        if version in (1, '1'):
            return CASClientV1(*args, **kwargs)
        elif version in (2, '2'):
            return CASClientV2(*args, **kwargs)
        elif version in (3, '3'):
            return CASClientV3(*args, **kwargs)
        elif version == 'CAS_2_SAML_1_0':
            return CASClientWithSAMLV1(*args, **kwargs)
        raise ValueError('Unsupported CAS_VERSION %r' % version)


class CASClientBase(object):

    logout_redirect_param_name = 'service'

    def __init__(self, service_url=None, server_url=None,
                 extra_login_params=None, renew=False,
                 username_attribute=None):

        self.service_url = service_url
        self.server_url = server_url
        self.extra_login_params = extra_login_params or {}
        self.renew = renew
        self.username_attribute = username_attribute
        pass

    def verify_ticket(self, ticket):
        """must return a triple"""
        raise NotImplementedError()

    def get_login_url(self):
        """Generates CAS login URL"""
        params = {'service': self.service_url}
        if self.renew:
            params.update({'renew': 'true'})

        params.update(self.extra_login_params)
        url = urllib_parse.urljoin(self.server_url, 'login')
        query = urllib_parse.urlencode(params)
        return url + '?' + query

    def get_logout_url(self, redirect_url=None):
        """Generates CAS logout URL"""
        url = urllib_parse.urljoin(self.server_url, 'logout')
        if redirect_url:
            params = {self.logout_redirect_param_name: redirect_url}
            url += '?' + urllib_parse.urlencode(params)
        return url

    def get_proxy_url(self, pgt):
        """Returns proxy url, given the proxy granting ticket"""
        params = urllib_parse.urlencode({'pgt': pgt, 'targetService': self.service_url})
        return "%s/proxy?%s" % (self.server_url, params)

    def get_proxy_ticket(self, pgt):
        """Returns proxy ticket given the proxy granting ticket"""
        response = urllib_request.urlopen(self.get_proxy_url(pgt))
        if response.code == 200:
            from lxml import etree
            root = etree.fromstring(response.read())
            tickets = root.xpath(
                "//cas:proxyTicket",
                namespaces={"cas": "http://www.yale.edu/tp/cas"}
            )
            if len(tickets) == 1:
                return tickets[0].text
            errors = root.xpath(
                "//cas:authenticationFailure",
                namespaces={"cas": "http://www.yale.edu/tp/cas"}
            )
            if len(errors) == 1:
                raise CASError(errors[0].attrib['code'], errors[0].text)
        raise CASError("Bad http code %s" % response.code)

    @staticmethod
    def get_page_charset(page, default="utf-8"):
        content_type = page.info().get('Content-type')
        if content_type and "charset=" in content_type:
            return content_type.split("charset=")[-1]
        else:
            return default


class CASClientV1(CASClientBase, ReturnUnicode):
    """CAS Client Version 1"""

    logout_redirect_param_name = 'url'

    def verify_ticket(self, ticket):
        """Verifies CAS 1.0 authentication ticket.

        Returns username on success and None on failure.
        """
        params = [('ticket', ticket), ('service', self.service_url)]
        if self.renew:
            params.append(('renew', 'true'))
        url = (urllib_parse.urljoin(self.server_url, 'validate') + '?' +
               urllib_parse.urlencode(params))
        page = urllib_request.urlopen(url)
        try:
            verified = page.readline().strip()
            if verified == b'yes':
                charset = self.get_page_charset(page, default="ascii")
                user = self.u(page.readline().strip(), charset)
                return user, None, None
            else:
                return None, None, None
        finally:
            page.close()


class CASClientV2(CASClientBase, ReturnUnicode):
    """CAS Client Version 2"""

    url_suffix = 'serviceValidate'
    logout_redirect_param_name = 'url'

    def __init__(self, proxy_callback=None, *args, **kwargs):
        """proxy_callback is for V2 and V3 so V3 is subclass of V2"""
        self.proxy_callback = proxy_callback
        super(CASClientV2, self).__init__(*args, **kwargs)

    def verify_ticket(self, ticket):
        """Verifies CAS 2.0+/3.0+ XML-based authentication ticket and returns extended attributes"""
        (response, charset) = self.get_verification_response(ticket)
        return self.verify_response(response, charset)

    def get_verification_response(self, ticket):
        params = [('ticket', ticket), ('service', self.service_url)]
        if self.renew:
            params.append(('renew', 'true'))
        if self.proxy_callback:
            params.append(('pgtUrl', self.proxy_callback))
        base_url = urllib_parse.urljoin(self.server_url, self.url_suffix)
        url = base_url + '?' + urllib_parse.urlencode(params)
        page = urllib_request.urlopen(url)
        try:
            charset = self.get_page_charset(page)
            return (page.read(), charset)
        finally:
            page.close()

    @classmethod
    def parse_attributes_xml_element(cls, element, charset):
        attributes = dict()
        for attribute in element:
            tag = cls.u(attribute.tag, charset).split(u"}").pop()
            if tag in attributes:
                if isinstance(attributes[tag], list):
                    attributes[tag].append(cls.u(attribute.text, charset))
                else:
                    attributes[tag] = [attributes[tag]]
                    attributes[tag].append(cls.u(attribute.text, charset))
            else:
                if tag == u'attraStyle':
                    pass
                else:
                    attributes[tag] = cls.u(attribute.text, charset)
        return attributes

    @classmethod
    def verify_response(cls, response, charset):
        user, attributes, pgtiou = cls.parse_response_xml(response, charset)
        if len(attributes) == 0:
            attributes = None
        return user, attributes, pgtiou

    @classmethod
    def parse_response_xml(cls, response, charset):
        try:
            from xml.etree import ElementTree
        except ImportError:
            from elementtree import ElementTree

        user = None
        attributes = {}
        pgtiou = None

        tree = ElementTree.fromstring(response)
        if tree[0].tag.endswith('authenticationSuccess'):
            for element in tree[0]:
                if element.tag.endswith('user'):
                    user = cls.u(element.text, charset)
                elif element.tag.endswith('proxyGrantingTicket'):
                    pgtiou = cls.u(element.text, charset)
                elif element.tag.endswith('attributes'):
                    attributes = cls.parse_attributes_xml_element(element, charset)
        return user, attributes, pgtiou


class CASClientV3(CASClientV2, SingleLogoutMixin):
    """CAS Client Version 3"""
    url_suffix = 'serviceValidate'
    logout_redirect_param_name = 'service'

    @classmethod
    def parse_attributes_xml_element(cls, element, charset):
        attributes = dict()
        for attribute in element:
            tag = cls.u(attribute.tag, charset).split(u"}").pop()
            if tag in attributes:
                if isinstance(attributes[tag], list):
                    attributes[tag].append(cls.u(attribute.text, charset))
                else:
                    attributes[tag] = [attributes[tag]]
                    attributes[tag].append(cls.u(attribute.text, charset))
            else:
                attributes[tag] = cls.u(attribute.text, charset)
        return attributes

    @classmethod
    def verify_response(cls, response, charset):
        return cls.parse_response_xml(response, charset)


SAML_1_0_NS = 'urn:oasis:names:tc:SAML:1.0:'
SAML_1_0_PROTOCOL_NS = '{' + SAML_1_0_NS + 'protocol' + '}'
SAML_1_0_ASSERTION_NS = '{' + SAML_1_0_NS + 'assertion' + '}'
SAML_ASSERTION_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Header/>
<SOAP-ENV:Body>
<samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"
MajorVersion="1"
MinorVersion="1"
RequestID="{request_id}"
IssueInstant="{timestamp}">
<samlp:AssertionArtifact>{ticket}</samlp:AssertionArtifact></samlp:Request>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""


class CASClientWithSAMLV1(CASClientV2, SingleLogoutMixin):
    """CASClient 3.0+ with SAML"""

    def verify_ticket(self, ticket, **kwargs):
        """Verifies CAS 3.0+ XML-based authentication ticket and returns extended attributes.

        @date: 2011-11-30
        @author: Carlos Gonzalez Vila <carlewis@gmail.com>

        Returns username and attributes on success and None,None on failure.
        """

        try:
            from xml.etree import ElementTree
        except ImportError:
            from elementtree import ElementTree

        page = self.fetch_saml_validation(ticket)
        charset = self.get_page_charset(page)

        try:
            user = None
            attributes = {}
            response = page.read()
            tree = ElementTree.fromstring(response)
            # Find the authentication status
            success = tree.find('.//' + SAML_1_0_PROTOCOL_NS + 'StatusCode')
            if success is not None and success.attrib['Value'].endswith(':Success'):
                # User is validated
                name_identifier = tree.find('.//' + SAML_1_0_ASSERTION_NS + 'NameIdentifier')
                if name_identifier is not None:
                    user = self.u(name_identifier.text, charset)
                attrs = tree.findall('.//' + SAML_1_0_ASSERTION_NS + 'Attribute')
                for at in attrs:
                    if self.username_attribute in list(at.attrib.values()):
                        user = self.u(
                            at.find(SAML_1_0_ASSERTION_NS + 'AttributeValue').text,
                            charset
                        )
                        attributes[u'uid'] = user

                    values = at.findall(SAML_1_0_ASSERTION_NS + 'AttributeValue')
                    key = self.u(at.attrib['AttributeName'], charset)
                    if len(values) > 1:
                        values_array = []
                        for v in values:
                            values_array.append(self.u(v.text, charset))
                            attributes[key] = values_array
                    else:
                        attributes[key] = self.u(values[0].text, charset)
            return user, attributes, None
        finally:
            page.close()

    def fetch_saml_validation(self, ticket):
        # We do the SAML validation
        headers = {
            'soapaction': 'http://www.oasis-open.org/committees/security',
            'cache-control': 'no-cache',
            'pragma': 'no-cache',
            'accept': 'text/xml',
            'connection': 'keep-alive',
            'content-type': 'text/xml; charset=utf-8',
        }
        params = [('TARGET', self.service_url)]
        saml_validate_url = urllib_parse.urljoin(
            self.server_url, 'samlValidate',
        )
        request = Request(
            saml_validate_url + '?' + urllib_parse.urlencode(params),
            self.get_saml_assertion(ticket),
            headers,
        )
        return urllib_request.urlopen(request)

    @classmethod
    def get_saml_assertion(cls, ticket):
        """
        http://www.jasig.org/cas/protocol#samlvalidate-cas-3.0

        SAML request values:

        RequestID [REQUIRED]:
            unique identifier for the request
        IssueInstant [REQUIRED]:
            timestamp of the request
        samlp:AssertionArtifact [REQUIRED]:
            the valid CAS Service Ticket obtained as a response parameter at login.
        """
        # RequestID [REQUIRED] - unique identifier for the request
        request_id = uuid4()

        # e.g. 2014-06-02T09:21:03.071189
        timestamp = datetime.datetime.now().isoformat()

        return SAML_ASSERTION_TEMPLATE.format(
            request_id=request_id,
            timestamp=timestamp,
            ticket=ticket,
        ).encode('utf8')
