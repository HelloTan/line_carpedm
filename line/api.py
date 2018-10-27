# -*- coding: utf-8 -*-
"""
    line.client
    ~~~~~~~~~~~

    LineClient for sending and receiving message from LINE server.

    :copyright: (c) 2014 by Taehoon Kim.
    :license: BSD, see LICENSE for more details.
"""
import rsa, requests
try:
    import simplejson as json
except ImportError:
    import json

from thrift.transport import THttpClient
from thrift.protocol import TCompactProtocol
from .lib import *
from .lib.ttypes import *

class LineAPI(object):
    """This class is a wrapper of LINE API

    """
    LINE_DOMAIN = 'https://gd2.line.naver.jp'

    LINE_POLL_QUERY_PATH_FIR    = LINE_DOMAIN + "/P4"
    LINE_CERTIFICATE_PATH       = LINE_DOMAIN + "/Q"
    LINE_LOGIN_QUERY_PATH       = LINE_DOMAIN + "/api/v4p/rs"
    LINE_AUTH_QUERY_PATH        = LINE_DOMAIN + "/api/v4/TalkService.do"
    
    CERT_FILE = ".line.crt"

    ip          = "127.0.0.1"
    version     = "8.14.5"
    user_agent  = "Line/%s" % (version)
    com_name    = "Line_Carpedm"
    carrier     = '51089, 1-0'
    revision    = 0
    system_ver  = '13.2.1'
    app_name    = "IOSIPAD\t%s\tiPhone_OS\t%s" % (version, system_ver)
    certificate = ""

    _headers = {}

    def __init__(self):
        object.__init__(self)
        self._session = requests.session()

    def ready(self):
        """
        After login, make `client` and `client_in` instance
        to communicate with LINE server
        """
        raise Exception("Code is removed because of the request of LINE corporation")

    def updateAuthToken(self):
        """
        After login, update authToken to avoid expiration of
        authToken. This method skip the PinCode validation step.
        """
        if self.certificate:
            self.login(self.com_name)
            self.tokenLogin()
            return True
        else:
            self.raise_error("You need to login first. There is no valid certificate")

    def tokenLogin(self):
        self.transport = THttpClient.THttpClient(self.LINE_AUTH_QUERY_PATH)
        self.transport.setCustomHeaders(self._headers)
        self.protocol = TCompactProtocol.TCompactProtocol(self.transport)
        self._client  = TalkService.Client(self.protocol)
        return self._client

    def loginRequest(self, type, data):
        lReq = LoginRequest()
        if type == '0':
            lReq.type = LoginType.ID_CREDENTIAL
            lReq.identityProvider = data['identityProvider']
            lReq.identifier = data['identifier']
            lReq.password = data['password']
            lReq.keepLoggedIn = data['keepLoggedIn']
            lReq.accessLocation = data['accessLocation']
            lReq.systemName = data['systemName']
            lReq.certificate = data['certificate']
            lReq.e2eeVersion = data['e2eeVersion']
        elif type == '1':
            lReq.type = LoginType.QRCODE
            lReq.keepLoggedIn = data['keepLoggedIn']
            if 'identityProvider' in data:
                lReq.identityProvider = data['identityProvider']
            if 'accessLocation' in data:
                lReq.accessLocation = data['accessLocation']
            if 'systemName' in data:
                lReq.systemName = data['systemName']
            lReq.verifier = data['verifier']
            lReq.e2eeVersion = data['e2eeVersion']
        else:
            lReq=False
        return lReq

    def login(self, keepLoggedIn=True, systemName=com_name):
        """Login to LINE server."""
        #TalkService
        self.transport = THttpClient.THttpClient(self.LINE_AUTH_QUERY_PATH)
        self.transport.setCustomHeaders(self._headers)
        self.protocol = TCompactProtocol.TCompactProtocol(self.transport)
        self._client   = TalkService.Client(self.protocol)
        #AuthService
        self.transport = THttpClient.THttpClient(self.LINE_LOGIN_QUERY_PATH)
        self.transport.setCustomHeaders(self._headers)
        self.protocol = TCompactProtocol.TCompactProtocol(self.transport)
        self._auth   = AuthService.Client(self.protocol)

        self.provider = IdentityProvider.LINE
        rsaKey = self._client.getRSAKeyInfo(self.provider)
        message = (chr(len(rsaKey.sessionKey)) + rsaKey.sessionKey +
                   chr(len(_id)) + _id +
                   chr(len(passwd)) + passwd).encode('utf-8')
        pub_key = rsa.PublicKey(int(rsaKey.nvalue, 16), int(rsaKey.evalue, 16))
        crypto = rsa.encrypt(message, pub_key).hex()
        
        try:
            with open(self.CERT_FILE,'r') as f:
                self.certificate = f.read()
                f.close()
        except:
            self.certificate = ""

        lReq = self.loginRequest('0', {
            'identityProvider': self.provider,
            'identifier': rsaKey.keynm,
            'password': crypto,
            'keepLoggedIn': keepLoggedIn,
            'accessLocation': '127.0.0.1',
            'systemName': systemName,
            'certificate': self.certificate,
            'e2eeVersion': 0
        })

        result = self._auth.loginZ(lReq)

        if result.type == LoginResultType.REQUIRE_DEVICE_CONFIRM:
            if withReturn == False:
                print('Enter Pincode: "{}"'.format(result.pinCode))
                self._headers['X-Line-Access'] = result.verifier
                getAccessKey = self.get_json(self.LINE_DOMAIN + '/Q')
                self.verifier = result.verifier
                self.pinCode = result.pinCode
                try:
                    lReq = self.loginRequest('1', {
                        'keepLoggedIn': keepLoggedIn,
                        'verifier': getAccessKey['result']['verifier'],
                        'e2eeVersion': 0
                    })
                    result = self._auth.loginZ(lReq)
                except Exception as e:
                    self.raise_error(e)

                if result.type == LoginResultType.SUCCESS:
                    if result.certificate is not None:
                        with open(self.CERT_FILE,'w') as f:
                            f.write(result.certificate)
                        self.certificate = result.certificate
                    if result.authToken is not None:
                        self.authToken = self._headers['X-Line-Access'] = result.authToken
                    else:
                        return False
                else:
                    return self.raise_error('Login failed')
            else:
                return (result, 'Enter Pincode: "{}"'.format(result.pinCode))
        elif result.type == LoginResultType.REQUIRE_QRCODE:
            self.qrLogin(systemName=self.com_name, APP_NAME=self.app_name)
            pass
        elif result.type == LoginResultType.SUCCESS:
            if result.authToken is not None:
                self.certificate = result.certificate
                self.authToken = self._headers['X-Line-Access'] = result.authToken
            else:
                return False
        else:
            raise Exception('Login Failed')

    def qrLogin(self,keepLoggedIn=True, systemName=com_name, APP_NAME=app_name):
        #TalkService
        self.transport = THttpClient.THttpClient(self.LINE_AUTH_QUERY_PATH)
        self.transport.setCustomHeaders(self._headers)
        self.protocol = TCompactProtocol.TCompactProtocol(self.transport)
        self._client   = TalkService.Client(self.protocol)
        #AuthService
        self.transport = THttpClient.THttpClient(self.LINE_LOGIN_QUERY_PATH)
        self.transport.setCustomHeaders(self._headers)
        self.protocol = TCompactProtocol.TCompactProtocol(self.transport)
        self._auth   = AuthService.Client(self.protocol)

        qr = self._client.getAuthQrcode(keepLoggedIn, systemName)
        uri = "line://au/q/" + qr.verifier
        print("Open this link qr on your LINE for smartphone in 2 minutes\n{}".format(uri))
        self._headers = {
            'User-Agent': self.user_agent,
            'X-Line-Application': APP_NAME,
            "x-lal" : "in_ID",
            "x-lpqs" : "/api/v4p/rs",
            'X-Line-Access': qr.verifier
        }
        getAccessKey = self.get_json(self.LINE_CERTIFICATE_PATH)
        req = LoginRequest()
        req.type = 1
        req.verifier = qr.verifier
        req.e2eeVersion = 1
        res = self._auth.loginZ(req)
        self.authToken = self._headers['X-Line-Access'] = res.authToken
        return self.tokenLogin()

    def get_json(self, url):
        """Get josn from given url with saved session and headers"""
        return json.loads(self._session.get(url, headers=self._headers).text)

    def _getProfile(self):
        """Get profile information

        :returns: Profile object
                    - picturePath
                    - displayName
                    - phone (base64 encoded?)
                    - allowSearchByUserid
                    - pictureStatus
                    - userid
                    - mid # used for unique id for account
                    - phoneticName
                    - regionCode
                    - allowSearchByEmail
                    - email
                    - statusMessage
        """
        return self._client.getProfile()

    def _getAllContactIds(self):
        """Get all contacts of your LINE account"""
        return self._client.getAllContactIds()

    def _getBlockedContactIds(self):
        """Get all blocked contacts of your LINE account"""
        return self._client.getBlockedContactIds()

    def _getContacts(self, ids):
        """Get contact information list from ids

        :returns: List of Contact list
                    - status
                    - capableVideoCall
                    - dispalyName
                    - settings
                    - pictureStatus
                    - capableVoiceCall
                    - capableBuddy
                    - mid
                    - displayNameOverridden
                    - relation
                    - thumbnailUrl
                    - createdTime
                    - facoriteTime
                    - capableMyhome
                    - attributes
                    - type
                    - phoneticName
                    - statusMessage
        """
        if type(ids) != list:
            msg = "argument should be list of contact ids"
            self.raise_error(msg)

        return self._client.getContacts(ids)

    def _findAndAddContactsByMid(self, mid, seq=0):
        """Find and add contacts by Mid"""
        return self._client.findAndAddContactsByMid(seq, mid, 0, '')

    def _findContactByUserid(self, userid):
        """Find contacts by Userid"""
        return self._client.findContactByUserid(userid)

    def _findAndAddContactsByUserid(self, userid, seq=0):
        """Find and add contacts by Userid"""
        return self._client.findAndAddContactsByUserid(seq, userid)

    def _findContactsByPhone(self, phones):
        """Find contacts by phone"""
        return self._client.findContactsByPhone(phones)

    def _findAndAddContactsByPhone(self, phones, seq=0):
        """Find and add contacts by phone"""
        return self._client.findAndAddContactsByPhone(seq, phones)

    def _findContactsByEmail(self, emails):
        """Find contacts by email"""
        return self._client.findContactsByEmail(emails)

    def _findAndAddContactsByEmail(self, emails, seq=0):
        """Find and add contacts by email"""
        return self._client.findAndAddContactsByEmail(seq, emails)

    def _createRoom(self, ids, seq=0):
        """Create a chat room"""
        return self._client.createRoom(seq, ids)

    def _getRoom(self, id):
        """Get a chat room"""
        return self._client.getRoom(id)

    def _inviteIntoRoom(self, roomId, contactIds=[]):
        """Invite contacts into room"""
        return self._client.inviteIntoRoom(0, roomId, contactIds)

    def _leaveRoom(self, id):
        """Leave a chat room"""
        return self._client.leaveRoom(0, id)

    def _createGroup(self, name, ids, seq=0):
        """Create a group"""
        return self._client.createGroup(seq, name, ids)

    def _getGroups(self, ids):
        """Get a list of group with ids"""
        if type(ids) != list:
            msg = "argument should be list of group ids"
            self.raise_error(msg)

        return self._client.getGroups(ids)

    def _getGroupIdsJoined(self):
        """Get group id that you joined"""
        return self._client.getGroupIdsJoined()

    def _getGroupIdsInvited(self):
        """Get group id that you invited"""
        return self._client.getGroupIdsInvited()

    def _acceptGroupInvitation(self, groupId, seq=0):
        """Accept a group invitation"""
        return self._client.acceptGroupInvitation(seq, groupId)

    def _kickoutFromGroup(self, groupId, contactIds=[], seq=0):
        """Kick a group members"""
        return self._client.kickoutFromGroup(seq, groupId, contactIds)

    def _cancelGroupInvitation(self, groupId, contactIds=[], seq=0):
        """Cancel a group invitation"""
        return self._client.cancelGroupInvitation(seq, groupId, contactIds)

    def _inviteIntoGroup(self, groupId, contactIds=[], seq=0):
        """Invite contacts into group"""
        return self._client.inviteIntoGroup(seq, groupId, contactIds)

    def _leaveGroup(self, id):
        """Leave a group"""
        return self._client.leaveGroup(0, id)

    def _getRecentMessages(self, id, count=1):
        """Get recent messages from `id`"""
        return self._client.getRecentMessages(id, count)

    def _sendMessage(self, message, seq=0):
        """Send a message to `id`. `id` could be contact id or group id

        :param message: `message` instance
        """
        return self._client.sendMessage(seq, message)

    def _getLastOpRevision(self):
        return self._client.getLastOpRevision()

    def _fetchOperations(self, revision, count=50):
        return self._client.fetchOperations(revision, count)

    def _getMessageBoxCompactWrapUp(self, id):
        try:
            return self._client.getMessageBoxCompactWrapUp(id)
        except:
            return None

    def _getMessageBoxCompactWrapUpList(self, start=1, count=50):
        try:
            return self._client.getMessageBoxCompactWrapUpList(start, count)
        except Exception as e:
            msg = e
            self.raise_error(msg)

    def raise_error(self, msg):
        """Error format"""
        raise Exception("Error: %s" % msg)

    def _get_json(self, url):
        """Get josn from given url with saved session and headers"""
        return json.loads(self._session.get(url, headers=self._headers).text)

    def post_content(self, url, data=None, files=None):
        return self._session.post(url, headers=self._headers, data=data, files=files)
