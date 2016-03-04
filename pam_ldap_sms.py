import random, ldap, string, hashlib, requests, pwd, syslog, re, json



class InvalidNumber(Exception):
    """Raised if an invalid phone number is passed to the class"""
    pass

class SmsApi:
    def __init__(self, pin, phone_num):
        self.pin = pin
        self.phone_num = phone_num
        self.url = "https://SMSSERVICE.URL.COM/SMS"
        self.apiuser = "SMSSERVICEAPIUSER"
        self.apipassword = "SMSSERVICEAPIPASSWORD"

    def parse_number(self):
        try:
            reg8 = re.compile('^8')
            reg_phone = re.compile('\+7(\d){10}$')
            if reg8.match(self.phone_num):
                new_num = re.sub(reg8, '+7', self.phone_num)
                self.phone_num = new_num
            if not re.search(reg_phone, self.phone_num):
                raise InvalidNumber(self.phone_num)

        except ValueError:
            raise InvalidNumber(self.phone_num)

    def send(self):
        try:
            self.parse_number()
        except:
            raise
        data = {}
        data['text'] = self.pin
        dest = {}
        dest['address'] = self.phone_num
        dest['npi'] = 1
        dest['ton'] = 0
        data['destinationAddress'] = dest
        json_data = json.dumps(data)
        auth_log("SMS: (%s)" % (json_data))
        auth_log("APIPASS: (%s)" % (self.apipassword))
        auth_log("APIUSER: (%s)" % (self.apiuser))
        resp = requests.post(url=self.url, auth=(self.apiuser, self.apipassword), data=json_data)
        auth_log("CODE: (%s)" % (resp.status_code))
        if resp.status_code != 201:
            raise InvalidNumber(self.phone_num)


def auth_log(msg):
    """Send errors to default auth log"""
    syslog.openlog(facility=syslog.LOG_AUTH)
    syslog.syslog("STAMP: " + msg)
    syslog.closelog()

def gen_pin(user, user_number, length):
    """Generate the pin and send it to the user  by sms-service.api"""
    pin = ''.join(random.choice(string.digits) for i in range(length))
    sms = SmsApi(pin, user_number)
    try:
        sms.send()
        auth_log("Send PIN to (%s)." % (user_number))
    except:
        if not user_number:
            auth_log("No phone number listed for user (%s)." % (user))           
        else:
            auth_log("Error sending PIN to the given SMS number (%s)" % (user_number))
        return -1
    return pin

def ldap_auth(user, password):
    LDAP_SERVER = 'LDAP://LDAPSERVer.DOMAIN.COM'
    LDAP_USERNAME = '%s@DOMAIN.COM' % user
    LDAP_PASSWORD = password
    base_dn = 'dc=DOMAIN'
    try:
        ldap_client = ldap.initialize(LDAP_SERVER)
        ldap_client.set_option(ldap.OPT_REFERRALS,0)
        ldap_client.simple_bind_s(LDAP_USERNAME, LDAP_PASSWORD)
        auth_log("Ldap binded")
        criteria = "(&(objectClass=user)(sAMAccountName=%s))" % user
        attributes = ['mobile']
        result = ldap_client.search_s(base_dn, ldap.SCOPE_SUBTREE, criteria, attributes)
        results = [entry for dn, entry in result if isinstance(entry, dict)]
        mobile = results[0].get('mobile')[0]
        ldap_client.unbind()
        return mobile
    except ldap.INVALID_CREDENTIALS:
        ldap_client.unbind()
        auth_log("Wrong username or password for user (%s)." % (user))
        return -1
    except ldap.SERVER_DOWN:
        auth_log("AD server not awailable")
        return -1
    except ldap.FILTER_ERROR:
        ldap_client.unbind()
        auth_log("Wrong ldap filter")
        return -1
    except ldap.LDAPError:
        auth_log("Another error during ldap processing")
        return -1

def pam_sm_authenticate(pamh, flags, argv):
    PIN_LENGTH = 8 
    try:
        user = pamh.get_user()
        auth_log("User trying to login: (%s)." % (user))
        msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "password: ")
        password = (pamh.conversation(msg)).resp
        user_number = ldap_auth(user, password)
    except pamh.exception, e:
        msg = pamh.Message(pamh.PAM_ERROR_MSG, "Unable to authenticate via ldap or collect phone number.\nPlease, contact your System Administrator")
        pamh.conversation(msg)
        """return pamh.PAM_ABORT"""
        return e.pam_result

    if user is None or user_number == -1:
        msg = pamh.Message(pamh.PAM_ERROR_MSG, "Unable to send one time PIN.\nPlease, contact your System Administrator")
        pamh.conversation(msg)
        return pamh.PAM_ABORT
    pin = gen_pin(user, user_number, PIN_LENGTH)
    if pin == -1:
        msg = pamh.Message(pamh.PAM_ERROR_MSG, "Unable to send one time PIN.\nPlease, contact your System Administrator")
        pamh.conversation(msg)
        return pamh.PAM_ABORT
    for attempt in range(0,3):
        msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Enter one time PIN: ")
        resp = pamh.conversation(msg)
        if resp.resp == pin:
            return pamh.PAM_SUCCESS
        else:
            continue
    return pamh.PAM_AUTH_ERR

def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS
def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS
def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS
def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS
def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS
