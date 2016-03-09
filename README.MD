# PAM-LDAP-SMS
Simple py module to authenticate via LDAP (Active Directory) and SMS.

  - LDAP connection binds with user credentials
  - SMS sends via sms-service api (fix it to your own)
  - Mobile number gets from AD attribute named 'mobile'
  - You can add additional ldap filters to ldap_auth() function
  
## Installation
### Prerequisites
> https://sourceforge.net/projects/pam-python/files/ (to compile on centos/redhat/fedora install patch https://sourceforge.net/p/pam-python/tickets/1/attachment/pam-python-1.0.4-fedora.patch) 

> pip install python-ldap

> pip install requests

and another imported modules ypu don't have already 

Copy binaries:
```sh
git clone https://github.com/starshayayord/pam_ldap_sms.git
cd pam_ldap_sms
cp pam_ldap_sms.py /lib/security/ #or /lib64/security
```
Change /etc/ssh/sshd_config
```sh
ChallengeResponseAuthentication yes
```
Change /etc/pamd./sshd
```sh
auth       sufficient   pam_python.so pam_ldap_sms.py
```
> IMPORTANT: If you are absolutely sure that are authorized in LDAP with the right credentials, please check that selinux right configured  or disabled.

