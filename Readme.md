# Linux Mail Server
In this guide, I will show you how to make a Linux Mail Server in fast and easy way.
This guide was taken from [tiq's tech-blog](https://tech.tiq.cc/2014/02/how-to-set-up-an-email-server-with-postfix-and-dovecot-without-mysql-on-debian-7/) for recent version, Linux distro I using is Ubuntu 20.04 LTS

# Certificate
Make sure you have Certificate and Key file ready to use.

make selfsigned cert

File for `~/openssl.cnf`

```
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = dev.mail.crm.com

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = mail.crm.com
DNS.2 = dev.mail.crm.com
DNS.3 = *.dev.mail.crm.com
IP.1 = 192.168.1.124
IP.1 = 127.0.0.1
```

create request cert
openssl req -new -newkey rsa:2048 -nodes -keyout dev.mail.crm.com.key -out dev.mail.crm.com.csr -subj "/CN=dev.mail.crm.com"

create cert
openssl x509 -req -in dev.mail.crm.com.csr -signkey dev.mail.crm.com.key -out dev.mail.crm.com.crt -days 3365 -extfile openssl.cnf -extensions v3_req


You can use existing Web Server SSL certificate, since we going to use same domain, `example.com`.

If you plan to use `mx.example.com` or `mail.example.com` you need create another one for these.

# Hostname, DNS & rDNS
Before you start, make sure you have a valid **Hostname**, **DNS** & **rDNS** ready in place.
However, you might not require **rDNS** to work, if you have one, this is just a bonus.

Example:
| Domain           | Type  |  Address        |
|------------------|:-----:|----------------:|
| dev.mail.crm.com |   A   | 192.1.2.3       |
| dev.mail.crm.com |   MX  | 10: example.com |

If you want to use sub-domain DNS record:
| Domain           | Type  |  Address        |
|------------------|:-----:|----------------:|
| example.com      |   A   | 192.1.2.3       |
| mail.example.com |   MX  | 10: example.com |

> Remember! Replace `example.com` to your domain when follow this guide!

# Install
Make sure Ubuntu server was on latest update and upgrade.

Login as **root** `sudo -i` and proceed to download these package:
```
apt install postfix dovecot-core dovecot-pop3d dovecot-imapd
```
> Select “Internet Site” during the installation process of postfix.

## Reinstall
Sure you mess something up, don't worry, you can restart, `purge` then `install`
```
apt purge postfix dovecot-core dovecot-pop3d dovecot-imapd
```

# User for Mail Server
Create `vmail` user with id `5000`
```
groupadd -g 5000 vmail
useradd -s /usr/sbin/nologin -u 5000 -g 5000 vmail
```

Add `postfix` and `dovecot` to `vmail` group
```
usermod -aG vmail postfix
usermod -aG vmail dovecot
```

# Required Folder & Files
Create folder for Mails to store and give permission to `vmail` group
```
mkdir -p /var/mail/vhosts/example.com
chown -R vmail:vmail /var/mail/vhosts
chmod -R 775 /var/mail/vhosts
```

Create `dovecot` log
```
touch /var/log/dovecot
chgrp vmail /var/log/dovecot
chmod 660 /var/log/dovecot
```

# Mailbox, Aliases & Domains
## Virtual Domains
Create a file
```
nano /etc/postfix/virtual_domains
```
During edit, add your domain and save.
```
example.com
```

## Virtual Mailbox
Create a empty file for now, later we using `add_useremail.sh` scripts to add emails
```
touch /etc/postfix/vmailbox
```

## Virtual Aliases
Create a file
```
nano /etc/postfix/virtual_alias
```

During edit, add one alias `root` to `admin` and save.
```
root@example.com admin@example.com
```

Execute this command every-time you **edit**, this will generate `.db` hash file for `postfix`
```
postmap /etc/postfix/virtual_alias
```

# Configuration files
All lines that you need to change have the string `CHANGETHIS` in them.

## Postfix main config
File for `/etc/postfix/main.cf`
```
smtpd_banner = Welcome to ESMTP for $myhostname (TempleOS)
biff = no
append_dot_mydomain = no
recipient_delimiter = +
readme_directory = no
myhostname = CHANGETHIS, example: mail
mydomain = CHANGETHIS, example: mail.dev.crm.com
myorigin = $mydomain
inet_interfaces = all
mydestination = localhost, $mydomain
mynetworks = 127.0.0.0/8 192.168.0.0/16

virtual_mailbox_domains = /etc/postfix/virtual_domains
virtual_mailbox_base = /var/mail/vhosts
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
virtual_alias_maps = hash:/etc/postfix/virtual_alias
virtual_minimum_uid = 100
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000
virtual_transport = virtual
virtual_mailbox_limit = 104857600
mailbox_size_limit = 0
message_size_limit = 52428800
dovecot_destination_recipient_limit = 1

##SASL##
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $mydomain
broken_sasl_auth_clients = yes

##TLS##
smtpd_use_tls = yes
smtpd_tls_security_level = may
smtpd_tls_auth_only = no
smtpd_tls_cert_file = /CHANGETHIS/your/certificate.crt
smtpd_tls_key_file = /CHANGETHIS/your/certificate.key
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtpd_tls_received_header = yes
smtpd_tls_security_level = may
smtp_tls_security_level = may
tls_random_source = dev:/dev/urandom

##restrictions##
smtpd_helo_required = no
smtpd_delay_reject = yes
strict_rfc821_envelopes = yes
disable_vrfy_command = yes

##limit rate##
anvil_rate_time_unit = 60s
smtpd_client_connection_rate_limit = 5
smtpd_client_connection_count_limit = 5

smtpd_error_sleep_time = 5s
smtpd_soft_error_limit = 2
smtpd_hard_error_limit = 3
##################

smtpd_helo_restrictions = permit_mynetworks,
  permit_sasl_authenticated,
  reject_non_fqdn_hostname,
  reject_invalid_helo_hostname,
  reject_unknown_helo_hostname

smtpd_client_restrictions = permit_mynetworks,
  permit_sasl_authenticated,
  reject_unknown_client_hostname,
  reject_unauth_pipelining,
  reject_rbl_client zen.spamhaus.org

smtpd_sender_restrictions = reject_non_fqdn_sender,
  reject_unknown_sender_domain

smtpd_recipient_restrictions = permit_mynetworks,
  permit_sasl_authenticated,
  reject_invalid_hostname,
  reject_non_fqdn_hostname,
  reject_non_fqdn_sender,
  reject_non_fqdn_recipient,
  reject_unauth_destination,
  reject_unauth_pipelining,
  reject_rbl_client zen.spamhaus.org,
  reject_rbl_client cbl.abuseat.org,
  reject_rbl_client dul.dnsbl.sorbs.net

smtpd_recipient_limit = 250
broken_sasl_auth_clients = yes
```
## Postfix master config
```
smtp       inet  n       -       -       -       -       smtpd
8080       inet  n       -       -       -       -       smtpd
smtps      inet  n       -       -       -       -       smtpd
submission inet  n       -       n       -       -       smtpd
pickup     fifo  n       -       -       60      1       pickup
cleanup    unix  n       -       -       -       0       cleanup
qmgr       fifo  n       -       n       300     1       qmgr
tlsmgr     unix  -       -       -       1000?   1       tlsmgr
rewrite    unix  -       -       -       -       -       trivial-rewrite
bounce     unix  -       -       -       -       0       bounce
defer      unix  -       -       -       -       0       bounce
trace      unix  -       -       -       -       0       bounce
verify     unix  -       -       -       -       1       verify
flush      unix  n       -       -       1000?   0       flush
proxymap   unix  -       -       n       -       -       proxymap
proxywrite unix  -       -       n       -       1       proxymap
smtp       unix  -       -       -       -       -       smtp
relay      unix  -       -       -       -       -       smtp
showq      unix  n       -       -       -       -       showq
error      unix  -       -       -       -       -       error
retry      unix  -       -       -       -       -       error
discard    unix  -       -       -       -       -       discard
local      unix  -       n       n       -       -       local
virtual    unix  -       n       n       -       -       virtual
lmtp       unix  -       -       -       -       -       lmtp
anvil      unix  -       -       -       -       1       anvil
scache     unix  -       -       -       -       1       scache
uucp       unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
ifmail     unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp      unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix	-	n	n	-	2	pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman    unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  ${nexthop} ${user}
dovecot    unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail:vmail argv=/usr/lib/dovecot/deliver -f ${sender} -d ${recipient}
```

##  Dovecot main config
File for `/etc/dovecot/dovecot.conf`
```
auth_mechanisms = plain login
disable_plaintext_auth = no
log_path = /var/log/dovecot
mail_location = maildir:/var/mail/vhosts/%d/%n

passdb {
	args = /var/mail/vhosts/%d/shadow
	driver = passwd-file
}

protocols = imap pop3

service auth {
	unix_listener /var/spool/postfix/private/auth {
		group = vmail
		mode = 0660
		user = postfix
	}
		unix_listener auth-master {
		group = vmail
		mode = 0600
		user = vmail
	}
}

ssl_cert = </CHANGETHIS/your/certificate.crt
ssl_key = </CHANGETHIS/your/certificate.key

userdb {
	args = /var/mail/vhosts/%d/passwd
	driver = passwd-file
}

protocol lda {
	auth_socket_path = /var/run/dovecot/auth-master
	hostname = CHANGETHIS, example: dev.mail.crm.com
	mail_plugin_dir = /usr/lib/dovecot/modules
	mail_plugins = sieve
	postmaster_address = CHANGETHIS, example: postmaster@dev.mail.crm.com
}
```

# Add Virtual User Email
Create `add_useremail.sh`
```
nano ~/add_useremail.sh
```
During edit, paste this and save.
```shell
#!/bin/bash
USAGE="Usage: $0 EMAIL PASSWORD [BASEDIR]";

if [ ! -n "$2" ]
then
	echo $USAGE;
	exit 1;
fi

USERNAME=$(echo "$1" | cut -f1 -d@);
DOMAIN=$(echo "$1" | cut -f2 -d@);
ADDRESS=$1;
PASSWD=$2;

if [ -n "$3" ]
then
	if [ ! -d "$3" ]
	then
		echo $USAGE;
		echo "BASEDIR must be a valid directory!";
		echo "I would have tried, $(postconf | grep ^virtual_mailbox_base | cut -f3 -d' ')";
		exit 2;
	else
	BASEDIR="$3";
	fi
else
	BASEDIR="$(postconf | grep ^virtual_mailbox_base | cut -f3 -d' ')";
fi

if [ -f /etc/postfix/vmailbox ]
then
	echo "Adding Postfix user configuration..."
	echo $ADDRESS $DOMAIN/$USERNAME/ >> /etc/postfix/vmailbox
	postmap /etc/postfix/vmailbox

	if [ $? -eq 0 ]
	then
		echo "Adding Dovecot user configuration..."
		echo $ADDRESS::5000:5000::$BASEDIR/$DOMAIN/$ADDRESS>> $BASEDIR/$DOMAIN/passwd
		echo $ADDRESS":"$(doveadm pw -p $PASSWD) >> $BASEDIR/$DOMAIN/shadow
		chown vmail:vmail $BASEDIR/$DOMAIN/passwd && chmod 775 $BASEDIR/$DOMAIN/passwd
		chown vmail:vmail $BASEDIR/$DOMAIN/shadow && chmod 775 $BASEDIR/$DOMAIN/shadow
		/etc/init.d/postfix reload
	fi
fi

```
To add email, simple execute:
```
bash ~/add_useremail.sh admin@example.com mypassword
```

# Connect to Email Clients
SMTP Port: 25 (or 587, or 8080. In some networks, port 25 and 587 outgoing are blocked)  
IMAP Port: 143  
POP3 Port: 110

Incoming & Outgoing mail server: example.com
*Or any domain that have valid certificate: mx.example.com or mail.example.com*

Username need in full, example: admin@example.com

SMTP require Authentication.
