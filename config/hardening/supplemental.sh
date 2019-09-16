#!/bin/sh
# This script was written by Frank Caviggia
# Last update was 13 May 2017
#
# Script: suplemental.sh (system-hardening)
# Description: Supplemental Hardening 
# License: Apache License, Version 2.0
# Copyright: Frank Caviggia, 2018
# Author: Frank Caviggia <fcaviggi (at) gmail.com>
#
# Modifications:
#
# danielsen - 9/16/2019
# - Changes legal banner

########################################
# LEGAL BANNER CONFIGURATION
########################################
BANNER_MESSAGE_TEXT='This system is for the use of authorized users only.\nIndividuals using this computer system without \nauthority, or in excess of their authority, are subject \nto having all of their activities on this system \nmonitored and recorded by system personnel. In the course of monitoring \nindividuals improperly using this \nsystem, or in the course of system maintenance, the \activities of authorized users may also be monitored. \nAnyone using this system expressly consents to such \nmonitoring and is advised that is such monitoring \nreveals possible evidence of criminal activity, system \npersonnel may provide the evidence of such monitoring \nto law enforcement officials.\n\n'
echo -e "${BANNER_MESSAGE_TEXT}" > /etc/issue
echo -e "${BANNER_MESSAGE_TEXT}" > /etc/issue.net

########################################
# DISA STIG PAM Configurations
########################################
cat <<EOF > /etc/pam.d/system-auth-local
#%PAM-1.0
auth required pam_env.so
auth required pam_lastlog.so inactive=35
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth requisite pam_succeed_if.so uid >= 1000 quiet
auth required pam_deny.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so inactive=35
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 1000 quiet
account required pam_permit.so

# Password Quality now set in /etc/security/pwquality.conf
password required pam_pwquality.so retry=3
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
-session optional pam_systemd.so
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
EOF
ln -sf /etc/pam.d/system-auth-local /etc/pam.d/system-auth
cat /etc/pam.d/system-auth-local > /etc/pam.d/system-auth-ac
chattr +i /etc/pam.d/system-auth-local

cat <<EOF > /etc/pam.d/password-auth-local
#%PAM-1.0
auth required pam_env.so
auth required pam_lastlog.so inactive=35
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth requisite pam_succeed_if.so uid >= 1000 quiet
auth required pam_deny.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so inactive=35
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 1000 quiet
account required pam_permit.so

# Password Quality now set in /etc/security/pwquality.conf
password required pam_pwquality.so retry=3
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
-session optional pam_systemd.so
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
EOF
ln -sf /etc/pam.d/password-auth-local /etc/pam.d/password-auth
cat /etc/pam.d/password-auth-local > /etc/pam.d/password-auth-ac
chattr +i /etc/pam.d/password-auth-local

cat <<EOF > /etc/security/pwquality.conf
# Configuration for systemwide password quality limits
# Defaults:
#
# Number of characters in the new password that must not be present in the
# old password.
# difok = 5
difok = 15
#
# Minimum acceptable size for the new password (plus one if
# credits are not disabled which is the default). (See pam_cracklib manual.)
# Cannot be set to lower value than 6.
# minlen = 9
minlen = 15
#
# The maximum credit for having digits in the new password. If less than 0
# it is the minimum number of digits in the new password.
# dcredit = 1
dcredit = -1
#
# The maximum credit for having uppercase characters in the new password.
# If less than 0 it is the minimum number of uppercase characters in the new
# password.
# ucredit = 1
ucredit = -1
#
# The maximum credit for having lowercase characters in the new password.
# If less than 0 it is the minimum number of lowercase characters in the new
# password.
# lcredit = 1
lcredit = -1
#
# The maximum credit for having other characters in the new password.
# If less than 0 it is the minimum number of other characters in the new
# password.
# ocredit = 1
ocredit = -1
#
# The minimum number of required classes of characters for the new
# password (digits, uppercase, lowercase, others).
minclass = 4
#
# The maximum number of allowed consecutive same characters in the new password.
# The check is disabled if the value is 0.
maxrepeat = 2
#
# The maximum number of allowed consecutive characters of the same class in the
# new password.
# The check is disabled if the value is 0.
maxclassrepeat = 2
#
# Whether to check for the words from the passwd entry GECOS string of the user.
# The check is enabled if the value is not 0.
# gecoscheck = 0
#
# Path to the cracklib dictionaries. Default is to use the cracklib default.
# dictpath =
EOF

## Secured NTP Configuration
cat <<EOF > /etc/ntp.conf
# by default act only as a basic NTP client
restrict -4 default nomodify nopeer noquery notrap
restrict -6 default nomodify nopeer noquery notrap
# allow NTP messages from the loopback address, useful for debugging
restrict 127.0.0.1
restrict ::1
# poll server at higher rate to prevent drift
maxpoll 10
# server(s) we time sync to
##server 192.168.0.1
##server 2001:DB9::1
#server time.example.net
server tick.usno.navy.mil
server tock.usno.navy.mil
EOF

cat <<EOF > /etc/chrony.conf
# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (http://www.pool.ntp.org/join.html).
# server freeipa.local.lan iburst
server tick.usno.navy.mil iburst
server tock.usno.navy.mil iburst

# Record the rate at which the system clock gains/losses time.
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
# if its offset is larger than 1 second.
makestep 1.0 3

# Enable kernel synchronization of the real-time clock (RTC).
rtcsync

# Enable hardware timestamping on all interfaces that support it.
hwtimestamp *

# Increase the minimum number of selectable sources required to adjust
# the system clock.
#minsources 2

# Allow NTP client access from local network.
#allow 192.168.0.0/16

# Serve time even if not synchronized to a time source.
local stratum 10

# Specify file containing keys for NTP authentication.
keyfile /etc/chrony.keys

# Get TAI-UTC offset and leap seconds from the system tz database.
leapsectz right/UTC

# Specify directory for log files.
logdir /var/log/chrony

# Select which information is logged.
#log measurements statistics tracking
EOF


########################################
# STIG Audit Configuration
########################################
cat <<EOF > /etc/audit/rules.d/audit.rules
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## Set failure mode to syslog
-f 1

# BEGIN MANAGED BY ANSIBLE-HARDENING
## Rules for auditd deployed by ansible-hardening
# Do not edit any of these rules directly. The contents of this file are
# controlled by Ansible variables and each variable is explained in detail
# within the role documentation:
#
#    http://docs.openstack.org/developer/ansible-hardening/
#

# Delete all existing auditd rules prior to loading this ruleset.
-D

# Increase the buffers to survive stress events.
-b 320

# Set the auditd failure flag.
-f 1

# V-72097
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# V-72099
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# V-72099
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# V-72103
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

# V-72105
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

# V-72107
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

# V-72109
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

# V-72111
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
#-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod # in V-75717 now 

# V-72113
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
#-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod # V-75721

# V-72115
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
#-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod V-75719

# V-72117
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
#-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod # V-75723

# V-72119
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# V-72121
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# V-72123
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access

# V-72125
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access

# V-72127
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access

# V-72129
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access

# V-72131
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access

# V-72133
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access

# V-72135
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

# V-72137
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

# V-72139
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

# V-72143
-w /var/log/tallylog -p wa -k logins

# V-72145
-w /var/run/faillock/ -p wa -k logins

# V-72147
-w /var/log/lastlog -p wa -k logins

# V-72149
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

# V-72151
-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

# V-72153
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

# V-72155
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

# V-72157
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

# V-72159
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

# V-72161
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

# V-72163
-w /etc/sudoers -p wa -k privileged-actions
-w /etc/sudoers.d -p wa -k privileged-actions

# V-72165
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

# V-72167
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

# V-72169
-a always,exit -F path=/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

# V-72171
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount

# V-72173
-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount

# V-72175
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-postfix

# V-72177
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-postfix

# V-72183
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-cron

# V-72185
-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam

# V-72187
-a always,exit -F arch=b32 -S init_module -k module-change
-a always,exit -F arch=b64 -S init_module -k module-change

# V-72189
-a always,exit -F arch=b32 -S delete_module -k module-change
-a always,exit -F arch=b64 -S delete_module -k module-change

# V-72191
-w /sbin/insmod -p x -F auid!=4294967295 -k module-change

# V-72195
-w /sbin/modprobe -p x -F auid!=4294967295 -k module-change

# V-72197
-w /etc/passwd -p wa -k identity

# V-72199
-a always,exit -F arch=b32 -S rename -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S rename -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

# V-72201
-a always,exit -F arch=b32 -S renameat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S renameat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

# V-72203
-a always,exit -F arch=b32 -S rmdir -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S rmdir -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

# V-72205
-a always,exit -F arch=b32 -S unlink -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S unlink -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

# V-72207
-a always,exit -F arch=b32 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete

#testing - ramy
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-a always,exit -F path=/usr/sbin/restorecon -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change
-w /sbin/rmmod -p x -F auid!=4294967295 -k module-change

#nessus fix text is missing the security directory for these
-w /etc/security/opasswd -p wa -k identity
-w /etc/security/group -p wa -k identity

# ian Fixes
-w /etc/opasswd -p wa -k identity

# V-78999
-a always,exit -F arch=b32 -S create_module -k module-change
-a always,exit -F arch=b64 -S create_module -k module-change

# V-79001
-a always,exit -F arch=b32 -S finit_module -k module-change
-a always,exit -F arch=b64 -S finit_module -k module-change

# V-72141
-a always,exit -F path=/usr/sbin/setfiles -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

# V-72179
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh

# V-72181
-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged_terminal

# V-75689
-a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv 
-a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv 

# V-75693
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

# V-75695
-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount

# V-75699
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh

# V-75709
-w /sbin/insmod -p x -k modules

# V-75711
-w /sbin/rmmod -p x -k modules

# V-75713
-w /sbin/modprobe -p x -k modules

# V-75715
-w /bin/kmod -p x -k modules

# V-75717
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod 

# V-75719
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -k perm_mod 

# V-75721
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod

# V-75723
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid=0 -k perm_mod

# V-75725
#-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod 

# V-75729
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_chng

# V-75731
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_chng

# V-75733
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_chng

# V-75735
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng

# V-75737
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_chng

# V-75739
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_chng

# V-75741
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng

# V-75743
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

# V-75745
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

# V-75747
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

# V-75749
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

# V-75751
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

# V-75753
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

# V-75755
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd

# V-75757
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd

# V-75759
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd

# V-75761
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd

# V-75765
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng

# V-75767
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng

# V-75769
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng

# V-75773
-w /var/log/faillog -p wa -k logins

# V-75779
-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update

# V-75781
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd

# V-75783
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chage

# V-75785
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod

# V-75787
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-crontab

# V-75789
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam_timestamp_check

# V-75791
-a always,exit -F arch=b64 -S init_module -F auid>=1000 -F auid!=4294967295 -k module_chng

# V-75793
-a always,exit -F arch=b64 -S finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng

# V-75795
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng
# END MANAGED BY ANSIBLE-HARDENING
EOF
# Find and monitor additional privileged commands
for PROG in `find / -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null`; do
	fgrep -r "path=$PROG" /etc/audit/rules.d/
	if [ $? -ne 0 ]; then
		echo "-a always,exit -F path=$PROG -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"  >> /etc/audit/rules.d/zzz-supplemental.rules
	fi
done

# Sometimes the SSG leaves some rules in a file simply named ".rules".
# This is also caused by the below mentioned "key" syntax mismatch.
if [ -f /etc/audit/rules.d/.rules ]; then
	# Some of the rules in the .rules file are invalid, this should
	# be fixed in 0.1.34.
	sed -i -e 's/EACCESS/EACCES/' /etc/audit/rules.d/.rules
	sed -i -e 's/EPRM/EPERM/'     /etc/audit/rules.d/.rules

	# Inconsistent syntax can lead to duplicate rules.  I'm told that:
	# 'The "-F key=$key" is correct and should be the audit key syntax
	# going forward. ... rather than moving backward to the -k syntax.'
	# But, most of the existing rules use the "old" syntax as well as
	# all of the STIG XCCDF content, so I'm normalizing that direction.
	sed -i -e 's/-F key=/-k /'    /etc/audit/rules.d/.rules
	sed -i -e 's/-F key=/-k /'    /etc/audit/rules.d/*.rules

	# Some of the rules in the .rules file are duplicates (due to
	# the above mentioned syntax mismatch).
	sort /etc/audit/rules.d/.rules -o /etc/audit/rules.d/.rules
	sort /etc/audit/rules.d/*.rules | comm -13 - /etc/audit/rules.d/.rules > /etc/audit/rules.d/ssg-orphaned.rules
	rm /etc/audit/rules.d/.rules
fi

cat <<EOF >> /etc/audit/auditd.conf
#
# This file controls the configuration of the audit daemon
#
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = RAW
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 8
num_logs = 5
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file_action = ROTATE
space_left = 500
verify_email = yes
action_mail_acct = root
admin_space_left = 75
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
##tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
distribute_network = no
EOF


########################################
# Fix cron.allow
########################################
echo "root" > /etc/cron.allow
chmod 400 /etc/cron.allow
chown root:root /etc/cron.allow

########################################
# Make SELinux Configuration Immutable
########################################
chattr +i /etc/selinux/config

########################################
# Disable Control-Alt-Delete
########################################
ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target


########################################
# No Root Login to Console (use admin user)
########################################
cat /dev/null > /etc/securetty


########################################
# SSSD Configuration
########################################
mkdir -p /etc/sssd
cat <<EOF > /etc/sssd/sssd.conf
[sssd]
services = sudo, autofs, pam
EOF

########################################
# Disable Interactive Shell (Timeout)
########################################
cat <<EOF > /etc/profile.d/autologout.sh
#!/bin/sh
TMOUT=600
export TMOUT
readonly TMOUT
EOF
cat <<EOF > /etc/profile.d/autologout.csh
#!/bin/csh
set autologout=15
set -r autologout
EOF
chown root:root /etc/profile.d/autologout.sh
chown root:root /etc/profile.d/autologout.csh
chmod 555 /etc/profile.d/autologout.sh
chmod 555 /etc/profile.d/autologout.csh

########################################
# Set Shell UMASK Setting (027)
########################################
cat <<EOF > /etc/profile.d/umask.sh
#!/bin/sh

# Non-Privledged Users get 027
# Privledged Users get 022
if [[ \$EUID -ne 0 ]]; then
	umask 027
else
	umask 022
fi
EOF
cat <<EOF > /etc/profile.d/umask.csh
#!/bin/csh
umask 027
EOF
chown root:root /etc/profile.d/umask.sh
chown root:root /etc/profile.d/umask.csh
chmod 555 /etc/profile.d/umask.sh
chmod 555 /etc/profile.d/umask.csh


########################################
# Vlock Alias (Cosole Screen Lock)
########################################
cat <<EOF > /etc/profile.d/vlock-alias.sh
#!/bin/sh
alias vlock='clear;vlock -a'
EOF
cat <<EOF > /etc/profile.d/vlock-alias.csh
#!/bin/csh
alias vlock 'clear;vlock -a'
EOF
chown root:root /etc/profile.d/vlock-alias.sh
chown root:root /etc/profile.d/vlock-alias.csh
chmod 555 /etc/profile.d/vlock-alias.sh
chmod 555 /etc/profile.d/vlock-alias.csh


########################################
# Wheel Group Require (sudo)
########################################
sed -i -re '/pam_wheel.so use_uid/s/^#//' /etc/pam.d/su
sed -i 's/^#\s*\(%wheel\s*ALL=(ALL)\s*ALL\)/\1/' /etc/sudoers
echo -e "\n## Set timeout for authentiation (5 Minutes)\nDefaults:ALL timestamp_timeout=5\n" >> /etc/sudoers


########################################
# Set Removeable Media to noexec
#   CCE-27196-5
########################################
for DEVICE in $(/bin/lsblk | grep sr | awk '{ print $1 }'); do
	mkdir -p /mnt/$DEVICE
	echo -e "/dev/$DEVICE\t\t/mnt/$DEVICE\t\tiso9660\tdefaults,ro,noexec,nosuid,nodev,noauto\t0 0" >> /etc/fstab
done
for DEVICE in $(cd /dev;ls *cd* *dvd*); do
	mkdir -p /mnt/$DEVICE
	echo -e "/dev/$DEVICE\t\t/mnt/$DEVICE\t\tiso9660\tdefaults,ro,noexec,nosuid,nodev,noauto\t0 0" >> /etc/fstab
done


########################################
# SSHD Hardening
########################################
sed -i '/Ciphers.*/d' /etc/ssh/ssh*config
sed -i '/MACs.*/d' /etc/ssh/ssh*config
sed -i '/Protocol.*/d' /etc/ssh/sshd_config
echo "Protocol 2" >> /etc/ssh/sshd_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/ssh_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
echo "MACs hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/ssh_config
echo "MACs hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
echo "PrintLastLog yes" >> /etc/ssh/sshd_config
echo "AllowGroups sshusers" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
echo "Banner /etc/issue" >> /etc/ssh/sshd_config
echo "RhostsRSAAuthentication no" >> /etc/ssh/sshd_config
echo "GSSAPIAuthentication no" >> /etc/ssh/sshd_config
echo "KerberosAuthentication no" >> /etc/ssh/sshd_config
echo "IgnoreUserKnownHosts yes" >> /etc/ssh/sshd_config
echo "StrictModes yes" >> /etc/ssh/sshd_config
echo "UsePrivilegeSeparation yes" >> /etc/ssh/sshd_config
echo "Compression delayed" >> /etc/ssh/sshd_config
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
if [ $(grep -c sshusers /etc/group) -eq 0 ]; then
	/usr/sbin/groupadd sshusers &> /dev/null
fi


########################################
# TCP_WRAPPERS
########################################
cat <<EOF >> /etc/hosts.allow
# LOCALHOST (ALL TRAFFIC ALLOWED) DO NOT REMOVE FOLLOWING LINE
ALL: 127.0.0.1 [::1]
# Allow SSH (you can limit this further using IP addresses - e.g. 192.168.0.*)
sshd: ALL
EOF
cat <<EOF >> /etc/hosts.deny
# Deny All by Default
ALL: ALL
EOF

########################################
# FirewallD Additonal Protections
########################################
# Set Default Zone to DROP
sed -i '/DefaultZone=/c\DefaultZone=drop' /etc/firewalld/firewalld.conf
# Rate Limit
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 0 -p tcp -m limit --limit 25/minute --limit-burst100  -j ACCEPT
# Remove DHCPv6
firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client
firewall-cmd --reload


########################################
# Postfix - Prevent Mail Relay
########################################
postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject'    


########################################
# Filesystem Attributes
#  CCE-26499-4,CCE-26720-3,CCE-26762-5,
#  CCE-26778-1,CCE-26622-1,CCE-26486-1.
#  CCE-27196-5
########################################
FSTAB=/etc/fstab
SED=`which sed`

if [ $(grep " \/sys " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	MNT_OPTS=$(grep " \/sys " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/sys.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/boot " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	MNT_OPTS=$(grep " \/boot " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/boot.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/usr " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/usr " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/usr .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/home " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/home " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/home .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/export\/home " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/export\/home " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/export\/home .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/usr\/local " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/usr\/local " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/usr\/local.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/dev\/shm " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/dev\/shm " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/dev\/shm.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/tmp " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/tmp " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/log " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/log\/audit " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/log\/audit " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/log\/audit.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/www " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/wwww " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/www.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/opt " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/opt " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/opt.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
echo -e "tmpfs\t\t\t/dev/shm\t\ttmpfs\tnoexec,nosuid,nodev\t\t0 0" >> /etc/fstab

########################################
# File Ownership 
########################################
find / -nouser -print | xargs chown root
find / -nogroup -print | xargs chown :root
cat <<EOF > /etc/cron.daily/unowned_files
#!/bin/sh
# Fix user and group ownership of files without user
find / -nouser -print | xargs chown root
find / -nogroup -print | xargs chown :root
EOF
chown root:root /etc/cron.daily/unowned_files
chmod 0700 /etc/cron.daily/unowned_files


########################################
# USGCB Blacklist
########################################
if [ -e /etc/modprobe.d/usgcb-blacklist.conf ]; then
	rm -f /etc/modprobe.d/usgcb-blacklist.conf
fi
touch /etc/modprobe.d/usgcb-blacklist.conf
chmod 0644 /etc/modprobe.d/usgcb-blacklist.conf
chcon 'system_u:object_r:modules_conf_t:s0' /etc/modprobe.d/usgcb-blacklist.conf

cat <<EOF > /etc/modprobe.d/usgcb-blacklist.conf
# Disable Bluetooth
install bluetooth /bin/true
# Disable AppleTalk
install appletalk /bin/true
# NSA Recommendation: Disable mounting USB Mass Storage
install usb-storage /bin/true
# Disable mounting of cramfs CCE-14089-7
install cramfs /bin/true
# Disable mounting of freevxfs CCE-14457-6
install freevxfs /bin/true
# Disable mounting of hfs CCE-15087-0
install hfs /bin/true
# Disable mounting of hfsplus CCE-14093-9
install hfsplus /bin/true
# Disable mounting of jffs2 CCE-14853-6
install jffs2 /bin/true
# Disable mounting of squashfs CCE-14118-4
install squashfs /bin/true
# Disable mounting of udf CCE-14871-8
install udf /bin/true
# CCE-14268-7
install dccp /bin/true
# CCE-14235-5
install sctp /bin/true
#i CCE-14027-7
install rds /bin/true
# CCE-14911-2
install tipc /bin/true
# CCE-14948-4 (row 176)
install net-pf-31 /bin/true
EOF


########################################
# GNOME 3 Lockdowns
########################################
if [ -x /bin/gsettings ]; then
	cat << EOF > /etc/dconf/db/gdm.d/99-gnome-hardening
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text="${BANNER_MESSAGE_TEXT}"
disable-user-list=true
disable-restart-buttons=true

[org/gnome/desktop/lockdown]
user-administration-disabled=true
disable-user-switching=true

[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true

[org/gnome/desktop/notifications] 
show-in-lock-screen=false

[org/gnome/desktop/privacy]
remove-old-temp-files=true
remove-old-trash-files=true
old-files-age=7

[org/gnome/desktop/interface]
clock-format="12h"

[org/gnome/desktop/screensaver]
user-switch-enabled=false
lock-enabled=true

[org/gnome/desktop/session]
idle-delay=900

[org/gnome/desktop/thumbnailers]
disable-all=true

[org/gnome/nm-applet]
disable-wifi-create=true
EOF
	cat << EOF > /etc/dconf/db/gdm.d/locks/99-gnome-hardening
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
/org/gnome/login-screen/disable-user-list
/org/gnome/login-screen/disable-restart-buttons
/org/gnome/desktop/lockdown/user-administration-disabled
/org/gnome/desktop/lockdown/disable-user-switching
/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/automount-open
/org/gnome/desktop/media-handling/autorun-never
/org/gnome/desktop/notifications/show-in-lock-screen
/org/gnome/desktop/privacy/remove-old-temp-files
/org/gnome/desktop/privacy/remove-old-trash-files
/org/gnome/desktop/privacy/old-files-age
/org/gnome/desktop/screensaver/user-switch-enabled
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/thumbnailers/disable-all
/org/gnome/nm-applet/disable-wifi-create
EOF
	cat << EOF > /usr/share/glib-2.0/schemas/99-custom-settings.gschema.override
[org.gnome.login-screen]
banner-message-enable=true
banner-message-text="${BANNER_MESSAGE_TEXT}"
disable-user-list=true
disable-restart-buttons=true

[org.gnome.desktop.lockdown]
user-administration-disabled=true
disable-user-switching=true

[org.gnome.desktop.media-handling]
automount=false
automount-open=false
autorun-never=true

[org.gnome.desktop.notifications] 
show-in-lock-screen=false

[org.gnome.desktop.privacy]
remove-old-temp-files=true
remove-old-trash-files=true
old-files-age=7

[org.gnome.desktop.interface]
clock-format="12h"

[org.gnome.desktop.screensaver]
user-switch-enabled=false
lock-enabled=true

[org.gnome.desktop.session]
idle-delay=900

[org.gnome.desktop.thumbnailers]
disable-all=true

[org.gnome.nm-applet]
disable-wifi-create=true
EOF

	cat << EOF > /etc/gdm/custom.conf
# GDM configuration storage

[daemon]
AutomaticLoginEnable=false
TimedLoginEnable=false

[security]

[xdmcp]

[greeter]

[chooser]

[debug]

EOF
	cp /etc/dconf/db/gdm.d/locks/99-gnome-hardening /etc/dconf/db/local.d/locks/99-gnome-hardening
 	/bin/glib-compile-schemas /usr/share/glib-2.0/schemas/
	/bin/dconf update
fi

########################################
# Kernel - Randomize Memory Space
# CCE-27127-0, SC-30(2), 1.6.1
########################################
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

########################################
# Kernel - Accept Source Routed Packets
# AC-4, 366, SRG-OS-000480-GPOS-00227
########################################
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

#######################################
# Kernel - Disable Redirects
#######################################
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf

#######################################
# Kernel - Disable ICMP Broadcasts
#######################################
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

#######################################
# Kernel - Disable Syncookies
#######################################
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

#######################################
# Kernel - Disable TCP Timestamps
#######################################
echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf

########################################
# Disable SystemD Date Service 
# Use (chrony or ntpd)
########################################
timedatectl set-ntp false

######################################## 
# Disable Kernel Dump Service 
######################################## 
systemctl disable kdump.service 
systemctl mask kdump.service

########################################
# Enable tmp mount service
########################################
systemctl enable tmp.mount

#######################################
# RHEL-07-030201, 
#######################################
yum install -y audispd-plugins
sed -i 's/active = no/active = yes/' /etc/audisp/plugins.d/au-remote.conf

######################################
# RHEL-07-030320
#####################################
sed -i 's/disk_full_action = warn_once/disk_full_action = single/' /etc/audisp/audisp-remote.conf
sed -i 's/network_failure_action = stop/network_failure_action = single/' /etc/audisp/audisp-remote.conf


##################
# RHEL-07-020270 
#################
userdel games 
