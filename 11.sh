#!/bin/bash
#ysw BASE11-C基线加固脚本 20210723

time=$(date "+%Y%m%d%H%M%S")

pass="H@gAJHJtGmPtm*XX"
sudo_user="eversec"


os=$(rpm -q centos-release|cut -d- -f3)
if [ $os -ne 7 ];then
	echo "脚本只适合centos7系统的基线加固" && exit 1
fi

isRoot=`id -u -n | grep root | wc -l`
if [ "x$isRoot" != "x1" ]; then
	echo "请用 root登陆系统执行脚本" && exit 1
fi


[ -f "/tmp/jixian.log" ] && echo "系统已经用脚本加固过，不需要重新执行脚本" && exit 1

cp /etc/login.defs /etc/login.defs_bak_$time
sed -i -e 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' -e 's/^PASS_MIN_LEN.*$/PASS_MIN_LEN 8/' -e 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 30/'  /etc/login.defs


for user in $(awk -F: 'length($2)==0 {print $1}' /etc/shadow)
	do
		echo $pass | passwd $user --stdin > /dev/null 2>&1
	done
	

cp /etc/passwd /etc/passwd_bak_$time
for id in $(awk -F: '{ if($3 == 0 && $1 != "root") print $1 }' /etc/passwd)
do
        userdel ${id}
done

cp /etc/login.defs /etc/login.defs_bak_$time
sed -i "s/^.*UMASK.*$/UMASK           027/" /etc/login.defs

chmod 644 /etc/group > /dev/null 2>&1
chmod 644 /etc/passwd > /dev/null 2>&1
chmod 600 /etc/shadow > /dev/null 2>&1
chmod 600 /etc/xinetd.conf > /dev/null 2>&1
chmod 644 /etc/services > /dev/null 2>&1
chmod 600 /etc/security > /dev/null 2>&1
chmod 750 /etc/rc6.d > /dev/null 2>&1
chmod 750 /tmp > /dev/null 2>&1
chmod 750 /etc/rc0.d/ > /dev/null 2>&1
chmod 750 /etc/rc1.d > /dev/null 2>&1
chmod 750 /etc/rc2.d > /dev/null 2>&1
chmod 750 /etc/rc4.d > /dev/null 2>&1
chmod 750 /etc/rc5.d > /dev/null 2>&1
chmod 750 /etc/rc3.d > /dev/null 2>&1
chmod 750 /etc/rc.d/init.d > /dev/null 2>&1
chmod 600 /etc/grub.conf > /dev/null 2>&1
chmod 600 /boot/grub/grub.conf > /dev/null 2>&1
chmod 600 /etc/grub2.cfg > /dev/null 2>&1
chmod 600 /boot/grub2/grub.cfg > /dev/null 2>&1

cp /etc/csh.cshrc /etc/csh.cshrc_bak_$time
sed -i 's/022/077/g' /etc/csh.cshrc
cp /etc/csh.login /etc/csh.login_bak_$time
grep umask /etc/csh.login||echo "umask 077" >> /etc/csh.login
cp /etc/bashrc /etc/bashrc_bak_$time
sed -i 's/022/077/g' /etc/bashrc
cp /etc/profile /etc/profile_bak_$time
sed -i 's/022/077/g' /etc/profile

sed -i "s/^.*HISTSIZE=.*$/HISTSIZE=10/" /etc/profile

cat /etc/bashrc | grep "TMOUT="  > /dev/null 2>&1 && sed -i "s/^.*TMOUT=.*$/TMOUT=300/" /etc/bashrc || echo "TMOUT=300" >> /etc/bashrc


touch /etc/ssh_banner
chown bin:bin /etc/ssh_banner
chmod 644 /etc/ssh_banner
echo " Authorized only. All activity will be monitored and reported " > /etc/ssh_banner
cat /etc/ssh/sshd_config | grep -v ^# |grep Banner || sed -i '/Banner/a\\Banner /etc/ssh_banner' /etc/ssh/sshd_config

cp /etc/rsyslog.conf /etc/rsyslog.conf_bak_$time
cat /etc/rsyslog.conf | grep "kern.debug" || echo "*.err;kern.debug;daemon.notice /var/adm/messages" >> /etc/rsyslog.conf
touch /var/adm/messages
chmod 666 /var/adm/messages

touch /etc/syslog.conf
cat /etc/syslog.conf|grep "kern.debug"||echo "*.err;kern.debug;daemon.notice /var/adm/messages" >> /etc/syslog.conf
chmod 666 /var/adm/messages


if [ -f "/etc/vsftpd/vsftpd.conf" ];then
	cp /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf_bak_$time
	sed -i 's/anonymous_enable=YES/anonymous_enable=NO/g' /etc/vsftpd/vsftpd.conf
	userdel ftp
fi

echo " Authorized users only. All activity may be monitored and reported " > /etc/issue
echo " Authorized users only. All activity may be monitored and reported " > /etc/issue.net

[ -f /etc/xinetd.d/telnet ] && cp /etc/xinetd.d/telnet /etc/xinetd.d/telnet_bak_$time
cat > /etc/xinetd.d/telnet << EOF
# default: on
# description: The telnet server serves telnet sessions; it uses \
#       unencrypted username/password pairs for authentication.
service telnet
{
        flags           = REUSE
        socket_type     = stream        
        wait            = no
        user            = root
        server          = /usr/sbin/in.telnetd
        log_on_failure  += USERID
        disable         = yes
}

EOF

cp /etc/ssh/sshd_config /etc/ssh/sshd_config_bak_$time
#sed -i '/PermitRootLogin/d' /etc/ssh/sshd_config
#sed -i '$aPermitRootLogin no' /etc/ssh/sshd_config
sed -i '/Protocol/d' /etc/ssh/sshd_config
sed -i '$aProtocol 2' /etc/ssh/sshd_config


if [ -f "/etc/ftpusers" ];then
	cp /etc/ftpusers /etc/ftpusers_bak_$time
	echo "root" > /etc/ftpusers
else
	echo "root" > /etc/ftpusers
fi


cp /etc/pam.d/su /etc/pam.d/su_bak_$time
cat > /etc/pam.d/su << EOF
#%PAM-1.0
auth            sufficient      pam_rootok.so
auth            required        pam_wheel.so group=wheel
auth            substack        system-auth
auth            include         postlogin
account         sufficient      pam_succeed_if.so uid = 0 use_uid quiet
account         include         system-auth
password        include         system-auth
session         include         system-auth
session         include         postlogin
session         optional        pam_xauth.so
EOF
usermod -G wheel ${sudo_user}

cp /etc/profile /etc/profile_bak_$time
sed -i -e  's/TMOUT=[0-9]\+/TMOUT=300/g'  /etc/profile

[ -f "/usr/lib/systemd/system/ctrl-alt-del.target" ] && rm -rf /usr/lib/systemd/system/ctrl-alt-del.target

cp /etc/security/limits.conf /etc/security/limits.conf_bak_$time
cat /etc/security/limits.conf|grep -v ^# |grep "* soft core 0" > /dev/null 2>&1 || echo "* soft core 0" >> /etc/security/limits.conf
cat /etc/security/limits.conf|grep -v ^# |grep "* hard core 0" > /dev/null 2>&1 || echo "* hard core 0" >> /etc/security/limits.conf

cp /etc/sysctl.conf /etc/sysctl.conf_bak_$time
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward=0" >> /etc/sysctl.conf
sysctl -p  > /dev/null 2>&1


cp /etc/pam.d/system-auth /etc/pam.d/system-auth_bak_$time
cat > /etc/pam.d/system-auth << EOF
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth 		required 	  pam_tally2.so deny=3 unlock_time=300 even_deny_root root_unlock_time=10
auth        required      pam_env.so
auth        required      pam_faildelay.so delay=2000000
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type= minlen=16 ucredit=-1 lcredit=-1 ocredit=-1 dcredit=-1
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so
EOF

array=( "adm" "lp" "sync" "shutdown" "halt" "uucp" "operator" "games" "gopher" "nobody" "nfsnobody" )
for(( i=0;i<${#array[@]};i++)) do
userdel ${array[i]} 2>/dev/null;
done;

chattr +i /etc/passwd
chattr +i /etc/shadow
chattr +i /etc/group
chattr +i /etc/gshadow

touch /tmp/jixian.log
echo "基线加固完成" > /tmp/jixian.log
