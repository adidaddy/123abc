#!/bin/bash
clear
#update list of packages
yum update -y
yum -y install wget
yum install firewalld
systemctl enable firewalld
systemctl start firewalld
systemctl status firewalld
firewall-cmd --zone=public --add-port=3128-7800/tcp
#install squid proxy server
yum install net-tools httpd-tools openssl openssl-devel openldap openldap-devel pam-devel quota-devel time psmisc -y
yum -y groupinstall "Development Tools"

#Add ipv6 addresses
read -p "Enter IP range start address:" first
temp="${first::-3}"

cd /tmp
wget -4 http://www.squid-cache.org/Versions/v3/3.5/squid-3.5.25.tar.gz
tar -xzf squid-3.5.25.tar.gz
cd squid-3.5.25
./configure \
'--build=x86_64-redhat-linux-gnu' \
'--host=x86_64-redhat-linux-gnu' \
'--program-prefix=' \
'--prefix=/usr' \
'--exec-prefix=/usr' \
'--bindir=/usr/bin' \
'--sbindir=/usr/sbin' \
'--sysconfdir=/etc' \
'--datadir=/usr/share' \
'--includedir=/usr/include' \
'--libdir=/usr/lib64' \
'--libexecdir=/usr/libexec' \
'--sharedstatedir=/var/lib' \
'--mandir=/usr/share/man' \
'--infodir=/usr/share/info' \
'--disable-strict-error-checking' \
'--exec_prefix=/usr' \
'--libexecdir=/usr/lib64/squid' \
'--localstatedir=/var' \
'--datadir=/usr/share/squid' \
'--sysconfdir=/etc/squid' \
'--with-logdir=$(localstatedir)/log/squid' \
'--with-pidfile=$(localstatedir)/run/squid.pid' \
'--disable-dependency-tracking' \
'--enable-eui' \
'--enable-follow-x-forwarded-for' \
'--enable-auth' \
'--enable-auth-basic=DB,LDAP,MSNT-multi-domain,NCSA,NIS,PAM,POP3,RADIUS,SASL,SMB,SMB_LM,getpwnam' \
'--enable-auth-ntlm=smb_lm,fake' \
'--enable-auth-digest=file,LDAP,eDirectory' \
'--enable-auth-negotiate=kerberos' \
'--enable-external-acl-helpers=file_userip,LDAP_group,unix_group,wbinfo_group' \
'--enable-cache-digests' \
'--enable-cachemgr-hostname=localhost' \
'--enable-delay-pools' \
'--enable-epoll' \
'--enable-ident-lookups' \
'--enable-linux-netfilter' \
'--enable-removal-policies=heap,lru' \
'--enable-snmp' \
'--enable-ssl-crtd' \
'--enable-storeio=aufs,diskd,ufs' \
'--enable-wccpv2' \
'--enable-esi' \
'--with-aio' \
'--with-default-user=squid' \
'--with-dl' \
'--with-openssl' \
'--with-pthreads' \
'--disable-arch-native' \
'build_alias=x86_64-redhat-linux-gnu' \
'host_alias=x86_64-redhat-linux-gnu' \
'CFLAGS=-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches  -m64 -mtune=generic -fpie' \
'LDFLAGS=-Wl,-z,relro  -pie -Wl,-z,relro -Wl,-z,now' \
'CXXFLAGS=-DMAXTCPLISTENPORTS=5000 -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches   -m64 -mtune=generic -fpie' \
'PKG_CONFIG_PATH=:/usr/lib64/pkgconfig:/usr/share/pkgconfig'

make && make install

groupadd squid
useradd -gsquid squid
mkdir -p /var/cache/squid
chown -R squid:squid /var/cache/squid
mkdir -p /var/log/squid
chown -R squid:squid  /var/log/squid

declare -a chars=(0 1 2 3 4 5 6 7 8 9 'a' 'b' 'c' 'd' 'e' 'f')
declare -a ips_list

i=0
ethernet=$(route | grep '^default' | grep -o '[^ ]*$')
secondary_ips=""

/usr/sbin/service network restart

for l in "${chars[@]}"
do
        for k in "${chars[@]}"
        do
                for j in "${chars[@]}"
                do
                        ips_list[i]="$temp$l$k$j"
                        ipv6_address="$temp$l$k$j"

                        ip a a $ipv6_address/128 dev $ethernet
                        echo "Added IP Address: $ipv6_address"

                        i=$((i + 1))
                done
        done
done

echo "acl localnet src 10.0.0.0/8     # RFC1918 possible internal network
acl localnet src 172.16.0.0/12  # RFC1918 possible internal network
acl localnet src 192.168.0.0/16 # RFC1918 possible internal network
acl localnet src fc00::/7       # RFC 4193 local private network range
acl localnet src fe80::/10      # RFC 4291 link-local (directly plugged) machines
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow localnet
http_access allow localhost
coredump_dir /var/cache/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
cache_effective_user squid
cache_effective_group squid
cache_dir ufs /var/cache/squid 100 16 256
cache_access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
cache_store_log /var/log/squid/store.log
pid_filename /var/run/squid/squid.pid" > /etc/squid/squid.conf

#backup the original squid.conf file and restrict access to it for users
mv /etc/squid/squid.conf /etc/squid/squid.conf.original
chmod 400 /etc/squid/squid.conf.original

#create a new squid.conf file from original file without comments
grep -ve ^# -ve ^$ /etc/squid/squid.conf.original > /etc/squid/squid.conf

#remove this line to allow clients to allow access
sed -i 's/http_access deny all//g' /etc/squid/squid.conf
sed -i 's/http_port 3128//g' /etc/squid/squid.conf

#Get a number which squid will start using as port number
read -p "Enter port number(Press ENTER to use default:3128 or select one from range:1025-65535):" -e -i 3128 port

temp=1
startport=$port

ip="$(ifconfig | grep broadcast | awk '{print $2}')"

echo "" > ~/proxy_export.txt
echo "" > ~/proxy.txt
echo "" > ~/users_export.txt
echo "" > ~/users.txt

for i in "${ips_list[@]}"
do
        printf "\n" >> /etc/squid/squid.conf
        echo "http_port $port name=port$temp" >> /etc/squid/squid.conf
        echo "acl proxy$temp myportname port$temp" >> /etc/squid/squid.conf
        echo "acl ip$temp myip $i" >> /etc/squid/squid.conf
        echo "tcp_outgoing_address $i proxy$temp" >> /etc/squid/squid.conf
        echo "$ip $i $port" >> ~/proxy.txt
        echo "$ip:$port" >> ~/proxy_export.txt
        ports="$ports$port "
        port=$((port + 1))
        temp=$((temp + 1))
done

echo "Used: 0
Total: $(($temp - 1))" > /etc/squid/proxy_counter

echo "squid will be using following ports: $ports"
echo "Proxy List saved in  ~/proxy.txt"
sudo firewall-cmd --zone=public --add-port=$startport-$port/tcp
sudo firewall-cmd --zone=public --permanent --add-port=$startport-$port/tcp

#Configure squid to asks users for credentials#slightwash
echo "
forwarded_for off
request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
request_header_access All deny all

auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/squid_passwd

auth_param basic children 5
auth_param basic realm Squid proxy-caching web server
auth_param basic credentialsttl 8 hours"  >> /etc/squid/squid.conf

touch /etc/squid/squid_passwd
chown squid:squid /etc/squid/squid_passwd
chmod 600 /etc/squid/squid_passwd

sed -i 's/* - nofile 32384//g' /etc/security/limits.conf
echo "* - nofile 32384" >> /etc/security/limits.conf

#restart squid service to apply settings
pkill -u squid
#squid

#configure squid to start automatically when system is rebooted
#chkconfig squid on

echo "DONE"
exit
