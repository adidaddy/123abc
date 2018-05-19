#!/bin/bash
clear
#printf "Enter first IP address of the user: "
$read ip_address1
$printf "Enter second IP address of the user: "
$read ip_address2
printf "Enter Username: "
read username
printf "Enter Password: "
read passwd

echo "
Proxy Availability"
cat /etc/squid/proxy_counter

printf "number of IP address(s) to allot: "
read ip_num
#remove this line to allow clients to allow access
sed -i 's/http_access deny all//g' /etc/squid/squid.conf

used=$(cat /etc/squid/proxy_counter | grep Used | awk '{print $2}')
total=$(cat /etc/squid/proxy_counter | grep Total | awk '{print $2}')

index=$((used+1))

htpasswd -b /etc/squid/squid_passwd $username $passwd
echo "$username" > /etc/squid/group_user$index
chown squid:squid /etc/squid/group_user$index
chmod 600 /etc/squid/group_user$index

echo "acl authentication$index proxy_auth \"/etc/squid/group_user$index\""  >> /etc/squid/squid.conf

proxy=""
ip="$(curl ipinfo.io/ip)"
for ((i=1;i<=$ip_num;i++));
do
        pointer=$(($used+$i))
        if [ $pointer -gt $total ]; then
                break
        fi
        ipv6=$(head -n $pointer ~/proxy.txt | tail -1 | awk '{print $2}')
        port=$(head -n $pointer ~/proxy.txt | tail -1 | awk '{print $3}')
        echo "$ip $ipv6 $port $username $passwd" >> ~/users.txt
	echo "$ip:$port:$username:$passwd" >> ~/users_export.txt
        echo "http_access allow authentication$index proxy$pointer"  >> /etc/squid/squid.conf
done
echo "http_access deny all"  >> /etc/squid/squid.conf

echo "Used: $pointer
Total: $total" > /etc/squid/proxy_counter

echo "
Proxy Availability"
cat /etc/squid/proxy_counter

#restart squid service to apply settings
pkill -u squid
squid
squid -z;pkill -u squid;pkill -u squid; squid

#configure squid to start automatically when system is rebooted
#chkconfig squid on

echo "DONE"

