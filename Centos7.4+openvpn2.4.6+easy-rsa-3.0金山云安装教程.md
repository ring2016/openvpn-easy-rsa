

# Centos7.4+openvpn2.4.6+easy-rsa3.0金山云安装配置教程

> 参考文献：https://www.jianshu.com/p/5ae8a5fddc1b

## 系统环境

* 金山云IO优化型主机
* 2核4G，20G SSD
* 弹性IP：110.43.33.177
* VPC-subnet：10.0.0.6
* OpenVPN：10.8.0.0

![image-20190123192137738](https://ws4.sinaimg.cn/large/006tNc79ly1fzgzfrlepfj31180hcdro.jpg)

​										本地ifconfig

---

## 安装OpenVPN, easy-rsa

```shell
yum install epel-release
lsb_release -a
yum install -y openssl openssl-devel lzo lzo-devel pam pam-devel automake pkgconfig makecache
yum install -y openvpn
yum install -y easy-rsa
#启动openvpn的用户
groupadd openvpn
useradd -g openvpn -M -s /sbin/nologin openvpn
```

```shell
mkdir /etc/openvpn/
cp -R /usr/share/easy-rsa/ /etc/openvpn/
cp /usr/share/doc/openvpn-2.4.6/sample/sample-config-files/server.conf /etc/openvpn/
cp -r /usr/share/doc/easy-rsa-3.0.3/vars.example /etc/openvpn/easy-rsa/3.0/vars
```

vim /etc/openvpn/server.conf  (配置文件如下：)

```shell
port 1194
proto tcp
dev tun
ca /etc/openvpn/easy-rsa/3.0/pki/ca.crt
cert /etc/openvpn/easy-rsa/3.0/pki/issued/wwwserver.crt
key /etc/openvpn/easy-rsa/3.0/pki/private/wwwserver.key
dh /etc/openvpn/easy-rsa/3.0/pki/dh.pem
tls-auth /etc/openvpn/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 198.18.254.60"
push "dhcp-option DNS 198.18.254.61"
keepalive 10 120
cipher AES-256-CBC
comp-lzo
max-clients 50
user openvpn
group openvpn
persist-key
persist-tun
status openvpn-status.log
log-append  openvpn.log
verb 3
mute 20
```

vim /etc/openvpn/easy-rsa/3.0/vars

修改第45、65、76、84-89、97、105、113、117、134、139、171、180、192行：

```shell
set_var EASYRSA                 "$PWD"
set_var EASYRSA_PKI             "$EASYRSA/pki"
set_var EASYRSA_DN      "cn_only"
set_var EASYRSA_REQ_COUNTRY     "CN"
set_var EASYRSA_REQ_PROVINCE    "BEIJING"
set_var EASYRSA_REQ_CITY        "BEIJING"
set_var EASYRSA_REQ_ORG         "OpenVPN CERTIFICATE AUTHORITY"
set_var EASYRSA_REQ_EMAIL       "110@qq.com"
set_var EASYRSA_REQ_OU          "OpenVPN EASY CA"
set_var EASYRSA_KEY_SIZE        2048
set_var EASYRSA_ALGO            rsa
set_var EASYRSA_CA_EXPIRE       7000
set_var EASYRSA_CERT_EXPIRE     3650
set_var EASYRSA_NS_SUPPORT      "no"
set_var EASYRSA_NS_COMMENT      "OpenVPN CERTIFICATE AUTHORITY"
set_var EASYRSA_EXT_DIR "$EASYRSA/x509-types"
set_var EASYRSA_SSL_CONF        "$EASYRSA/openssl-1.0.cnf"
set_var EASYRSA_DIGEST          "sha256"
```

## 初始化配置，创建CA，密码ca.com

```shell
cd /etc/openvpn/easy-rsa/3.0
./easyrsa init-pki
./easyrsa build-ca
设置ca密码（输入两次）：ca.com
```

![img](https://upload-images.jianshu.io/upload_images/9045881-0543e74114500fad.png?imageMogr2/auto-orient/)

```bash
./easyrsa gen-dh
openvpn --genkey --secret ta.key
cp -r ta.key /etc/openvpn/
```

## 创建服务端证书,生成请求,使用gen-req来生成req

```bash
./easyrsa  gen-req wwwserver
设置server密码（输入两次）：openserver.com
```

![img](https://upload-images.jianshu.io/upload_images/9045881-32c3084df4639501.png?imageMogr2/auto-orient/)

​							创建服务端证书、密码openserver.com

---

## 签发证书,签约服务端证书

```shell
./easyrsa sign-req server wwwserver
```

![img](https://upload-images.jianshu.io/upload_images/9045881-e4fdfbc8089d6d39.png?imageMogr2/auto-orient/)

​						输入yes签发证书，输入ca密码：ca.com

---

## 生成客户端用户

```shell
./easyrsa build-client-full www001
#注意：生成客户端用户的时候会提示设置密码，这里随便输入一个密码即可
#接着ca认证环节，需要输入ca密码`ca.com`
```

![img](https://upload-images.jianshu.io/upload_images/9045881-2acc5e4a50a84bc6.png?imageMogr2/auto-orient/)

​						生成客户端证书，并设置密码（客户端连接时用）

---

```
查看客户端证书存放路径：
ls -l /etc/openvpn/easy-rsa/3.0/pki/issued/www001.crt
-rw-------. 1 root root 4517 Apr 16 00:30 /etc/openvpn/easy-rsa/3.0/pki/issued/www001.crt

ls -l /etc/openvpn/easy-rsa/3.0/pki/private/www001.key
-rw-------. 1 root root 1834 Apr 16 00:30 /etc/openvpn/easy-rsa/3.0/pki/private/www001.key
```

## 配置防火墙

vim /etc/sysctl.conf

```shell
末尾加入
net.ipv4.ip_forward = 1
保存后执行：sysctl -p
```

Firewall运行状态

![img](https://upload-images.jianshu.io/upload_images/9045881-0c6a40e6e44ecb78.png?imageMogr2/auto-orient/)

命令运行：

```shell
firewall-cmd --state &&
firewall-cmd --zone=public --list-all &&
firewall-cmd --add-interface=eth0 --permanent &&
firewall-cmd --add-service=openvpn --permanent &&
firewall-cmd --add-port=1194/udp --permanent &&
firewall-cmd --add-port=22/tcp --permanent &&
firewall-cmd --add-source=10.8.0.0 --permanent &&
firewall-cmd --query-source=10.8.0.0 --permanent &&
firewall-cmd --add-masquerade --permanent &&
firewall-cmd --query-masquerade --permanent &&
firewall-cmd --reload
```

## 启动OpenVPN

```shell
systemctl start openvpn@server
启动时输入服务端证书密码：openserver.com

第一次启动的时候可能会提示，重新执行systemctl start openvpn@server输入密码即可
```

![img](https://upload-images.jianshu.io/upload_images/9045881-61ce4e46eaba0e90.png?imageMogr2/auto-orient/)

​							启动vpn，输入密码才能启动

---

![image-20190124001410481](/Users/ring.chen/Library/Application Support/typora-user-images/image-20190124001410481.png)

​						网络信息，至此openvpn服务器安装完成

---

## 客户端设置

> 客户端需要的证书：www001.crt、www001.key、ca.crt、ta.key

客户端配置文件ksyun.ovpn（ip换为openvpn服务器外网ip。ksyun.ovpn内容如下：

```shell
client
dev tun
proto tcp
remote 110.43.33.177 1194
resolv-retry infinite
nobind
# ;user nobody
# ;group nogroup
persist-key
persist-tun
remote-cert-tls server
comp-lzo
key-direction 1
verb 4
redirect-gateway
route-method exe
route-delay 2
status www001-status.log
<ca>
-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIJAKT6r66tpPCTMA0GCSqGSIb3DQEBCwUAMCgxJjAkBgNV
BAMMHU9wZW5WUE4gQ0VSVElGSUNBVEUgQVVUSE9SSVRZMB4XDTE5MDEyMzA4NTky
NVoXDTI5MDEyMDA4NTkyNVowKDEmMCQGA1UEAwwdT3BlblZQTiBDRVJUSUZJQ0FU
RSBBVVRIT1JJVFkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCeQFlg
sNHCPL1ojpT+FTkiB9PeeOI3Gbaz+eotdVhJxr5xoVxjfrsCWwR7aBd/LgMpn8n7
jISlLmIYeCyqD+2e3Hwc7RBqFNBM7Id231rEwoxW667e5I6V2QCtqf6cvTSVo+xH
9t5RoqOx7Gq2OGcG/4zJVNC8xEioJ+rew9RHbgEOdmY17fIN6narc5+YEvr8APyX
b46qq+oU78BU8ZYV+MpzdUvoEfrldOZHe/06m2w1f17vtH0B59NmU5w+67AKbqpT
oLR11kY5r8KBJYVgayyZksJaYDV3LQad5MEO3aSBQXr97Cdj8awdgkFJuTRvgMhV
usWtDgB1bCc/i+yfAgMBAAGjgZcwgZQwHQYDVR0OBBYEFGoL1My3iBtAhWFG0usQ
LEFiQNSjMFgGA1UdIwRRME+AFGoL1My3iBtAhWFG0usQLEFiQNSjoSykKjAoMSYw
JAYDVQQDDB1PcGVuVlBOIENFUlRJRklDQVRFIEFVVEhPUklUWYIJAKT6r66tpPCT
MAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQAQ
KnxktA+ZeOpVzMd7j7WKQuMnq9RUDhXu68wnj1WcyyqqKn9gcaNObnZYPx5K2qSL
Amf5aZCEMFf9dYWTjHhMGCN5nw2BNfoKABomeBbjHzt2gA3ldm6dYPJm5P2utCWj
erZ2jUJRZ9V0Q6SWToi3/BXQkUzMyN27sOFuqegAFr0EeEz7BXhf38I+IYIXKJcN
JDh2gvDwfhZgFpEm0REABLFAemLFY73GBKEsN6K3Ti/ZvjQDDr8HRVfKt8A72Alm
6aKEMAN2O9xL+t8oe2nPI7zIy0E1+wk2W2US63KTtPcoh71GlT7PQ7rreQhsC+S2
rhi5ivKm7miO3WhMrZdL
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            bd:0f:fb:3d:c5:ec:57:94:21:fa:f4:e6:71:a6:f1:1b
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=OpenVPN CERTIFICATE AUTHORITY
        Validity
            Not Before: Jan 23 09:24:26 2019 GMT
            Not After : Jan 20 09:24:26 2029 GMT
        Subject: CN=www001
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:f1:6f:0e:d7:24:49:c0:10:dc:af:a0:88:ad:eb:
                    3b:22:06:fb:f1:10:64:e4:0f:08:43:95:f4:79:97:
                    c1:b6:87:8a:b2:43:da:ba:6b:d5:c0:0b:1d:94:e9:
                    71:ce:65:98:9d:3a:56:19:dc:88:eb:f7:0c:bb:75:
                    5c:be:98:f5:dc:9e:1c:12:a2:91:c7:ce:f0:fb:14:
                    c0:01:34:34:cb:65:09:50:af:f6:35:f1:78:fa:91:
                    7c:99:6c:de:91:46:36:be:d9:5a:a2:18:ed:69:dc:
                    f4:9d:61:26:0d:ee:22:ee:65:57:0c:9f:a8:31:ae:
                    61:c5:7d:9f:6f:96:a5:8b:bf:34:5a:b5:85:27:ac:
                    3e:72:f6:71:14:43:fa:33:dd:8e:1d:09:f8:52:59:
                    da:58:3f:dc:61:dd:d1:f7:af:31:ef:b5:45:53:39:
                    8d:68:2d:c3:18:60:16:30:d4:04:12:15:8d:29:1e:
                    59:53:06:d0:33:1c:19:08:82:8f:51:aa:77:25:71:
                    77:e8:79:2d:4d:bc:0c:bc:f4:35:81:3d:55:e7:69:
                    13:71:bc:10:06:aa:d9:11:73:5a:72:ed:19:af:64:
                    50:9c:1d:c9:17:0d:15:49:e6:cc:6d:be:8a:35:a0:
                    9c:13:3d:96:2e:4c:36:29:87:06:3a:af:94:11:3b:
                    35:87
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                89:3B:06:0F:64:1C:55:3E:70:22:C5:9A:C5:50:BF:38:11:00:25:B8
            X509v3 Authority Key Identifier: 
                keyid:6A:0B:D4:CC:B7:88:1B:40:85:61:46:D2:EB:10:2C:41:62:40:D4:A3
                DirName:/CN=OpenVPN CERTIFICATE AUTHORITY
                serial:A4:FA:AF:AE:AD:A4:F0:93

            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: 
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
         48:a2:cd:a5:c7:60:2a:96:aa:34:67:59:ba:4c:b9:3e:b9:76:
         a4:b7:00:a8:e9:ff:8a:05:c3:56:0f:90:13:68:2e:be:0b:03:
         85:09:e0:1f:ca:4f:c1:c5:0b:ca:bf:0a:1d:d0:0d:c7:5a:67:
         59:e5:10:f0:35:9a:1c:91:8c:9b:34:fe:f3:e8:31:d6:29:5b:
         0b:4b:9c:54:0a:16:fd:f2:55:d0:80:4e:d5:76:4c:4a:d9:0d:
         6f:35:96:01:68:d7:d9:68:f1:63:f1:ca:0d:3a:e3:20:33:a7:
         e3:0a:a4:08:c4:7e:db:20:a7:35:6d:ae:b7:d0:8c:57:fa:c4:
         11:db:23:3e:bf:02:33:d5:af:c9:84:c4:d1:fc:63:0b:3d:36:
         0c:99:3d:40:c8:9c:5f:32:5d:78:76:c8:fb:68:59:5e:0b:df:
         93:9e:14:c6:0c:15:b4:59:13:93:68:c7:f0:40:c1:63:7b:61:
         1a:41:3f:80:ac:15:b2:02:7e:98:bf:97:02:c7:e7:c2:12:0a:
         ec:31:a4:f2:01:21:1b:c0:af:f7:30:cd:71:2f:17:5f:61:46:
         c9:12:55:ba:25:59:ea:63:65:6b:a2:e7:87:22:0f:3f:b8:df:
         78:39:9b:b6:8f:45:70:d4:7e:90:38:b2:ec:a6:19:c2:94:85:
         e4:7a:f6:10
-----BEGIN CERTIFICATE-----
MIIDbjCCAlagAwIBAgIRAL0P+z3F7FeUIfr05nGm8RswDQYJKoZIhvcNAQELBQAw
KDEmMCQGA1UEAwwdT3BlblZQTiBDRVJUSUZJQ0FURSBBVVRIT1JJVFkwHhcNMTkw
MTIzMDkyNDI2WhcNMjkwMTIwMDkyNDI2WjARMQ8wDQYDVQQDDAZ3d3cwMDEwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDxbw7XJEnAENyvoIit6zsiBvvx
EGTkDwhDlfR5l8G2h4qyQ9q6a9XACx2U6XHOZZidOlYZ3Ijr9wy7dVy+mPXcnhwS
opHHzvD7FMABNDTLZQlQr/Y18Xj6kXyZbN6RRja+2VqiGO1p3PSdYSYN7iLuZVcM
n6gxrmHFfZ9vlqWLvzRatYUnrD5y9nEUQ/oz3Y4dCfhSWdpYP9xh3dH3rzHvtUVT
OY1oLcMYYBYw1AQSFY0pHllTBtAzHBkIgo9RqnclcXfoeS1NvAy89DWBPVXnaRNx
vBAGqtkRc1py7RmvZFCcHckXDRVJ5sxtvoo1oJwTPZYuTDYphwY6r5QROzWHAgMB
AAGjgakwgaYwCQYDVR0TBAIwADAdBgNVHQ4EFgQUiTsGD2QcVT5wIsWaxVC/OBEA
JbgwWAYDVR0jBFEwT4AUagvUzLeIG0CFYUbS6xAsQWJA1KOhLKQqMCgxJjAkBgNV
BAMMHU9wZW5WUE4gQ0VSVElGSUNBVEUgQVVUSE9SSVRZggkApPqvrq2k8JMwEwYD
VR0lBAwwCgYIKwYBBQUHAwIwCwYDVR0PBAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IB
AQBIos2lx2Aqlqo0Z1m6TLk+uXaktwCo6f+KBcNWD5ATaC6+CwOFCeAfyk/BxQvK
vwod0A3HWmdZ5RDwNZockYybNP7z6DHWKVsLS5xUChb98lXQgE7VdkxK2Q1vNZYB
aNfZaPFj8coNOuMgM6fjCqQIxH7bIKc1ba630IxX+sQR2yM+vwIz1a/JhMTR/GML
PTYMmT1AyJxfMl14dsj7aFleC9+TnhTGDBW0WROTaMfwQMFje2EaQT+ArBWyAn6Y
v5cCx+fCEgrsMaTyASEbwK/3MM1xLxdfYUbJElW6JVnqY2VroueHIg8/uN94OZu2
j0Vw1H6QOLLsphnClIXkevYQ
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIA8dTo4V8rN0CAggA
MBQGCCqGSIb3DQMHBAiIxY7+8wUIPwSCBMgKhe/4CkWIUSfG7SzkZHYRptRytChu
lnfOH1cIQK6h+9+R1V0pPIOg2FS0BiCwgWd573JIY8y9cboSGqmUqWB9oTNPb9mp
PKI+IjW2LYJTWIveelolZxWxfhe03v83w7qcUnNrryafTRFRkxQtGvBQhjUqL6k3
V6ho7XGUA9hkpGZOJrvr2iPPGszCDznmPYcrOZRRwG1RHbKCxWPnnbqGc4EbSujQ
6DoPxYMnATheVPOJrNvz7LkEDRkO7yfMrsZxTI+WpZn4qOMVLwVa9ehFUv6sUwk8
/4MgP0UmOqzbFBG/j/ienyi5uNv/2EQnf/lI6ioLG98cjL9JtG9mxGzdg9WTH4IZ
8vUhCr73oidOn3ikxIwDBGZWZGjXh4W0BD+RVzNM9y9KGBGuf/YlA92zBzFKv8Kw
6nycfpsn07ioZ0rt3lkcnpRzMruR32psTLInZ0Qn0vns1cQ6lutzpp/p8I+ojxkV
P31XyC+jpy8iM9OrzdaRl+i5/88VDFN1CkkM27T16xWVxc7A0c4wWiiBAmliJ0ki
qz6OlZW093Ao70ZNNpZZieb/usvqroK0wanfMew9p5TFEPFGZx836wfS/YyxYPGV
unKguqLjc8qgdf7uu+uZU5lcqNSM8rKTh1UXHEAH+Kjb4o+1xeY6d/wrZwbEPUBb
FHl7o2ZXhfF7ioi0Gn6m9zrJNQxvINjcPV26P2FrUH6ap1aMsyPRpunApaZM7Cw2
/uBJl0n5Oxe89uZT5mdk1GAVDWcFtWSCekY4Z4yCtPRCQy+g0/+AQXvOcuhtSPY2
Is2PqBUXYB1tnJL12yzIZSop8VuPcMNKIOhGh0BrzVvqOhEXvFfVkQuJeYQzeVPP
x2+mCGZIckTaLW4cdVGyBaPzAdPLLw+9KZHHSLUA85yro4LobmylHLxzzxqtB0Jw
dCHS3JwIKDVGElG/g9gDRw2n/6QnuKtVDv19hG7IE9z0h/ouB3W3aCl71gqvRE48
uakm7bvztJToGhSJpsSpvrqyof0/HS/HfTsGrR9MmVhLpH52bOud23p0VdjKzcg9
zHn9V9D1PFqqQkE+t4Dgv4uPV1cO9Vkh9DMFt47nUJkS5R9aEKXuXyhuclX2YzSp
WfpCSpO7Tz5eSr0Q8j/uDsGlzvDLBHfUB5q0BdRMpM7abID0tEaCchRdahzRgZYA
DbOeNNKpyC0GdDNu+ApbME3UYLpxNYjs0O4yvO//IJEiztfDs2v1a5oH4oyefPm6
jLvwz1Dn+408Ofa0zbCqklyZqm6pJsi5ZhCEbtGV+KdOd9+75+zHv7it9py8B5cM
8w6Ia984FFetQIGwVD7ffd4Ps2a07aGxqCpw9cNzZO9bWXCTjFUiWfMKE7CmFqzy
1xJMHgaggVmFgOn8atWKeJ9BkFQZZEqrm+NUlqyJPEn51XsHQ96druVm/u5YK/BW
MD+UDlqLCMEyQ8DGG+q5yFGFO4k4qoSxzvYwRZzv48OKpFD9hPTyMqSfzZe2vj5m
4uCg4TbdaYrRZUJf/LTkam6bdJDwZjeA7ooSi/k4CtHa+62azWv+TwHYikqggjWP
Jl6cXzxY1p4gR7ycGbQsAxw6g+7FISrnsiu5Ht33rDCRaBC4vR7Ntjasf+wiZWJ5
OsI=
-----END ENCRYPTED PRIVATE KEY-----
</key>
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
a015412449a5d013203ec956785cb1c3
6e50a57621460b2ed147be59818dce1d
888e13e45811cb22d836ba88520904ab
2843a60488ab84eb9647806f13e64881
3a3126ae54c8a767187d47921a9d933c
4d036065fa5e47d970c9d7f86dcd916f
e480f12f9ba1152abd2dfae4a6a9ccf4
6fe08c16490439a5a758e8852fa3ac92
3c86316e899c286c0e593a734eebf4e6
9381c743e9d44161550bd35e16d2333a
3958a397a6efb76e4c204d738923b9a2
f594d8e4ee9e16c33c69d2e1e6596c88
8998eb4100128b26fea98fbaf06d33df
0ab7fbad46c9cad4747c1d299adcd286
eccb5588b4c2b40daa6d90acb0c40279
cd55ecf89969c6667394ba65563b310b
-----END OpenVPN Static key V1-----
</tls-auth>
```

