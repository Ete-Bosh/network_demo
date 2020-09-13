# network_demo



## 简介

SEU17级计算机网络课程设计。实现发送**DHCP客户端**报文和**ARP**报文，解析报文并保存。

__注意__ ：此程序并不保证健壮性。



采用` Winpcap` + `Jpcap` + `DHCP4Java`+` Java`实现对数据包的发送和接受。

Jpcap可以发送传输层及以下的报文，用来实现ARP。

DHCP4Java 实现了DHCP报文的构建和解析，用其实现DHCP。



## ARP.java

### **静态变量**

```java
//选择接受发送的网卡，修改[]内数字为使用的网卡
public static NetworkInterface DEVICE = JpcapCaptor.getDeviceList()[6];
//本机的IP
public static String LOCALIP = "";
//文件输出地址
private static String ARP_FILEPATH = "./ARPlog.txt";
private static String DEVICE_FILEPATH = "./DEVICElog.txt";
```



### **方法**

**public static void *GetAllDevices*()**

``` 
显示所有设备列表，结果保存在DEVICElog.txt中
```



**public static void *GetLocalIPAndMAC*()**

```
显示当前主机的IP地址和MAC地址
```



**public static byte[] *GetMacByIp*(String ip) **

```
返回ARP查询的MAC地址.ARP请求和响应解析后的报文保存在ARPlog.txt中
```



## DHCP.java

### **静态变量**

```java
public static String fpip = ""; //DHCP服务器分配的ip
public static String gateip = ""; //网关的ip地址
public static NetworkInterface DEVICE = JpcapCaptor.getDeviceList()[6];  //选择接受发送的网卡，修改[]内数字为使用的网卡
private static String DHCP_FILEPATH = "./DHCPlog.txt";  //文件输出地址
```



### **方法**

**public static void step1()**

```
发送DHCP DISCOVER并接受 DHCP OFFER.解析后的报文保存在DHCPlog.txt中
```



**public static void step2()**

```
发送DHCP REQUEST并接受 DHCP ACK.解析后的报文保存在DHCPlog.txt中
```

---



 __具体使用方法见代码，推荐配合wireshark一同使用__

