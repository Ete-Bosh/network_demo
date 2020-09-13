import jpcap.*;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;

import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Date;

import static Util.MacAddrUtils.MacByteToString;

public class ARP {
    //当前默认打开的网卡
    public static NetworkInterface DEVICE = JpcapCaptor.getDeviceList()[6];
    //本机的IP
    public static String LOCALIP = "";
    //文件输出地址
    private static String ARP_FILEPATH = "./ARPlog.txt";
    private static String DEVICE_FILEPATH = "./DEVICElog.txt";
    /**
     遍历本电脑上所有的网卡
     */

    public static void GetAllDevices(){

        NetworkInterface[] devices = JpcapCaptor.getDeviceList();

        for (NetworkInterface n : devices){
            System.out.println();
            System.out.println();
            FileWriter writer = null;
            try {
                // 打开一个写文件器，构造函数中的第二个参数true表示以追加形式写文件
                writer = new FileWriter(DEVICE_FILEPATH, true);
                writer.write("网卡名称" + n.name + "     |     " + "描述："  + n.description + System.getProperty("line.separator"));
                writer.write("MAC地址：" + MacByteToString(n.mac_address) + System.getProperty("line.separator"));
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if(writer != null){
                        writer.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return;
    }



    /**
     * 先选择默认网卡
     */

    public static void GetLocalIPAndMAC() throws Exception{
        InetAddress inetAddress = InetAddress.getLocalHost();

        //获取本地IP
        String localName = inetAddress.getHostName();
        String localIP = inetAddress.getHostAddress();


        //根据网卡获取本机MAC地址
        byte[] mac = DEVICE.mac_address;

        LOCALIP = localIP;

        FileWriter writer = null;
        try {
            // 打开一个写文件器，构造函数中的第二个参数true表示以追加形式写文件
            writer = new FileWriter(DEVICE_FILEPATH, true);
            writer.write("---------获取本机信息-----------" + System.getProperty("line.separator"));
            writer.write("Local name：" + localName + System.getProperty("line.separator"));
            writer.write("Local IP：" + localIP + System.getProperty("line.separator"));
            writer.write("Local MAC：" + MacByteToString(mac) +  System.getProperty("line.separator"));
            writer.write("---------获取本机信息结束-----------" + System.getProperty("line.separator"));
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if(writer != null){
                    writer.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }



    /**
     * 传入IP，通过ARP广播，查找MAC地址
     */

    public static byte[] GetMacByIp(String ip) throws IOException {
        JpcapCaptor jc = JpcapCaptor.openDevice(DEVICE,2000,false,3000);
        JpcapSender sender = jc.getJpcapSenderInstance();
        InetAddress senderIP = InetAddress.getByName(DHCP.fpip);
        InetAddress receiverIP = InetAddress.getByName(ip);

        //构建ARP报文
        ARPPacket arp = new ARPPacket();
        arp.hardtype = ARPPacket.HARDTYPE_ETHER;
        arp.prototype = ARPPacket.PROTOTYPE_IP;
        arp.operation = ARPPacket.ARP_REQUEST;
        arp.hlen = 6; //物理地址长度 MAC
        arp.plen = 4; //协议地址长度 IPV4

        byte[] broadcast = new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};

        arp.sender_hardaddr = DEVICE.mac_address;
        arp.sender_protoaddr = senderIP.getAddress();
        arp.target_hardaddr = broadcast;
        arp.target_protoaddr = receiverIP.getAddress();

        jpcap.packet.EthernetPacket ether = new jpcap.packet.EthernetPacket();
        ether.frametype = jpcap.packet.EthernetPacket.ETHERTYPE_ARP;
        ether.src_mac = DEVICE.mac_address;
        ether.dst_mac = broadcast;
        arp.datalink = ether;
        {
            FileWriter writer = null;
            Date date = new Date();
            try {
                // 打开一个写文件器，构造函数中的第二个参数true表示以追加形式写文件
                writer = new FileWriter(ARP_FILEPATH, true);
                writer.write("------------------" + date.toString() + "------------------" + System.getProperty("line.separator"));
                writer.write("------------ARP---------------" + System.getProperty("line.separator"));
                writer.write("Opcode: " + arp.operation + System.getProperty("line.separator"));
                writer.write("Sender IP: " + InetAddress.getByAddress(arp.sender_protoaddr).getHostAddress() +  System.getProperty("line.separator"));
                writer.write("Sender MAC: " +MacByteToString(arp.sender_hardaddr) + System.getProperty("line.separator"));
                writer.write("target IP: " +InetAddress.getByAddress(arp.target_protoaddr).getHostAddress() + System.getProperty("line.separator"));
                writer.write("target MAC: " +MacByteToString(arp.target_hardaddr) + System.getProperty("line.separator"));
                writer.write("------------ARP---------------" + System.getProperty("line.separator"));
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if(writer != null){
                        writer.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        sender.sendPacket(arp);

        while(true)
        {
            Packet packet = jc.getPacket();
            if(packet instanceof ARPPacket)
            {
                ARPPacket arpp =(ARPPacket) packet;
                if(arpp == null)
                {
                    throw new IllegalArgumentException(senderIP+" is not a local address");
                }
                if(Arrays.equals(arpp.target_protoaddr,senderIP.getAddress()))
                {
                    FileWriter writer = null;
                    Date date = new Date();
                    try {
                        // 打开一个写文件器，构造函数中的第二个参数true表示以追加形式写文件
                        writer = new FileWriter(ARP_FILEPATH, true);
                        writer.write("------------------" + date.toString() + "------------------" + System.getProperty("line.separator"));
                        writer.write("------------ARP---------------" + System.getProperty("line.separator"));
                        writer.write("Opcode: " + arpp.operation + System.getProperty("line.separator"));
                        writer.write("Sender IP: " + InetAddress.getByAddress(arpp.sender_protoaddr).getHostAddress() +  System.getProperty("line.separator"));
                        writer.write("Sender MAC: " +MacByteToString(arpp.sender_hardaddr) + System.getProperty("line.separator"));
                        writer.write("target IP: " +InetAddress.getByAddress(arpp.target_protoaddr).getHostAddress() + System.getProperty("line.separator"));
                        writer.write("target MAC: " +MacByteToString(arpp.target_hardaddr) + System.getProperty("line.separator"));
                        writer.write("------------ARP---------------" + System.getProperty("line.separator"));
                    } catch (IOException e) {
                        e.printStackTrace();
                    } finally {
                        try {
                            if(writer != null){
                                writer.close();
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                    return arpp.sender_hardaddr;
                }

            }

        }
    }



    /*
    public static void main(String[] args) throws Exception {
        GetAllDevices();
        GetLocalIPAndMAC();
        String dstip = "192.168.1.1";
        GetMacByIp(dstip);
    }
    */
}

