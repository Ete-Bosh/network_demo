import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Date;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.EthernetPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.UDPPacket;
import org.dhcp4java.DHCPConstants;
import org.dhcp4java.DHCPPacket;

import static Util.MacAddrUtils.MacByteToString;

public class DHCP {
    public static String bytesToHexString(byte[] src){
        StringBuilder stringBuilder = new StringBuilder();
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }
    public static String fpip = "";
    public static String gateip = "";
    public static NetworkInterface DEVICE = JpcapCaptor.getDeviceList()[6];

    private static String DHCP_FILEPATH = "./DHCPlog.txt";

    public static void step1() throws IOException {
        JpcapCaptor jc = JpcapCaptor.openDevice(DEVICE, 65535, false, 3000);//打开网络设备
        jc.setFilter("udp",true);
        JpcapSender sender = jc.getJpcapSenderInstance();
        DHCPPacket discover = new DHCPPacket();
        discover.setOp(DHCPConstants.BOOTREQUEST);
        discover.setHtype(DHCPConstants.HTYPE_ETHER);
        discover.setHlen((byte) 6);
        discover.setHops((byte) 0);
        discover.setXid(435763);
        discover.setSecs((short) 10000);
        discover.setFlags((short) 0);
        discover.setChaddr(DEVICE.mac_address);
        discover.setDHCPMessageType(DHCPConstants.DHCPDISCOVER);


        InetAddress senderAddr = InetAddress.getByName("0.0.0.0");
        InetAddress receiverAddr = InetAddress.getByName("255.255.255.255");
        UDPPacket udpPacket = new UDPPacket(68,67);
        udpPacket.setIPv4Parameter(0,false,false,false,0,false,false,false,
                0,17235,100, IPPacket.IPPROTO_UDP,senderAddr,receiverAddr);

        udpPacket.data = discover.serialize();
        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_IP;
        ether.src_mac = DEVICE.mac_address;
        ether.dst_mac = new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};
        udpPacket.datalink = ether;
        sender.sendPacket(udpPacket);
        {
            FileWriter writer = null;
            Date date = new Date();
            try {
                // 打开一个写文件器，构造函数中的第二个参数true表示以追加形式写文件
                writer = new FileWriter(DHCP_FILEPATH, true);
                writer.write("------------------" + date.toString() + "------------------" + System.getProperty("line.separator"));
                writer.write("------------DHCP---------------" + System.getProperty("line.separator"));
                writer.write(discover.toString() + System.getProperty("line.separator"));
                writer.write("------------DHCP---------------" + System.getProperty("line.separator"));
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

        while(true)
        {
            Packet packet = jc.getPacket();
            if(packet instanceof UDPPacket)
            {
                UDPPacket udpp = (UDPPacket) packet;
                if(udpp.dst_port == 68)
                {
                    DHCPPacket dp = DHCPPacket.getPacket(udpp.data,0,udpp.data.length,false);
                    byte[] mmacc = {0,0,0,0,0,0};
                    System.arraycopy(dp.getChaddr(),0,mmacc,0,6);
                    if(Arrays.equals(mmacc,DEVICE.mac_address))
                    {
                        fpip = dp.getYiaddr().getHostAddress();
                        gateip = dp.getOptionAsInetAddr(DHCPConstants.DHO_DHCP_SERVER_IDENTIFIER).getHostAddress();
                        FileWriter writer = null;
                        Date date = new Date();
                        try {
                            // 打开一个写文件器，构造函数中的第二个参数true表示以追加形式写文件
                            writer = new FileWriter(DHCP_FILEPATH, true);
                            writer.write("------------------" + date.toString() + "------------------" + System.getProperty("line.separator"));
                            writer.write("------------DHCP---------------" + System.getProperty("line.separator"));
                            writer.write(dp.toString() + System.getProperty("line.separator"));
                            writer.write("------------DHCP---------------" + System.getProperty("line.separator"));
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
                        break;
                    }
                }
            }
        }
    }
    public static void step2() throws IOException {
        JpcapCaptor jc = JpcapCaptor.openDevice(DEVICE, 65535, false, 3000);//打开网络设备
        jc.setFilter("udp",true);
        JpcapSender sender = jc.getJpcapSenderInstance();
        DHCPPacket discover = new DHCPPacket();
        discover.setOp(DHCPConstants.BOOTREQUEST);
        discover.setHtype(DHCPConstants.HTYPE_ETHER);
        discover.setHlen((byte) 6);
        discover.setHops((byte) 0);
        discover.setXid(981010);
        discover.setSecs((short) 10000);
        discover.setFlags((short) 0);
        discover.setChaddr(DEVICE.mac_address);
        discover.setDHCPMessageType(DHCPConstants.DHCPREQUEST);
        discover.setOptionAsInetAddress(DHCPConstants.DHO_DHCP_SERVER_IDENTIFIER,gateip);
        discover.setOptionAsInetAddress(DHCPConstants.DHO_DHCP_REQUESTED_ADDRESS,fpip);


        InetAddress senderAddr = InetAddress.getByName("0.0.0.0");
        InetAddress receiverAddr = InetAddress.getByName("255.255.255.255");
        UDPPacket udpPacket = new UDPPacket(68,67);
        udpPacket.setIPv4Parameter(0,false,false,false,0,false,false,false,
                0,17235,100, IPPacket.IPPROTO_UDP,senderAddr,receiverAddr);

        udpPacket.data = discover.serialize();
        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_IP;
        ether.src_mac = DEVICE.mac_address;
        ether.dst_mac = new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};
        udpPacket.datalink = ether;
        sender.sendPacket(udpPacket);
        {
            FileWriter writer = null;
            Date date = new Date();
            try {
                // 打开一个写文件器，构造函数中的第二个参数true表示以追加形式写文件
                writer = new FileWriter(DHCP_FILEPATH, true);
                writer.write("------------------" + date.toString() + "------------------" + System.getProperty("line.separator"));
                writer.write("------------DHCP---------------" + System.getProperty("line.separator"));
                writer.write(discover.toString() + System.getProperty("line.separator"));
                writer.write("------------DHCP---------------" + System.getProperty("line.separator"));
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
        while(true)
        {
            Packet packet = jc.getPacket();
            if(packet instanceof UDPPacket)
            {
                UDPPacket udpp = (UDPPacket) packet;
                if(udpp.dst_port == 68)
                {
                    DHCPPacket dp = DHCPPacket.getPacket(udpp.data,0,udpp.data.length,false);
                    byte[] mmacc = {0,0,0,0,0,0};
                    System.arraycopy(dp.getChaddr(),0,mmacc,0,6);
                    if(Arrays.equals(mmacc,DEVICE.mac_address))
                    {
                        FileWriter writer = null;
                        Date date = new Date();
                        try {
                            // 打开一个写文件器，构造函数中的第二个参数true表示以追加形式写文件
                            writer = new FileWriter(DHCP_FILEPATH, true);
                            writer.write("------------------" + date.toString() + "------------------" + System.getProperty("line.separator"));
                            writer.write("------------DHCP---------------" + System.getProperty("line.separator"));
                            writer.write(dp.toString() + System.getProperty("line.separator"));
                            writer.write("------------DHCP---------------" + System.getProperty("line.separator"));
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
                        break;
                    }
                }
            }
        }
    }
    /*public static void main(String[] args) throws IOException {
        step1();
        step2();
    }
     */
}
