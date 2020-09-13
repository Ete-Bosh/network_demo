import org.dhcp4java.DHCPPacket;

public class Demo {
    public static void main(String[] arg) throws Exception {
        ARP.GetAllDevices();
        System.out.println("---------GetAllDevices Finish----------");
        ARP.GetLocalIPAndMAC();;
        System.out.println("---------GetLocalIPAndMAC Finish----------");
        DHCP.step1();
        System.out.println("---------DHCPstep1 Finish----------");
        DHCP.step2();
        System.out.println("---------DHCPstep2 Finish----------");
        ARP.GetMacByIp(DHCP.gateip);
        System.out.println("---------GetMacByIp Finish----------");

    }
}
