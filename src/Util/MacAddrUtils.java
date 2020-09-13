package Util;

public class MacAddrUtils {

    public static String MacByteToString(byte[] mac){

        StringBuffer sb = new StringBuffer();

        for (int i=0; i<mac.length; i++){
            if (i != 0){
                sb.append("-");
            }

            //mac[i] & 0xFF 是为了把byte转化为正整数
            String s = Integer.toHexString(mac[i] & 0xFF);
            sb.append(s.length()==1?0+s:s);
        }
        return sb.toString().toUpperCase();
    }
}
