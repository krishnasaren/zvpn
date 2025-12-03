package elrasseo.syreao.zvpn.util;

public class PingUtils {

    public static boolean ping(String host) {
        try {
            Process p = Runtime.getRuntime().exec("/system/bin/ping -c 1 -W 1 " + host);
            int status = p.waitFor();
            return status == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
