package elrasseo.syreao.zvpn.net;

import java.net.InetAddress;

public class NetQualityMonitor {
    public static int ping(String ip, int timeoutMs) {
        try {
            long start = System.nanoTime();
            boolean reachable = InetAddress.getByName(ip).isReachable(timeoutMs);
            long end = System.nanoTime();

            if (!reachable) return -1;

            return (int) ((end - start) / 1_000_000);  // ms
        } catch (Exception e) {
            return -1;
        }
    }
}
