package elrasseo.syreao.zvpn.util;

public class DataFormatter {
    public static String formatBytes(long bytes) {
        if (bytes < 1024)
            return bytes + " B";
        if (bytes < 1024 * 1024)
            return (bytes / 1024) + " KB";
        if (bytes < 1024 * 1024 * 1024)
            return (bytes / (1024 * 1024)) + " MB";
        return (bytes / (1024 * 1024 * 1024)) + " GB";
    }

    public static String formatSpeed(long bytesPerSecond) {
        if (bytesPerSecond < 1024)
            return bytesPerSecond + " B/s";
        if (bytesPerSecond < 1024 * 1024)
            return (bytesPerSecond / 1024) + " KB/s";
        return (bytesPerSecond / (1024 * 1024)) + " MB/s";
    }
}
