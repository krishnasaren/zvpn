package elrasseo.syreao.zvpn.util;

public class ConnectionTimer {

    private long startTime = 0;

    /** Start or restart the timer */
    public void start() {
        startTime = System.currentTimeMillis();
    }

    /** Reset timer to zero */
    public void reset() {
        startTime = 0;
    }

    /** Return formatted uptime: HH:MM:SS */
    public String getFormatted() {
        if (startTime == 0) {
            return "00:00:00";
        }

        long now = System.currentTimeMillis();
        long diff = now - startTime;

        long sec = (diff / 1000) % 60;
        long min = (diff / (1000 * 60)) % 60;
        long hr  = (diff / (1000 * 60 * 60));

        return String.format("%02d:%02d:%02d", hr, min, sec);
    }
}
