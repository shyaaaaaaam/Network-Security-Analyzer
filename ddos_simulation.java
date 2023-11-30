import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

public class ddos_simulation {

    private static Map<String, Integer> packetCountMap = new HashMap<>();
    private static Map<String, String> blocklist = new HashMap<>();
    private static final int DDOS_PACKET_THRESHOLD = 100;

    public static void main(String[] args) {
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                refreshAndCheckDDOS();
            }
        }, 0, 30 * 1000);
    }

    private static void refreshAndCheckDDOS() {
        packetCountMap.clear();

        String[] packetData = {
                "SourceIP:192.168.1.1, DestinationIP:10.0.0.1",
                "SourceIP:192.168.1.2, DestinationIP:10.0.0.1",
                "SourceIP:192.168.1.1, DestinationIP:10.0.0.1",
        };

        for (String packet : packetData) {
            if (isDDoSAttack(packet)) {
                String sourceIP = extractSourceIP(packet);
                System.out.println("Potential DDoS Attack Detected from " + sourceIP + "!");
                blockIP(sourceIP);
            }
        }

        System.out.println("Blocklisted IPs: " + blocklist.keySet());
    }

    private static boolean isDDoSAttack(String packet) {
        String sourceIP = extractSourceIP(packet);

        if (blocklist.containsKey(sourceIP)) {
            System.out.println("IP " + sourceIP + " is already blocklisted.");
            return false;
        }

        int count = packetCountMap.getOrDefault(sourceIP, 0) + 1;
        packetCountMap.put(sourceIP, count);

        return count > DDOS_PACKET_THRESHOLD;
    }

    private static void blockIP(String sourceIP) {
        blocklist.put(sourceIP, "Blocked");
    }

    private static String extractSourceIP(String packet) {
        String[] parts = packet.split(",");
        for (String part : parts) {
            if (part.trim().startsWith("SourceIP:")) {
                return part.trim().substring("SourceIP:".length());
            }
        }
        return "";
    }
}
