import java.util.HashMap;
import java.util.Map;

public class arp_simulation {
    private static Map<String, String> arpCache = new HashMap<>();
    private static Map<String, String> blocklist = new HashMap<>();
    private static final long INTERVAL = 30 * 1000; // 30 seconds

    public static void main(String[] args) {
        while (true) {
            try {
                String[] arpPackets = {
                        "ARP 192.168.1.1 is at 00:11:22:33:44:55",
                        "ARP 192.168.1.2 is at 00:AA:BB:CC:DD:EE",
                        "ARP 192.168.1.1 is at 00:11:22:33:44:66"
                };

                for (String arpPacket : arpPackets) {
                    if (isARPSpoofAttack(arpPacket)) {
                        System.out.println("Potential ARP Spoofing Attack Detected!");
                    }
                }

                arpCache.clear();
                Thread.sleep(INTERVAL);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private static boolean isARPSpoofAttack(String arpPacket) {
        String[] parts = arpPacket.split("\\s+");

        if (parts.length == 7 && parts[0].equals("ARP") && parts[2].equals("is") && parts[3].equals("at")) {
            String ipAddress = parts[1];
            String macAddress = parts[6];

            if (arpCache.containsKey(ipAddress)) {
                String cachedMacAddress = arpCache.get(ipAddress);
                if (!macAddress.equals(cachedMacAddress)) {
                    blocklist.put(ipAddress, "Blocked");
                    return true;
                }
            } else {
                arpCache.put(ipAddress, macAddress);
            }
        }

        return false;
    }
}
