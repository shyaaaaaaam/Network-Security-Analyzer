import java.net.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

public class NetworkSecurityAnalyzer {
    int ddoskey[] = new int[] {1};
    int arpkey[] = new int[] {1};
    int mitmkey[] = new int[] {1};
    Map<Integer, String> devices;
    int openports[] = new int[10000];
    private static Map<String, Integer> packetCountMap = new HashMap<>();
    private static Map<String, String> blocklist = new HashMap<>();
    private static final int DDOS_PACKET_THRESHOLD = 5; //small packet count to simulate ddos
    String interface_name = "Wi-Fi";
    private static Map<String, String> arpCache = new HashMap<>();
    private static final int THREAD_COUNT = 75;

    private static volatile boolean stopDDOSDetection = false;
    private static volatile boolean stopARPDetection = false;
    private static volatile boolean stopMITMDetection = false;

    private static void discoverDevicesInRange(int start, int end) {
        try {
            InetAddress localhost = InetAddress.getLocalHost();
            byte[] ip = localhost.getAddress();

            for (int i = start; i <= end && i <= 254; i++) {
                ip[3] = (byte) i;
                InetAddress address = InetAddress.getByAddress(ip);
                if (address.isReachable(1000)) {
                    System.out.println(address + " machine is turned on and can be pinged");
                } else if (!address.getHostAddress().equals(address.getHostName())) {
                    System.out.println(address + " machine is known in a DNS lookup");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean isARPSpoofAttack(String arpPacket) {
        System.out.println("ARP Packet: " + arpPacket);
    
        String[] parts = arpPacket.split("\\s+");
        
        if (parts.length >= 13 && parts[6].equals("ARP")) {
            String ipAddress = parts[8];
            String macAddress = parts[12];
    
            if (arpCache.containsKey(ipAddress)) {
                String cachedMacAddress = arpCache.get(ipAddress);
                if (!macAddress.equals(cachedMacAddress)) {
                    blocklist.put(ipAddress, "Blocked");
                    System.out.println("ARP Spoofing Attack Detected!");
                    return true;
                }
            } else {
                arpCache.put(ipAddress, macAddress);
            }
        }
    
        return false;
    }        

    private static boolean isDDoSAttack(String sourceIP) {
        String ssip = sourceIP.trim();

        if (blocklist.containsKey(ssip)) {
            return false;
        }

        int count = packetCountMap.getOrDefault(ssip, 0) + 1;
        packetCountMap.put(ssip, count);

        return count > DDOS_PACKET_THRESHOLD;
    }

    private static void blockIP(String sourceIP) throws IOException {
        blocklist.put(sourceIP, "Blocked");
        String command = "netsh advfirewall firewall add rule name=\"Block " + sourceIP + "\" dir=in interface=any action=block remoteip=" + sourceIP;

        Process process = Runtime.getRuntime().exec(command);
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            int x;
        }

        /*int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Failed to block IP. Exit code: " + exitCode);
        }*/
    }

    private static boolean isPortOpen(String ip, int port, int timeout) {
        try (Socket socket = new Socket()) {
            InetSocketAddress socketAddress = new InetSocketAddress(InetAddress.getByName(ip), port);
            socket.connect(socketAddress, timeout);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void PortScan() {
        String targetIp = "127.0.0.1";
        int timeout = 1000;
        int count = 0;
        for (int port = 1; port <= 500; port++) {//65535
            if (isPortOpen(targetIp, port, timeout)) {

                openports[count] = port;
                count++;
            }
        }
        System.out.println("Open Ports Found And Saved!");
    }

    private static boolean isMITMAttack(String arpPacket) {
        //format ARP 192.168.1.1 is at 00:11:22:33:44:55
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

    private static void performDNSLookup(InetAddress targetAddress) {
        System.out.println("Performing DNS Lookup...");
        String hostName = targetAddress.getHostName();
        //String canonicalHostName = targetAddress.getCanonicalHostName();

        System.out.println("Host Name: " + hostName);
        System.out.println("Canonical Host Name: " + localip());
    }

    public void startmitmdetection() {
        mitmkey[0] = 1;
        stopMITMDetection = false;
        new Thread(() -> {
            while (mitmkey[0] == 1 && !stopMITMDetection) {
                try {
                    Process process = Runtime.getRuntime().exec("tshark -i " + interface_name + " -Y arp");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.equals("") || line.equals(localip())){continue;}
                        if (isMITMAttack(line)) {
                            System.out.println("Man In The Middle Attack Detected!");
                        }
                    }

                    reader.close();
                    Thread.sleep(30 * 1000);
                } catch (IOException | InterruptedException e) {
                    int x;
                }
            }
        }).start();
    }

    public void stopmitmattack() {
        mitmkey[0] = 0;
        stopMITMDetection = true;
    }

    public static String localip() {
        try {
            InetAddress localHost = InetAddress.getLocalHost();
            return localHost.getHostAddress();

        } catch (UnknownHostException e) {
            e.printStackTrace();
            return "";
        }
    }

    public static void devicesinnetwork() {
        ExecutorService executorService = Executors.newFixedThreadPool(THREAD_COUNT);

        for (int i = 1; i <= 254; i += THREAD_COUNT) {
            int startRange = i;
            int endRange = i + THREAD_COUNT - 1;
            executorService.execute(() -> discoverDevicesInRange(startRange, endRange));
        }

        executorService.shutdown();
    }

    public void startddosdetection() {
        ddoskey[0] = 1;
        stopDDOSDetection = false;
        new Thread(() -> {
            while (ddoskey[0] == 1 && !stopDDOSDetection) {
                try {
                    packetCountMap.clear();
                    Process process = Runtime.getRuntime().exec("tshark -i " + interface_name + " -T fields -e ip.src");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        String sourceIP = line.trim();
                        if (sourceIP.equals("") || sourceIP.equals(localip())) {continue;}
                        if (isDDoSAttack(sourceIP)) {
                            System.out.println("Potential DDoS Attack Detected from " + sourceIP + "!");
                            blockIP(sourceIP);
                            System.out.flush();
                        }
                    }
                    reader.close();
                    Thread.sleep(30 * 1000);
                } catch (IOException | InterruptedException e) {
                    int x;
                }
            }
        }).start();
    }    

    public void stopddosdetection() {
        ddoskey[0] = 0;
        stopDDOSDetection = true;
    }

    public void startarpdetection() {
        arpkey[0] = 1;
        stopARPDetection = false;
        new Thread(() -> {
            while (arpkey[0] == 1 && !stopARPDetection) {
                try {
                    Process process = Runtime.getRuntime().exec("tshark -i " + interface_name + " -Y arp");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.equals("") || line.equals(localip())){continue;}
                        if (isARPSpoofAttack(line)) {
                            System.out.println("ARP Spoofing Attack Detected!");
                        }
                    }

                    reader.close();
                    Thread.sleep(30 * 1000);
                } catch (IOException | InterruptedException e) {
                    int x;
                }
            }
        }).start();
    }

    public void stoparpdetection() {
        arpkey[0] = 0;
        stopARPDetection = true;
    }

    public void dashboard() {
        Scanner scanner = new Scanner(System.in);
        String targetIp = "127.0.0.1";

        try {
            InetAddress targetAddress = InetAddress.getByName(targetIp);

            while (true) {
                System.out.println("Starting Network Security Analysis for: " + targetAddress.getHostAddress());
                System.out.println("-----------------------------------------------------");
                System.out.println("1 - Start DDOS Detection");
                System.out.println("2 - Stop DDOS Detection");
                System.out.println("3 - Start ARP Spoofing Detection");
                System.out.println("4 - Stop ARP Spoofing Detection");
                System.out.println("5 - Start MITM Detection");
                System.out.println("6 - Stop MITM Detection");
                System.out.println("7 - Open Port Scanner");
                System.out.println("8 - Active Devices In Network [Local IP]");
                System.out.println("9 - Perform DNSLookup");
                System.out.println("10 - Exit");

                System.out.print("> ");
                int n = scanner.nextInt();

                if (n == 1) {
                    System.out.println("DDOS Detection Has Begun!\nAny DDOS Attempts Will Be Reported...");
                    startddosdetection();
                } else if (n == 2) {
                    System.out.println("DDOS Detection Has Stopped!\nScanning For Packets Stopped...");
                    stopddosdetection();
                } else if (n == 3) {
                    System.out.println("ARP Detection Has Begun!\nAny ARP Spoofing Attempts Will Be Reported...");
                    startarpdetection();
                } else if (n == 4) {
                    System.out.println("ARP Detection Has Stopped!\nScanning For Packets Stopped...");
                    stoparpdetection();
                } else if (n == 5) {
                    System.out.println("Analyzing for MITM Attacks!\nAny MITM Attack Attempts Will Be Reported...");
                    startmitmdetection();
                } else if (n == 6) {
                    System.out.println("MITM Analyzing Has Stopped!\nScanning For Packets Stopped...");
                    stopmitmattack();
                } else if (n == 7) {
                    PortScan();
                    System.out.println("Open Ports In The Network Are: ");
                    for (int p : openports) {
                        if (p != 0) {
                            System.out.println(p);
                        }
                    }
                } else if (n == 8) {
                    devicesinnetwork();
                } else if (n == 9) {
                    performDNSLookup(targetAddress);
                } else if (n == 10) {
                    System.exit(0);
                } else {
                    System.out.println("Invalid Option! Please Retry!");
                }
            }

        } catch (UnknownHostException e) {
            System.err.println("Invalid IP address or hostname.");
        }
    }

    public static void main(String[] args) throws Exception {
        NetworkSecurityAnalyzer obj = new NetworkSecurityAnalyzer();
        obj.dashboard();
    }
}
