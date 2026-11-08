import org.local.xcpeguard.DnsPacket;
import org.local.xcpeguard.DomainRules;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public final class DnsPacketTest {
    private static void check(boolean cond, String message) {
        if (!cond) throw new AssertionError(message);
    }
    private static void put16(byte[] b, int offset, int n) {
        b[offset] = (byte) (n >>> 8);
        b[offset + 1] = (byte) n;
    }
    private static byte[] query(String host) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x12); out.write(0x34); out.write(0x01); out.write(0x00);
        out.write(0); out.write(1); // QDCOUNT
        for (int i = 0; i < 6; i++) out.write(0);
        for (String label : host.split("\\.")) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
            out.write(bytes.length);
            out.write(bytes, 0, bytes.length);
        }
        out.write(0);
        out.write(0); out.write(1); // A
        out.write(0); out.write(1); // IN
        return out.toByteArray();
    }
    private static byte[] ipv4Dns(String host) {
        byte[] dns = query(host);
        byte[] frame = new byte[20 + 8 + dns.length];
        frame[0] = 0x45;
        put16(frame, 2, frame.length);
        frame[8] = 64;
        frame[9] = 17; // UDP
        frame[12] = 10; frame[13] = 0; frame[14] = 0; frame[15] = 2;
        frame[16] = (byte)198; frame[17] = 18; frame[18] = 0; frame[19] = 1;
        put16(frame, 20, 44444);
        put16(frame, 22, 53);
        put16(frame, 24, 8 + dns.length);
        System.arraycopy(dns, 0, frame, 28, dns.length);
        return frame;
    }
    public static void main(String[] args) {
        byte[] frame = ipv4Dns("mqtt.szbboys.com");
        DnsPacket.Query parsed = DnsPacket.decode(frame, frame.length);
        check(parsed != null, "DNS packet must parse");
        check("mqtt.szbboys.com".equals(parsed.name), "DNS question name");
        check(DomainRules.matches(DomainRules.parse(DomainRules.DEFAULT_DOMAINS), parsed.name), "C2 match");
        byte[] nx = DnsPacket.errorReply(parsed.payload, 3);
        check(nx != null && (nx[3] & 15) == 3 && (nx[2] & 128) != 0, "NXDOMAIN flags");
        byte[] response = DnsPacket.wrapReply(parsed, nx);
        check((response[12] & 255) == 198 && (response[13] & 255) == 18 &&
                (response[16] & 255) == 10, "reply IP direction");
        check((response[22] & 255) == (44444 >>> 8), "reply UDP destination port");
        check(DnsPacket.validUpstreamResponse(parsed.payload, nx), "reply ID");
        byte[] tampered = nx.clone();
        tampered[0] = 0x44;
        check(!DnsPacket.validUpstreamResponse(parsed.payload, tampered), "forged DNS ID");
        byte[] wrongHost = ipv4Dns("github.com");
        check(DnsPacket.decode(wrongHost, wrongHost.length) != null, "ordinary DNS");
        wrongHost[16] = 1;
        check(DnsPacket.decode(wrongHost, wrongHost.length) == null, "only local DNS captured");
        System.out.println("DNS packet tests: all passed");
    }
}
