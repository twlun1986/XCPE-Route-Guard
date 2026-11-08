package org.local.xcpeguard;

import java.util.Arrays;
import java.util.Locale;

/** Minimal IPv4 UDP/53 packet handling. No general traffic proxy. */
public final class DnsPacket {
    private DnsPacket() {}
    public static final String LOCAL_DNS = "198.18.0.1";

    public static final class Query {
        public final byte[] source;
        public final byte[] destination;
        public final int sourcePort;
        public final byte[] payload;
        public final String name;
        private Query(byte[] source, byte[] destination, int port, byte[] payload, String name) {
            this.source = source;
            this.destination = destination;
            this.sourcePort = port;
            this.payload = payload;
            this.name = name;
        }
    }

    /** Return null if this is not a complete IPv4 UDP DNS query to our local resolver. */
    public static Query decode(byte[] packet, int length) {
        if (length < 40 || (packet[0] & 0xf0) != 0x40) return null;
        int ihl = (packet[0] & 0x0f) * 4;
        if (ihl < 20 || ihl + 20 > length || (packet[9] & 0xff) != 17) return null;
        if ((u16(packet, 6) & 0x3fff) != 0) return null; // no fragments
        int total = u16(packet, 2);
        if (total < ihl + 20 || total > length) return null;
        if ((packet[16] & 255) != 198 || (packet[17] & 255) != 18 ||
                (packet[18] & 255) != 0 || (packet[19] & 255) != 1) return null;
        if (u16(packet, ihl + 2) != 53) return null;
        int udpLength = u16(packet, ihl + 4);
        if (udpLength < 20 || ihl + udpLength > total) return null;
        int dnsOffset = ihl + 8, dnsLength = udpLength - 8;
        byte[] dns = Arrays.copyOfRange(packet, dnsOffset, dnsOffset + dnsLength);
        if ((dns[2] & 0x80) != 0) return null;
        byte[] src = Arrays.copyOfRange(packet, 12, 16);
        byte[] dst = Arrays.copyOfRange(packet, 16, 20);
        return new Query(src, dst, u16(packet, ihl), dns, getName(dns));
    }

    /** Returns null for compressed/unusual questions, which are forwarded unchanged. */
    public static String getName(byte[] message) {
        if (message.length < 17 || u16(message, 4) != 1) return null;
        int position = 12;
        StringBuilder sb = new StringBuilder();
        while (position < message.length) {
            int n = message[position++] & 255;
            if (n == 0) {
                if (position + 4 > message.length) return null;
                return sb.toString().toLowerCase(Locale.ROOT);
            }
            if (n > 63 || position + n > message.length) return null;
            if (sb.length() > 0) sb.append('.');
            for (int i = 0; i < n; i++) {
                int c = message[position + i] & 255;
                if (c < 32 || c > 126) return null;
                sb.append((char) c);
            }
            position += n;
            if (sb.length() > 253) return null;
        }
        return null;
    }

    /** RFC1035 NXDOMAIN (3) or SERVFAIL (2); no cached or forged records. */
    public static byte[] errorReply(byte[] request, int rcode) {
        int questionEnd = 12;
        if (request.length < 17) return null;
        int pos = 12;
        while (pos < request.length) {
            int n = request[pos++] & 255;
            if (n == 0) {
                if (pos + 4 > request.length) return null;
                questionEnd = pos + 4;
                break;
            }
            if (n > 63 || pos + n > request.length) return null;
            pos += n;
        }
        if (questionEnd == 12) return null;
        byte[] reply = Arrays.copyOf(request, questionEnd);
        // QR=1, RD preserved, RA=1; clear TC/AD/CD and all response records.
        reply[2] = (byte) (0x80 | (request[2] & 1));
        reply[3] = (byte) (0x80 | (rcode & 0x0f));
        reply[4] = 0; reply[5] = 1;
        for (int i = 6; i < 12; i++) reply[i] = 0;
        return reply;
    }

    public static boolean validUpstreamResponse(byte[] request, byte[] reply) {
        return reply != null && reply.length >= 12 && request.length >= 12 &&
                reply[0] == request[0] && reply[1] == request[1] &&
                (reply[2] & 0x80) != 0;
    }

    public static byte[] wrapReply(Query request, byte[] dnsResponse) {
        int udpLen = 8 + dnsResponse.length;
        if (udpLen > 65515) throw new IllegalArgumentException("DNS reply too large");
        byte[] b = new byte[20 + udpLen];
        b[0] = 0x45;
        write16(b, 2, b.length);
        b[8] = 64;
        b[9] = 17;
        System.arraycopy(request.destination, 0, b, 12, 4);
        System.arraycopy(request.source, 0, b, 16, 4);
        write16(b, 20, 53);
        write16(b, 22, request.sourcePort);
        write16(b, 24, udpLen);
        System.arraycopy(dnsResponse, 0, b, 28, dnsResponse.length);
        write16(b, 10, checksum(b, 0, 20));
        long sum = 17 + udpLen;
        for (int i = 12; i < 20; i += 2) sum += u16(b, i);
        for (int i = 20; i < b.length; i += 2) {
            sum += (b[i] & 255) << 8;
            if (i + 1 < b.length) sum += b[i + 1] & 255;
        }
        while ((sum >>> 16) != 0) sum = (sum & 65535) + (sum >>> 16);
        int udpCheck = (int) (~sum) & 65535;
        write16(b, 26, udpCheck == 0 ? 65535 : udpCheck);
        return b;
    }

    private static int checksum(byte[] b, int start, int length) {
        long sum = 0;
        for (int i = start; i < start + length; i += 2) sum += u16(b, i);
        while ((sum >>> 16) != 0) sum = (sum & 65535) + (sum >>> 16);
        return (int) (~sum) & 65535;
    }
    private static int u16(byte[] b, int off) {
        return ((b[off] & 255) << 8) | (b[off + 1] & 255);
    }
    private static void write16(byte[] b, int off, int v) {
        b[off] = (byte) (v >>> 8);
        b[off + 1] = (byte) v;
    }
}
