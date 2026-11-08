import org.local.xcpeguard.IpRules;

public final class RuleValidationTest {
    private static void invalid(String s) {
        try { IpRules.parse(s); throw new AssertionError("Accepted invalid: " + s); }
        catch (IllegalArgumentException expected) { }
    }
    public static void main(String[] args) {
        if (IpRules.parse(IpRules.DEFAULT_IPS).size() != 4) throw new AssertionError();
        if (IpRules.parse("219.134.163.210\n219.134.163.210").size() != 1)
            throw new AssertionError();
        invalid("0.0.0.0"); invalid("8.8.8.8/0"); invalid("10.0.0.1");
        invalid("192.168.1.1"); invalid("1.2.3.999"); invalid("1.2.3.004");
        invalid("xyz"); invalid("1.1.1.1:443"); invalid("::1"); invalid("");
        System.out.println("IP rule validation: all tests passed");
    }
}
