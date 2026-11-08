import org.local.xcpeguard.DomainRules;
import java.util.List;

public final class DomainRulesTest {
    private static void check(boolean test, String message) {
        if (!test) throw new AssertionError(message);
    }
    public static void main(String[] args) {
        List<String> list = DomainRules.parse(DomainRules.DEFAULT_DOMAINS);
        check(list.size() == 4, "four published Google domains");
        check(DomainRules.matches(list, "mqtt.szbboys.com"), "mqtt C2");
        check(DomainRules.matches(list, "ott.szbboys.com"), "OTA C2");
        check(DomainRules.matches(list, "stb12T.anyevonline.com"), "bootstrap subdomain");
        check(DomainRules.matches(list, "intermedia-arts.tv"), "fallback C2");
        check(DomainRules.matches(list, "YOKATVONLINE.COM."), "YokaTV fallback");
        check(!DomainRules.matches(list, "notanyevonline.com"), "strict suffix boundary");
        check(!DomainRules.matches(list, "github.com"), "never block shared GitHub");
        check(!DomainRules.matches(list, "google.com"), "do not block legitimate DNS");
        check(DomainRules.parse("*.szbboys.com\nszbboys.com").size() == 1, "wildcard canonicalization");
        try {
            DomainRules.parse("http://szbboys.com");
            throw new AssertionError("URL accepted instead of FQDN");
        } catch (IllegalArgumentException expected) {}
        System.out.println("Domain rules: all tests passed");
    }
}
