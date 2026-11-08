import org.local.xcpeguard.StartupPolicy;

public final class StartupPolicyTest {
    private static void check(boolean actual, boolean expected, String name) {
        if (actual != expected) throw new AssertionError(name);
    }
    public static void main(String[] args) {
        String boot = "android.intent.action.BOOT_COMPLETED";
        String upgrade = "android.intent.action.MY_PACKAGE_REPLACED";
        check(StartupPolicy.mayAutoStart(false, boot), false, "OFF remains OFF after reboot");
        check(StartupPolicy.mayAutoStart(false, upgrade), false, "OFF remains OFF after update");
        check(StartupPolicy.mayAutoStart(true, boot), true, "ON resumes after boot");
        check(StartupPolicy.mayAutoStart(true, upgrade), true, "ON resumes after update");
        check(StartupPolicy.mayAutoStart(true, null), false, "no unknown action");
        check(StartupPolicy.mayAutoStart(true, "android.intent.action.SCREEN_ON"),
                false, "no screen wake persistence");
        check(StartupPolicy.mayAutoStart(true, "org.local.xcpeguard.STOP"),
                false, "no stop triggering restart");
        System.out.println("Startup policy tests: all passed");
    }
}
