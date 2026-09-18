package com.packetanalyzer.types;

import com.flowgate.policy.ThrottlePolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that all six demo applications are correctly classified by AppType.fromSni()
 * AND that the demo throttle-policy maps them to the required tiers.
 *
 * Both steps (classification + tier) must pass for each application —
 * this rules out config-only evidence and proves the full runtime chain.
 */
public class DemoAppTierMappingTest {

    private static ThrottlePolicy policy;

    @BeforeAll
    static void loadDemoPolicy() throws Exception {
        File f = new File("config/demo/throttle-policy-demo.txt");
        assertTrue(f.exists(), "Demo throttle policy file must exist");
        policy = ThrottlePolicy.loadFromFile(f.getPath());
    }

    // ── ESSENTIAL ──────────────────────────────────────────────────────────
    @Test
    void googlePay_classifiesAsGPAY_andIsESSENTIAL() {
        AppType app = AppType.fromSni("pay.google.com");
        assertEquals(AppType.GPAY, app, "pay.google.com must classify as GPAY, not shadowed by GOOGLE");
        assertEquals(ThrottlePolicy.Tier.ESSENTIAL, policy.getTier(app),
                "GPAY must be ESSENTIAL in demo policy");
    }

    @Test
    void whatsApp_classifiesAsWHATSAPP_andIsESSENTIAL() {
        AppType app = AppType.fromSni("whatsapp.com");
        assertEquals(AppType.WHATSAPP, app);
        assertEquals(ThrottlePolicy.Tier.ESSENTIAL, policy.getTier(app),
                "WHATSAPP must be ESSENTIAL in demo policy");
    }

    // ── STANDARD ───────────────────────────────────────────────────────────
    @Test
    void google_classifiesAsGOOGLE_andIsSTANDARD() {
        AppType app = AppType.fromSni("www.google.com");
        assertEquals(AppType.GOOGLE, app);
        assertEquals(ThrottlePolicy.Tier.STANDARD, policy.getTier(app),
                "GOOGLE must be STANDARD in demo policy");
    }

    @Test
    void gmail_classifiesAsGMAIL_andIsSTANDARD() {
        AppType app = AppType.fromSni("mail.google.com");
        assertEquals(AppType.GMAIL, app, "mail.google.com must classify as GMAIL, not shadowed by GOOGLE");
        assertEquals(ThrottlePolicy.Tier.STANDARD, policy.getTier(app),
                "GMAIL must be STANDARD in demo policy");
    }

    // ── ENTERTAINMENT ──────────────────────────────────────────────────────
    @Test
    void netflix_classifiesAsNETFLIX_andIsENTERTAINMENT() {
        AppType app = AppType.fromSni("www.netflix.com");
        assertEquals(AppType.NETFLIX, app);
        assertEquals(ThrottlePolicy.Tier.ENTERTAINMENT, policy.getTier(app),
                "NETFLIX must be ENTERTAINMENT in demo policy");
    }

    @Test
    void spotify_classifiesAsSPOTIFY_andIsENTERTAINMENT() {
        AppType app = AppType.fromSni("www.spotify.com");
        assertEquals(AppType.SPOTIFY, app);
        assertEquals(ThrottlePolicy.Tier.ENTERTAINMENT, policy.getTier(app),
                "SPOTIFY must be ENTERTAINMENT in demo policy");
    }
}
