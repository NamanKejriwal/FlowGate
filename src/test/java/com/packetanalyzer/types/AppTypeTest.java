package com.packetanalyzer.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AppTypeTest {

    @Test
    public void testGoogleShadowing_Gpay() {
        // "pay.google.com" contains "google", but should map to GPAY
        assertEquals(AppType.GPAY, AppType.fromSni("pay.google.com"));
        assertEquals(AppType.GPAY, AppType.fromSni("gpay"));
    }

    @Test
    public void testGoogleShadowing_Gmail() {
        // "mail.google.com" contains "google", but should map to GMAIL
        assertEquals(AppType.GMAIL, AppType.fromSni("mail.google.com"));
        assertEquals(AppType.GMAIL, AppType.fromSni("gmail"));
    }

    @Test
    public void testStandardChecks() {
        assertEquals(AppType.GOOGLE, AppType.fromSni("www.google.com"));
        assertEquals(AppType.WHATSAPP, AppType.fromSni("whatsapp.com"));
        assertEquals(AppType.NETFLIX, AppType.fromSni("www.netflix.com"));
        assertEquals(AppType.SPOTIFY, AppType.fromSni("www.spotify.com"));
    }
}
