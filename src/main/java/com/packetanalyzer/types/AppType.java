package com.packetanalyzer.types;

public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook/Meta"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static AppType fromDisplayName(String name) {
        for (AppType type : values()) {
            if (type.displayName.equalsIgnoreCase(name)) {
                return type;
            }
        }
        return UNKNOWN;
    }

    public static AppType fromSni(String sni) {
        if (sni == null || sni.isEmpty()) {
            return UNKNOWN;
        }
        
        String lowerSni = sni.toLowerCase();
        
        if (lowerSni.contains("google") || lowerSni.contains("gstatic") || lowerSni.contains("googleapis")) {
            return GOOGLE;
        } else if (lowerSni.contains("youtube") || lowerSni.contains("ytimg")) {
            return YOUTUBE;
        } else if (lowerSni.contains("facebook") || lowerSni.contains("fbcdn") || lowerSni.contains("fb.com") || lowerSni.contains("meta.com")) {
            return FACEBOOK;
        } else if (lowerSni.contains("twitter") || lowerSni.contains("twimg")) {
            return TWITTER;
        } else if (lowerSni.contains("instagram") || lowerSni.contains("cdninstagram")) {
            return INSTAGRAM;
        } else if (lowerSni.contains("netflix") || lowerSni.contains("nflxvideo") || lowerSni.contains("nflximg")) {
            return NETFLIX;
        } else if (lowerSni.contains("amazon") || lowerSni.contains("aws") || lowerSni.contains("cloudfront")) {
            return AMAZON;
        } else if (lowerSni.contains("microsoft") || lowerSni.contains("windows") || lowerSni.contains("azure") || lowerSni.contains("live.com")) {
            return MICROSOFT;
        } else if (lowerSni.contains("apple") || lowerSni.contains("icloud") || lowerSni.contains("mzstatic")) {
            return APPLE;
        } else if (lowerSni.contains("whatsapp") || lowerSni.contains("wa.me")) {
            return WHATSAPP;
        } else if (lowerSni.contains("telegram") || lowerSni.contains("t.me")) {
            return TELEGRAM;
        } else if (lowerSni.contains("tiktok") || lowerSni.contains("byteoversea")) {
            return TIKTOK;
        } else if (lowerSni.contains("spotify") || lowerSni.contains("scdn")) {
            return SPOTIFY;
        } else if (lowerSni.contains("zoom.us") || lowerSni.contains("zoom.com")) {
            return ZOOM;
        } else if (lowerSni.contains("discord") || lowerSni.contains("discordapp")) {
            return DISCORD;
        } else if (lowerSni.contains("github") || lowerSni.contains("githubusercontent")) {
            return GITHUB;
        } else if (lowerSni.contains("cloudflare")) {
            return CLOUDFLARE;
        }
        
        return HTTPS;
    }
}
