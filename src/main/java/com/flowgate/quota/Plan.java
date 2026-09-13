package com.flowgate.quota;

/**
 * Immutable data model for a subscriber plan.
 * All byte values use -1 to denote "unlimited".
 */
public final class Plan {

    // Pre-defined plan limits
    public static final long BYTES_PER_GB = 1_073_741_824L;

    private final String name;
    private final long dailyQuotaBytes;          // -1 = unlimited
    private final long throttleThresholdBytes;   // Throttle kicks in here
    private final long hardDropThresholdBytes;   // Hard-drop kicks in here (e.g. 2x quota)
    private final boolean carryForwardEnabled;
    private final int offPeakStartHour;          // 24h clock, inclusive
    private final int offPeakEndHour;            // 24h clock, exclusive

    private Plan(Builder builder) {
        this.name                  = builder.name;
        this.dailyQuotaBytes       = builder.dailyQuotaBytes;
        this.throttleThresholdBytes = builder.throttleThresholdBytes;
        this.hardDropThresholdBytes = builder.hardDropThresholdBytes;
        this.carryForwardEnabled   = builder.carryForwardEnabled;
        this.offPeakStartHour      = builder.offPeakStartHour;
        this.offPeakEndHour        = builder.offPeakEndHour;
    }

    // ── Static factory methods ────────────────────────────────────────────────

    /** 1.5 GB/day. Throttles at 100%, hard-drops at 200%. Off-peak: 2AM–6AM. */
    public static Plan basic() {
        long quota = (long)(1.5 * BYTES_PER_GB);
        return new Builder("Basic")
                .dailyQuotaBytes(quota)
                .throttleThresholdBytes(quota)
                .hardDropThresholdBytes(quota * 2)
                .carryForwardEnabled(false)
                .offPeakHours(2, 6)
                .build();
    }

    /** 3 GB/day. Throttles at 100%. Carry-forward enabled. Off-peak: 2AM–6AM. */
    public static Plan standard() {
        long quota = 3L * BYTES_PER_GB;
        return new Builder("Standard")
                .dailyQuotaBytes(quota)
                .throttleThresholdBytes(quota)
                .hardDropThresholdBytes(quota * 2)
                .carryForwardEnabled(true)
                .offPeakHours(2, 6)
                .build();
    }

    /** Unlimited. Never throttled or dropped. */
    public static Plan premium() {
        return new Builder("Premium")
                .dailyQuotaBytes(-1)
                .throttleThresholdBytes(-1)
                .hardDropThresholdBytes(-1)
                .carryForwardEnabled(false)
                .offPeakHours(0, 0)
                .build();
    }

    /** 10 GB/day. No throttle but hard-drop at 200%. Carry-forward enabled. */
    public static Plan business() {
        long quota = 10L * BYTES_PER_GB;
        return new Builder("Business")
                .dailyQuotaBytes(quota)
                .throttleThresholdBytes(-1)
                .hardDropThresholdBytes(quota * 2)
                .carryForwardEnabled(true)
                .offPeakHours(0, 0)
                .build();
    }

    /** Small deterministic plan for FUP demonstration. */
    public static Plan demo() {
        return new Builder("Demo")
                .dailyQuotaBytes(2000)
                .throttleThresholdBytes(2000)
                .hardDropThresholdBytes(4000)
                .carryForwardEnabled(false)
                .offPeakHours(0, 0)
                .build();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    public boolean isUnlimited() { return dailyQuotaBytes == -1; }

    /**
     * Returns true if the given hour falls in the off-peak window.
     * Off-peak data is not counted against the daily quota.
     */
    public boolean isOffPeak(int hourOfDay) {
        if (offPeakStartHour == offPeakEndHour) return false;
        return hourOfDay >= offPeakStartHour && hourOfDay < offPeakEndHour;
    }

    // ── Getters ───────────────────────────────────────────────────────────────

    public String getName()                  { return name; }
    public long getDailyQuotaBytes()         { return dailyQuotaBytes; }
    public long getThrottleThresholdBytes()  { return throttleThresholdBytes; }
    public long getHardDropThresholdBytes()  { return hardDropThresholdBytes; }
    public boolean isCarryForwardEnabled()   { return carryForwardEnabled; }
    public int getOffPeakStartHour()         { return offPeakStartHour; }
    public int getOffPeakEndHour()           { return offPeakEndHour; }

    @Override
    public String toString() {
        return String.format("Plan{name='%s', quota=%s, offPeak=%d-%d}",
                name,
                isUnlimited() ? "UNLIMITED" : (dailyQuotaBytes / BYTES_PER_GB) + "GB",
                offPeakStartHour, offPeakEndHour);
    }

    // ── Builder ───────────────────────────────────────────────────────────────

    public static final class Builder {
        private final String name;
        private long dailyQuotaBytes       = -1;
        private long throttleThresholdBytes = -1;
        private long hardDropThresholdBytes = -1;
        private boolean carryForwardEnabled = false;
        private int offPeakStartHour        = 0;
        private int offPeakEndHour          = 0;

        public Builder(String name) { this.name = name; }

        public Builder dailyQuotaBytes(long v)        { this.dailyQuotaBytes = v; return this; }
        public Builder throttleThresholdBytes(long v)  { this.throttleThresholdBytes = v; return this; }
        public Builder hardDropThresholdBytes(long v)  { this.hardDropThresholdBytes = v; return this; }
        public Builder carryForwardEnabled(boolean v)  { this.carryForwardEnabled = v; return this; }
        public Builder offPeakHours(int start, int end){ this.offPeakStartHour = start; this.offPeakEndHour = end; return this; }

        public Plan build() { return new Plan(this); }
    }
}
