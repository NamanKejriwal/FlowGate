package com.flowgate.policy;

/** The current FUP enforcement state of a subscriber. */
public enum FupState {
    /** Under 80% quota usage. Full speed. */
    NORMAL,
    /** 80–100% quota usage. Warning issued, still full speed. */
    WARNING,
    /** 100%–200% quota usage. ASIT throttling active. */
    THROTTLE,
    /** Over 200% quota usage. Hard-drop active. */
    HARD_DROP
}
