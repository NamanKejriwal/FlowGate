package com.flowgate.util;

/**
 * Base exception for all FlowGate runtime errors.
 */
public class FlowGateException extends RuntimeException {
    public FlowGateException(String message) { super(message); }
    public FlowGateException(String message, Throwable cause) { super(message, cause); }

    /** Thrown when a config file is missing, malformed, or has invalid values. */
    public static class ConfigurationException extends FlowGateException {
        public ConfigurationException(String message) { super(message); }
        public ConfigurationException(String message, Throwable cause) { super(message, cause); }
    }

    /** Thrown when subscribers.txt cannot be parsed. */
    public static class SubscriberLoadException extends FlowGateException {
        public SubscriberLoadException(String message) { super(message); }
        public SubscriberLoadException(String message, Throwable cause) { super(message, cause); }
    }

    /** Thrown when the quota engine hits an unrecoverable internal error. */
    public static class QuotaEngineException extends FlowGateException {
        public QuotaEngineException(String message) { super(message); }
        public QuotaEngineException(String message, Throwable cause) { super(message, cause); }
    }

    /** Thrown when PCAP simulation parameters are invalid. */
    public static class SimulationException extends FlowGateException {
        public SimulationException(String message) { super(message); }
        public SimulationException(String message, Throwable cause) { super(message, cause); }
    }
}
