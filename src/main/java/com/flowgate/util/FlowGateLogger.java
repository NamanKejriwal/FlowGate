package com.flowgate.util;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

public final class FlowGateLogger {
    public enum Level { DEBUG, INFO, WARN, ERROR }
    private static volatile Level minLevel = Level.INFO;
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");

    private FlowGateLogger() {} // Prevent instantiation

    public static void setLevel(Level level) {
        minLevel = level;
    }

    private static void log(Level level, String component, String message, Throwable t) {
        if (level.ordinal() < minLevel.ordinal()) return;
        
        String time = LocalTime.now().format(FORMATTER);
        String logLine = String.format("[%s] [%-5s] [%s] %s", time, level.name(), component, message);
        
        if (level == Level.ERROR) {
            System.err.println(logLine);
            if (t != null && minLevel == Level.DEBUG) {
                t.printStackTrace(System.err);
            }
        } else {
            System.out.println(logLine);
        }
    }

    public static void debug(String component, String message) { log(Level.DEBUG, component, message, null); }
    public static void info(String component, String message) { log(Level.INFO, component, message, null); }
    public static void warn(String component, String message) { log(Level.WARN, component, message, null); }
    public static void error(String component, String message, Throwable t) { log(Level.ERROR, component, message, t); }
    public static void error(String component, String message) { log(Level.ERROR, component, message, null); }
}
