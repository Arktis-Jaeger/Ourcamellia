package org.ourcamellia.core.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Product-wide logging with secret redaction. The redactor strips password-like
 * fields, tokens, and secondary-password material from any log record; application
 * code is additionally required never to log such values at all (defense in depth).
 * Message bodies are logged at FINE only and truncated.
 */
public final class RedactingLog {

    private static final String[] SENSITIVE_KEYS = {
            "password", "passwd", "secret", "token", "secondary", "privateKey", "box"
    };

    private RedactingLog() {}

    public static Logger get(String name) {
        return Logger.getLogger(name);
    }

    public static void configure(Path logDir, String level) {
        try {
            Files.createDirectories(logDir);
            Logger root = Logger.getLogger("");
            root.setLevel(Level.INFO);
            // Remove default console handler, add redacting file + console handlers.
            for (var h : root.getHandlers()) {
                root.removeHandler(h);
            }
            FileHandler file = new FileHandler(logDir.resolve("ourcamellia.log").toString(),
                    4 * 1024 * 1024, 3, true);
            file.setFormatter(new RedactingFormatter());
            file.setLevel(parseLevel(level));
            ConsoleHandler console = new ConsoleHandler();
            console.setFormatter(new RedactingFormatter());
            console.setLevel(parseLevel(level));
            root.addHandler(file);
            root.addHandler(console);
        } catch (IOException e) {
            // Logging setup failure must not kill the product.
            System.err.println("warning: log configuration failed: " + e.getMessage());
        }
    }

    private static Level parseLevel(String level) {
        return switch (level == null ? "info" : level.toLowerCase()) {
            case "off" -> Level.OFF;
            case "severe", "error" -> Level.SEVERE;
            case "warning", "warn" -> Level.WARNING;
            case "fine" -> Level.FINE;
            case "finer" -> Level.FINER;
            case "finest" -> Level.FINEST;
            default -> Level.INFO;
        };
    }

    /** Redacts known secret-bearing substrings and truncates long records. */
    public static String redact(String text) {
        if (text == null) {
            return "";
        }
        String out = text;
        for (String key : SENSITIVE_KEYS) {
            out = out.replaceAll("(?i)(\"?" + key + "\"?\\s*[:=]\\s*\")[^\"]*(\")", "$1***$2");
        }
        // BOT token pattern: 43-char base64url
        out = out.replaceAll("[A-Za-z0-9_-]{43,}", "***");
        return out.length() > 4096 ? out.substring(0, 4096) + "...(truncated)" : out;
    }

    private static final class RedactingFormatter extends Formatter {
        private static final DateTimeFormatter TS =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

        @Override
        public String format(LogRecord record) {
            String msg = redact(formatMessage(record));
            return String.format("%s %-7s [%s] %s%n",
                    TS.format(Instant.ofEpochMilli(record.getMillis())),
                    record.getLevel().getLocalizedName(),
                    record.getLoggerName(),
                    msg);
        }
    }
}
