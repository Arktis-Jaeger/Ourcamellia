package org.ourcamellia.client;

import org.ourcamellia.common.Errors;

import java.io.IOException;

/** Client executable entry point. */
public final class ClientMain {

    public static void main(String[] args) {
        int code = run(args);
        System.exit(code);
    }

    static int run(String[] args) {
        try {
            CliSupport.Options options = CliSupport.parseArgs(args);
            org.ourcamellia.common.config.ClientConfig config = CliSupport.loadConfigOnly(options);
            String secondaryPassword = null;
            if (config.secondaryPasswordProtectHistory()) {
                secondaryPassword = resolveSecondaryPassword();
            }
            CliSupport.Launch launch = CliSupport.launch(options, secondaryPassword);
            String mode = options.mode() != null ? options.mode() : launch.config().mode();
            if (mode.equals("auto")) {
                mode = System.console() != null ? "observatory" : "old";
            }
            switch (mode) {
                case "old" -> new OldUi(launch.app(), System.in, System.out).run();
                case "observatory" -> {
                    if (!ObservatoryUi.supported()) {
                        System.err.println("observatory mode is not supported on this terminal; use --mode old");
                        return CliSupport.EXIT_USAGE;
                    }
                    new ObservatoryUi(launch.app()).run();
                }
                default -> {
                    System.err.println("unknown mode: " + mode);
                    return CliSupport.EXIT_USAGE;
                }
            }
            return CliSupport.EXIT_OK;
        } catch (Errors.Usage e) {
            System.err.println("usage error: " + e.getMessage());
            return CliSupport.EXIT_USAGE;
        } catch (Errors.OcException e) {
            System.err.println("error: " + e.getMessage());
            return CliSupport.EXIT_ERROR;
        } catch (IOException e) {
            System.err.println("terminal error: " + e.getMessage());
            return CliSupport.EXIT_ERROR;
        }
    }

    private static String resolveSecondaryPassword() {
        // Interactive: prompt. Non-interactive: environment or clear refusal.
        String env = System.getenv("OURCAMELLIA_SECONDARY_PASSWORD");
        if (System.console() == null) {
            if (env != null && !env.isBlank()) {
                return env;
            }
            throw new Errors.Usage("secondaryPasswordProtectHistory is enabled but stdin is not "
                    + "interactive; set OURCAMELLIA_SECONDARY_PASSWORD or disable protection in config");
        }
        System.err.print("secondary password (protects local history): ");
        char[] pw = System.console().readPassword();
        if (pw == null || pw.length == 0) {
            throw new Errors.Usage("a secondary password is required while protection is enabled");
        }
        return new String(pw);
    }
}
