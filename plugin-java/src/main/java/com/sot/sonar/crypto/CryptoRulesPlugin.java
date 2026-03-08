package com.sot.sonar.crypto;

import org.sonar.api.Plugin;

public class CryptoRulesPlugin implements Plugin {

    @Override
    public void define(Context context) {
        context.addExtension(CryptoRulesDefinition.class);
        try {
            // Use Class.forName to avoid eager resolution of CheckRegistrar
            // (sonar-java API) when the java plugin is not loaded in this context.
            context.addExtension(
                Class.forName("com.sot.sonar.crypto.JavaCheckRegistrar",
                    true, getClass().getClassLoader()));
        } catch (ClassNotFoundException | NoClassDefFoundError ignored) {
            // sonar-java not available in this context (e.g. scanner-side in SQ 26.x);
            // JavaCheckRegistrar will be registered when java plugin is present (server-side).
        }
    }
}
