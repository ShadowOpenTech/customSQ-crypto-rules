package com.sot.sonar.crypto;

import org.sonar.api.Plugin;

public class CryptoRulesPlugin implements Plugin {

    @Override
    public void define(Context context) {
        context.addExtension(CryptoRulesDefinition.class);
        try {
            context.addExtension(JavaCheckRegistrar.class);
        } catch (NoClassDefFoundError ignored) {
            // sonar-java not loaded in this context; Java checks skipped
        }
    }
}
