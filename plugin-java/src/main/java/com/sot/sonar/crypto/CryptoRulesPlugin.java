package com.sot.sonar.crypto;

import org.sonar.api.Plugin;

public class CryptoRulesPlugin implements Plugin {

    @Override
    public void define(Context context) {
        context.addExtension(CryptoRulesDefinition.class);
        context.addExtension(CryptoSensor.class);
        try {
            context.addExtension(
                Class.forName("com.sot.sonar.crypto.JavaCheckRegistrar",
                    true, getClass().getClassLoader()));
        } catch (ClassNotFoundException | NoClassDefFoundError ignored) {
            // sonar-java not available yet in this loading phase
        }
    }
}
