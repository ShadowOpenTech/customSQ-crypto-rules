package com.sot.sonar.crypto;

import org.sonar.api.Plugin;

public class CryptoRulesPlugin implements Plugin {

    @Override
    public void define(Context context) {
        context.addExtensions(
            CryptoRulesDefinition.class,
            JavaCheckRegistrar.class
        );
    }
}
