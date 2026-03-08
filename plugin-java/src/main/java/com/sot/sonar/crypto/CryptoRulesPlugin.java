package com.sot.sonar.crypto;

import org.sonar.api.Plugin;

public class CryptoRulesPlugin implements Plugin {

    @Override
    public void define(Context context) {
        context.addExtension(CryptoRulesDefinition.class);
        // JavaExtensionRegistrar is a BeanDefinitionRegistryPostProcessor that registers
        // JavaCheckRegistrar after all plugins (including sonar-java) are loaded.
        context.addExtension(JavaExtensionRegistrar.class);
    }
}
