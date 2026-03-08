package com.sot.sonar.crypto;

import org.sonar.plugins.java.api.CheckRegistrar;

import java.util.Collections;

public class JavaCheckRegistrar implements CheckRegistrar {

    @Override
    public void register(RegistrarContext registrarContext) {
        registrarContext.registerClassesForRepository(
            CryptoRulesDefinition.REPOSITORY_KEY,
            RulesList.getCheckClasses(),
            Collections.emptyList()
        );
    }
}
