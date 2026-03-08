package com.sot.sonar.crypto;

import org.sonar.api.SonarRuntime;
import org.sonar.api.server.rule.RulesDefinition;
import org.sonarsource.analyzer.commons.RuleMetadataLoader;

public class CryptoRulesDefinition implements RulesDefinition {

    public static final String REPOSITORY_KEY = "crypto";
    static final String REPOSITORY_NAME = "Custom Crypto Rules";
    static final String RESOURCE_BASE_PATH = "org/sonar/l10n/java/rules/crypto";

    private final SonarRuntime sonarRuntime;

    public CryptoRulesDefinition(SonarRuntime sonarRuntime) {
        this.sonarRuntime = sonarRuntime;
    }

    @Override
    public void define(Context context) {
        NewRepository repository = context
            .createRepository(REPOSITORY_KEY, "java")
            .setName(REPOSITORY_NAME);

        new RuleMetadataLoader(RESOURCE_BASE_PATH, sonarRuntime)
            .addRulesByAnnotatedClass(repository, RulesList.getJavaChecks());

        repository.done();
    }
}
