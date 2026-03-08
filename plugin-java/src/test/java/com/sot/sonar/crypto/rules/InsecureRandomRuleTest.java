package com.sot.sonar.crypto.rules;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;

class InsecureRandomRuleTest {

    private static final String SAMPLES_DIR = "src/test/resources/com/sot/sonar/crypto/rules/samples/";

    @Test
    void java_samples() {
        CheckVerifier.newVerifier()
            .onFile(SAMPLES_DIR + "InsecureRandomSamples.java")
            .withCheck(new InsecureRandomRule())
            .verifyIssues();
    }

    @Test
    @Disabled("Kotlin files require the sonar-kotlin plugin; Java CheckVerifier cannot parse .kt files")
    void kotlin_samples() {
        CheckVerifier.newVerifier()
            .onFile(SAMPLES_DIR + "InsecureRandomSamples.kt")
            .withCheck(new InsecureRandomRule())
            .verifyIssues();
    }
}
