package com.sot.sonar.crypto.rules;

import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;

class WeakHashAlgorithmRuleTest {

    private static final String SAMPLES_DIR = "src/test/resources/com/sot/sonar/crypto/rules/samples/";

    @Test
    void java_samples() {
        CheckVerifier.newVerifier()
            .onFile(SAMPLES_DIR + "WeakHashAlgorithmSamples.java")
            .withCheck(new WeakHashAlgorithmRule())
            .verifyIssues();
    }

    @Test
    void kotlin_samples() {
        CheckVerifier.newVerifier()
            .onFile(SAMPLES_DIR + "WeakHashAlgorithmSamples.kt")
            .withCheck(new WeakHashAlgorithmRule())
            .verifyIssues();
    }
}
