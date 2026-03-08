package com.sot.sonar.crypto;

import com.sot.sonar.crypto.rules.InsecureRandomRule;
import com.sot.sonar.crypto.rules.WeakHashAlgorithmRule;
import com.sot.sonar.crypto.rules.WeakPasswordHashRule;
import org.sonar.plugins.java.api.JavaCheck;

import java.util.Arrays;
import java.util.List;

public final class RulesList {

    private RulesList() {
    }

    /** For RuleMetadataLoader — requires List<Class<?>> */
    public static List<Class<?>> getJavaChecks() {
        return Arrays.asList(
            WeakHashAlgorithmRule.class,
            InsecureRandomRule.class,
            WeakPasswordHashRule.class
        );
    }

    /** For CheckRegistrar — requires Iterable<Class<? extends JavaCheck>> */
    public static List<Class<? extends JavaCheck>> getCheckClasses() {
        return Arrays.asList(
            WeakHashAlgorithmRule.class,
            InsecureRandomRule.class,
            WeakPasswordHashRule.class
        );
    }
}
