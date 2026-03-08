package com.sot.sonar.crypto;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;

/**
 * Registers {@code JavaCheckRegistrar} as a Spring bean after ALL plugins are loaded
 * (including the optional sonar-java language plugin). This deferred registration is
 * necessary in SonarQube 26.x where BUNDLED language plugins (java) are loaded in a
 * second phase, AFTER EXTERNAL plugins' {@code Plugin.define()} has already been called.
 *
 * <p>Without this class, referencing {@code JavaCheckRegistrar.class} in
 * {@code CryptoRulesPlugin.define()} fails with {@code NoClassDefFoundError} on
 * {@code CheckRegistrar} because sonar-java is not yet loaded.
 *
 * <p>Spring invokes {@link BeanDefinitionRegistryPostProcessor} implementations during
 * context refresh, BEFORE beans are instantiated — at which point java IS loaded and
 * {@code CheckRegistrar} is available in the plugin classloader.
 */
public class JavaExtensionRegistrar implements BeanDefinitionRegistryPostProcessor {

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        try {
            Class<?> jcr = Class.forName(
                    "com.sot.sonar.crypto.JavaCheckRegistrar",
                    true,
                    getClass().getClassLoader());
            registry.registerBeanDefinition("cryptoJavaCheckRegistrar", new RootBeanDefinition(jcr));
        } catch (ClassNotFoundException | NoClassDefFoundError ignored) {
            // sonar-java not in classloader; JavaCheckRegistrar not registered
        }
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        // no-op
    }
}
