package com.github.enokiy.springcloudgatewaydemo;

import org.bouncycastle.util.encoders.Base64Encoder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class TestDemo {
    @Test
    public void test() throws IOException {
        System.out.println(Base64.getEncoder().encodeToString(Runtime.getRuntime().exec(new String("whoami")).getInputStream().readAllBytes()));;
    }
    @Test
    public void test1() throws IOException {
        System.out.println(Base64.getEncoder().encodeToString(Files.readAllBytes(Paths.get("J:\\code\\cve_learning_record\\cve-2022-22947-springcloud-gateway\\target\\classes\\NettyMemShell.class"))));
    }
    @Test
    public void test2() throws IOException {
        System.out.println(Base64.getEncoder().encodeToString(Files.readAllBytes(Paths.get("J:\\code\\cve_learning_record\\cve-2022-22947-springcloud-gateway\\target\\classes\\SpringRequestMappingMemshell.class"))));
    }
}
