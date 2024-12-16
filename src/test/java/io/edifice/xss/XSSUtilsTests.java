package io.edifice.xss;


import static org.junit.Assert.assertEquals;
import static org.owasp.html.AntiSamyTest.assertSanitizedDoesNotContain;

import org.junit.Test;

public class XSSUtilsTests {

    @Test
    public void iw270Test() {
        final String content = "<style>@keyframes slidein {}</style><xss style=\"animation-duration:1s;animation-name:slidein;animation-iteration-count:2\" onanimationiteration=\"alert(1)\"></xss>";
        final String resContent = XSSUtils.stripXSS(content);
        System.out.println(resContent);
        assertSanitizedDoesNotContain(resContent, "onanimationiteration");

        final String payload = "{\"name\":\"<style>@keyframes slidein {}</style><xss style=\\\"animation-duration:1s;animation-name:slidein;animation-iteration-count:2\\\" onanimationiteration=\\\"alert(1)\\\"></xss>\"}";
        final String resPayload = XSSUtils.stripXSS(payload);
        System.out.println(resPayload);
        assertSanitizedDoesNotContain(resPayload, "onanimationiteration");
    }

}
