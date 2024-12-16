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

    @Test
    public void iw271Test() {
        final String content = "[[$on.constructor('alert(1)')()]]";
        final String resContent = XSSUtils.stripXSS(content);
        System.out.println(resContent);
        assertSanitizedDoesNotContain(resContent, content);

        final String payload = "{\"title\":\"test xss\",\"pages\":[{\"title\":\"Page d'accueil\",\"titleLink\":\"pagedaccueil\",\"href\":\"/pages#/website/85c51e81-b7b9-4fff-8d46-217e9e040263/pagedaccueil\",\"rows\":[{\"cells\":[{\"width\":3,\"index\":0,\"media\":{\"source\":{\"template\":\"navigation\",\"application\":\"pages\",\"source\":{\"_id\":\"85c51e81-b7b9-4fff-8d46-217e9e040263\",\"landingPage\":\"pagedaccueil\"}},\"type\":\"sniplet\"},\"style\":{}},{\"width\":9,\"index\":1,\"media\":{\"source\":\"<h1 class=\\\"ng-scope\\\">Construisez votre page</h1>\\n" + //
                        "<ul class=\\\"ng-scope\\\">\\n" + //
                        "    <li>Vous pouvez entrer ici les informations que vous voulez : cliquez dans un encart de texte comme celui-ci pour en modifier le contenu.​</li>\\n" + //
                        "</ul>\\n" + //
                        "<div>​</div>\\n" + //
                        "<div>​</div>\\n" + //
                        "<div>​<span style=\\\"background-color: rgb(34, 39, 43); color: rgba(0, 0, 0, 0); font-family: sans-serif; font-size: 17.7833px;\\\">[[$on.constructor('alert(1)')()]]</span>\\n" + //
                        "    <br>\\n" + //
                        "</div>\\n" + //
                        "<ul class=\\\"ng-scope\\\">\\n" + //
                        "    <li>Utilisez le menu sur la droite de l'application pour glisser-déposer du contenu dans votre page.</li>\\n" + //
                        "</ul>\\n" + //
                        "<hr class=\\\"ng-scope\\\">\\n" + //
                        "<div class=\\\"row ng-scope\\\">\\n" + //
                        "    <video style=\\\"max-width: 70%; display: block; margin: auto\\\" controls=\\\"\\\" src=\\\"/pages/public/tutorial.mp4\\\"></video>\\n" + //
                        "</div>\\n" + //
                        "<hr class=\\\"ng-scope\\\">\\n" + //
                        "<h1 class=\\\"ng-scope\\\">Naviguez dans votre page</h1>\\n" + //
                        "<ul class=\\\"ng-scope\\\">\\n" + //
                        "    <li>La navigation de gauche sera complétée automatiquement au fur et à mesure que vous ajouterez des pages.​</li>\\n" + //
                        "    <li>Vous avez la possibilité de publier ou dé-publier votre page à tout moment de son édition afin d'en contrôler la visibilité.</li>\\n" + //
                        "</ul>\",\"type\":\"text\"},\"style\":{}}]}],\"published\":true,\"owner\":\"91c22b66-ba1b-4fde-a3fe-95219cc18d4a\"}],\"landingPage\":\"pagedaccueil\",\"referencedResources\":{\"pages\":[]},\"visibility\":\"PRIVATE\"}";
        final String resPayload = XSSUtils.stripXSS(payload);
        System.out.println(resPayload);
        assertSanitizedDoesNotContain(resPayload, content);
    }

}
