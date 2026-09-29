package com.martecyber.plugins.shodan;

import com.martecyber.ares.plugins.PluginComponent;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/** Plain REST client for Shodan's public API — plugin-owned (not shared via {@code ares-sdk}):
 *  zero coupling to Ares's own state, and nothing else needs it, so it doesn't belong in a shared
 *  contract (see {@code ares-plugins/DEVELOPING.md}'s "what belongs in ares-sdk" rule — same
 *  reasoning as {@code ares-plugin-caido}'s own {@code CaidoGraphQLClient}). */
public class ShodanClient implements PluginComponent {

    private static final String BASE = "https://api.shodan.io";
    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE =
        new ParameterizedTypeReference<>() {};

    private final RestTemplate http;

    public ShodanClient(RestTemplateBuilder builder) {
        this.http = builder
            .setConnectTimeout(Duration.ofSeconds(10))
            .setReadTimeout(Duration.ofSeconds(60))
            .build();
    }

    /**
     * GET /shodan/host/{ip} — all available information for an IP.
     */
    public Map<String, Object> getHostInfo(String ip, String apiKey) {
        String url = BASE + "/shodan/host/" + encode(ip) + "?key=" + apiKey;
        return get(url);
    }

    /**
     * GET /shodan/host/search — text search across Shodan's database.
     */
    public Map<String, Object> search(String query, int limit, String apiKey) {
        String url = BASE + "/shodan/host/search?query=" + encode(query)
            + "&limit=" + limit + "&key=" + apiKey;
        return get(url);
    }

    /**
     * GET /api-info — verifies the API key and returns plan/credit info.
     */
    public Map<String, Object> getApiInfo(String apiKey) {
        String url = BASE + "/api-info?key=" + apiKey;
        return get(url);
    }

    private Map<String, Object> get(String url) {
        try {
            ResponseEntity<Map<String, Object>> resp =
                http.exchange(url, HttpMethod.GET, null, MAP_TYPE);
            return resp.getBody();
        } catch (HttpClientErrorException e) {
            String body = e.getResponseBodyAsString();
            throw new ShodanApiException(e.getStatusCode().value(), body);
        }
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    public static class ShodanApiException extends RuntimeException {
        private final int statusCode;
        public ShodanApiException(int statusCode, String body) {
            super("Shodan API error " + statusCode + ": " + body);
            this.statusCode = statusCode;
        }
        public int getStatusCode() { return statusCode; }
    }
}
