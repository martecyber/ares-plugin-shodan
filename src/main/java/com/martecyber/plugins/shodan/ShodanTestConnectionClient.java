package com.martecyber.plugins.shodan;

import com.martecyber.ares.integrations.tools.IntegrationClient;

import java.util.Map;

/** "Test connection" support for the {@code "shodan"} integration type — backed by this plugin's
 *  own {@link ShodanClient} (vendored in, see that class's own doc for why it isn't a shared
 *  {@code ares-sdk} facade). */
public class ShodanTestConnectionClient implements IntegrationClient {

    private final ShodanClient shodan;

    public ShodanTestConnectionClient(ShodanClient shodan) {
        this.shodan = shodan;
    }

    @Override
    public String supports() { return "shodan"; }

    @Override
    public void testConnection(String settingsJson, Map<String, String> credentials) throws Exception {
        String apiKey = credentials.get("apiKey");
        if (apiKey == null || apiKey.isBlank())
            throw new IllegalArgumentException("Shodan API key is missing");
        shodan.getApiInfo(apiKey);
    }
}
