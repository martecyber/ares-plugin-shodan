package com.martecyber.plugins.shodan;

import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Turns one Shodan "host" JSON blob — either a direct {@code /shodan/host/{ip}} response, or one
 * synthesized from a {@code /shodan/host/search} match by {@link ShodanIntegrationActionHandler}
 * — into assets (mutating a shared {@link ParseResult} directly, same convention {@code
 * FortiReconAssetParser} uses) plus the raw CVE references found on it. Vulnerabilities are
 * deliberately NOT turned into {@link com.martecyber.ares.imports.ParsedDetection}s here — a
 * {@code ParsedDetection}'s severity/CVSS fields are set at construction time, and resolving them
 * means looking every CVE id up in Ares' own KB, which {@link ShodanIntegrationActionHandler} does
 * once in bulk across every target in a run rather than per-host — see {@link VulnRef}.
 *
 * <p>Response field names/shapes here match {@code Map<String,Object>} — the plain-Jackson-map
 * shape {@code ShodanClient} already returns (not a {@code JsonNode} tree) — same convention the
 * pre-existing, still-in-core {@code ShodanImportService} uses for the same API.
 */
public class ShodanHostParser {

    /** One CVE id Shodan reported, and which asset it's attributed to (the port-level SERVICE
     *  asset when Shodan scoped it to one banner, the IP-level asset otherwise). {@code raw} is
     *  the per-CVE sub-object Shodan sometimes includes (cvss/summary/references) when {@code
     *  vulns} is shaped as an object rather than a bare id list — {@code null} when not present;
     *  kept only as supplementary context, since Ares' own CVE KB (see {@link
     *  ShodanIntegrationActionHandler#attachDetections}) is the authoritative severity/CVSS
     *  source, not Shodan's own (frequently absent) copy. */
    public record VulnRef(String cveId, String assetIdentifier, Object raw) {}

    public List<VulnRef> parseHost(Map<String, Object> host, ParseResult result) {
        List<VulnRef> vulns = new ArrayList<>();
        String ip = str(host, "ip_str");
        if (ip == null) return vulns;

        String hostAssetId = "host-" + ip;
        String ifaceAssetId = "iface-" + ip;
        result.addAsset(new ParsedAsset(hostAssetId, AssetType.HOST));
        result.addAsset(new ParsedAsset(ifaceAssetId, AssetType.INTERFACE, Map.of("ip", ip)));
        result.addAsset(new ParsedAsset(ip, AssetType.IP));
        result.addLink(hostAssetId, ifaceAssetId, AssetLinkType.HOST_INTERFACE);
        result.addLink(ifaceAssetId, ip, AssetLinkType.INTERFACE_IP);

        for (String hostname : listOf(host, "hostnames")) {
            if (hostname == null || hostname.isBlank()) continue;
            result.addAsset(new ParsedAsset(hostname.toLowerCase().trim(), AssetType.DOMAIN));
        }
        for (String domain : listOf(host, "domains")) {
            if (domain == null || domain.isBlank()) continue;
            result.addAsset(new ParsedAsset(domain.toLowerCase().trim(), AssetType.DOMAIN));
        }

        // Host-level vulns — attributed to the IP itself, since nothing narrower is known.
        addVulnRefs(vulns, host.get("vulns"), ip);

        for (Object entryObj : listRaw(host, "data")) {
            if (!(entryObj instanceof Map<?, ?> entry)) continue;
            Number port = asNumber(entry.get("port"));
            if (port == null) continue;
            String transport = Objects.toString(entry.get("transport"), "tcp");
            // "ip:port/proto" — the SERVICE identifier shape every other target-resolution/tool
            // path in this codebase already expects (see TargetResolver.formatAssetForTarget),
            // not the bare "port/proto" the older, still-in-core ShodanImportService uses (which
            // collides across different hosts sharing a port — not reproduced here).
            String serviceId = ip + ":" + port.intValue() + "/" + transport;

            Map<String, Object> meta = new LinkedHashMap<>();
            putIfPresent(meta, "product", entry.get("product"));
            putIfPresent(meta, "version", entry.get("version"));
            putIfPresent(meta, "cpe", entry.get("cpe"));
            result.addAsset(new ParsedAsset(serviceId, AssetType.SERVICE, meta));
            result.addLink(ifaceAssetId, serviceId, AssetLinkType.INTERFACE_SERVICE);

            addVulnRefs(vulns, entry.get("vulns"), serviceId);
        }
        return vulns;
    }

    /** {@code vulnsRaw} is, depending on the endpoint/plan, either a bare list of CVE id strings
     *  or an object keyed by CVE id with a per-CVE detail sub-object as the value — unverified
     *  which shape a given tenant actually returns (same "confirm against a live tenant" caveat
     *  ares-plugin-fortirecon's own client carries), so both are handled defensively. */
    @SuppressWarnings("unchecked")
    private static void addVulnRefs(List<VulnRef> out, Object vulnsRaw, String assetIdentifier) {
        if (vulnsRaw instanceof List<?> list) {
            for (Object id : list) {
                if (id != null) out.add(new VulnRef(String.valueOf(id), assetIdentifier, null));
            }
        } else if (vulnsRaw instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (e.getKey() != null) out.add(new VulnRef(String.valueOf(e.getKey()), assetIdentifier, e.getValue()));
            }
        }
    }

    private static String str(Map<?, ?> m, String key) {
        Object v = m.get(key);
        return v == null ? null : v.toString();
    }

    @SuppressWarnings("unchecked")
    private static List<String> listOf(Map<?, ?> m, String key) {
        Object v = m.get(key);
        if (v instanceof List<?> l) return (List<String>) (List<?>) l;
        return List.of();
    }

    private static List<?> listRaw(Map<?, ?> m, String key) {
        Object v = m.get(key);
        return v instanceof List<?> l ? l : List.of();
    }

    private static Number asNumber(Object v) {
        return v instanceof Number n ? n : null;
    }

    private static void putIfPresent(Map<String, Object> m, String key, Object v) {
        if (v != null) m.put(key, v);
    }
}
