package com.martecyber.plugins.shodan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.agents.tasks.TargetResolverFacade;
import com.martecyber.ares.imports.IngestFacade;
import com.martecyber.ares.imports.IngestResult;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import com.martecyber.ares.integrations.IntegrationFacade;
import com.martecyber.ares.integrations.IntegrationView;
import com.martecyber.ares.jobs.JobFacade;
import com.martecyber.ares.jobs.JobView;
import com.martecyber.ares.kb.cve.CveFacade;
import com.martecyber.ares.kb.cve.CveInfo;
import com.martecyber.ares.projects.ProjectFacade;
import com.martecyber.ares.workflows.integrations.IntegrationActionDescriptor;
import com.martecyber.ares.workflows.integrations.IntegrationActionHandler;
import com.martecyber.ares.workflows.integrations.IntegrationActionResult;
import com.martecyber.ares.workflows.integrations.IntegrationInstanceDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Wires Shodan asset + vulnerability discovery into {@code ACTION_INTEGRATION_CALL} under the
 * plain {@code "shodan"} integration type — the plugin's one Spring-managed bean (see {@code
 * com.martecyber.ares.plugins.PluginLoader}'s own doc comment).
 *
 * <p>Given a target — a domain/host/IP asset already known to the project, a project scope entry,
 * or free text of either kind (see {@link #resolveTargets}) — looks it up on Shodan (a direct host
 * lookup for something that looks like an IP; a {@code hostname:} search otherwise, since Shodan
 * has no single "everything for this domain" endpoint), creates/updates whatever assets it finds
 * (see {@link ShodanHostParser}), and creates a Detection for every CVE Shodan reports — with
 * severity/CVSS resolved against Ares' own CVE knowledge base ({@link CveFacade}) rather than
 * trusted from Shodan's own (frequently thin or absent) copy, since Shodan's {@code vulns} field is
 * often just a bare CVE id with no score attached at all.
 *
 * <p>The old {@code "shodan-task"} type (org-wide HOST_INFO/SEARCH, assets only, no detections,
 * its own core-resident tables) was removed 2026-09-26 — it was unreachable from the UI and fully
 * superseded by this plugin. This is now the only Shodan integration.
 */
public class ShodanIntegrationActionHandler implements IntegrationActionHandler {

    private static final Logger log = LoggerFactory.getLogger(ShodanIntegrationActionHandler.class);
    private static final String TYPE = "shodan";
    private static final String JOB_TYPE = "TOOL_SHODAN_ENRICH";
    private static final int SEARCH_LIMIT = 100;

    private final ShodanClient shodanClient;
    private final IntegrationFacade integrationFacade;
    private final TargetResolverFacade targetResolverFacade;
    private final IngestFacade ingestFacade;
    private final CveFacade cveFacade;
    private final JobFacade jobFacade;
    private final ProjectFacade projectFacade;
    private final ObjectMapper objectMapper;
    private final ShodanHostParser parser = new ShodanHostParser();

    public ShodanIntegrationActionHandler(ShodanClient shodanClient,
                                           IntegrationFacade integrationFacade,
                                           TargetResolverFacade targetResolverFacade,
                                           IngestFacade ingestFacade,
                                           CveFacade cveFacade,
                                           JobFacade jobFacade,
                                           ProjectFacade projectFacade,
                                           ObjectMapper objectMapper) {
        this.shodanClient = shodanClient;
        this.integrationFacade = integrationFacade;
        this.targetResolverFacade = targetResolverFacade;
        this.ingestFacade = ingestFacade;
        this.cveFacade = cveFacade;
        this.jobFacade = jobFacade;
        this.projectFacade = projectFacade;
        this.objectMapper = objectMapper;
    }

    @Override
    public String integrationType() { return TYPE; }

    @Override
    public String integrationTypeLabel() { return "Shodan"; }

    @Override
    public Set<String> supportedScopes() { return Set.of("project"); }

    @Override
    public List<IntegrationActionDescriptor> describeActions() {
        return List.of(new IntegrationActionDescriptor("ENRICH_ASSETS", "Enrich project assets"));
    }

    /** Same org-owned + granted merge as FortiRecon's own handler — see that class's identical
     *  method for the full rationale. */
    @Override
    public List<IntegrationInstanceDescriptor> listInstances(String scopeKind, Long scopeId) {
        Long orgId = organizationIdFor(scopeId);
        if (orgId == null) return List.of();
        var byOrg = integrationFacade.list(orgId, TYPE, null, 0, 200);
        var byGrant = integrationFacade.listForProject(scopeId, orgId).stream()
            .filter(i -> TYPE.equals(i.type()))
            .toList();
        return Stream.concat(byOrg.stream(), byGrant.stream())
            .collect(Collectors.toMap(IntegrationView::id, i -> i, (a, b) -> a, LinkedHashMap::new))
            .values().stream()
            .map(i -> new IntegrationInstanceDescriptor(i.id(), i.name()))
            .toList();
    }

    @Override
    public Long start(String actionCode, Long integrationInstanceId, String scopeKind, Long scopeId, Map<String, Object> params) {
        if (!"ENRICH_ASSETS".equals(actionCode)) {
            throw new IllegalArgumentException("Unsupported Shodan action: " + actionCode);
        }
        Long projectId = scopeId;
        Long orgId = organizationIdFor(projectId);
        if (orgId == null) {
            throw new IllegalArgumentException("Project " + projectId + " not found");
        }
        String targetSource = stringParam(params, "targetSource");
        List<String> manual = stringListParam(params, "targets");

        var job = jobFacade.create(JOB_TYPE, orgId, projectId, "{}");
        CompletableFuture.runAsync(() -> run(job.id(), integrationInstanceId, projectId, orgId, targetSource, manual));
        return job.id();
    }

    @Override
    public IntegrationActionResult checkStatus(Long refId) {
        JobView job;
        try {
            job = jobFacade.get(refId);
        } catch (Exception e) {
            return new IntegrationActionResult(IntegrationActionResult.FAILED, null, "Job " + refId + " no longer exists");
        }
        return switch (job.status()) {
            case "completed" -> new IntegrationActionResult(IntegrationActionResult.COMPLETED,
                job.result() != null ? job.result() : "{}", null);
            case "failed", "cancelled" -> new IntegrationActionResult(IntegrationActionResult.FAILED, null,
                job.error() != null ? job.error() : "Job " + job.status());
            default -> new IntegrationActionResult(IntegrationActionResult.RUNNING, null, null);
        };
    }

    // ── Work ──────────────────────────────────────────────────────────────────

    private void run(Long jobId, Long integrationId, Long projectId, Long orgId, String targetSource, List<String> manual) {
        setStatus(jobId, "running", 0);
        try {
            Map<String, String> creds = integrationFacade.loadCredentials(integrationId);
            String apiKey = creds.get("apiKey");
            if (apiKey == null || apiKey.isBlank()) {
                throw new IllegalStateException("Shodan API key not configured for integration " + integrationId);
            }

            List<String> resolved = resolveTargets(targetSource, manual, projectId);
            log.info("Shodan enrich start job={} integration={} project={} targetSource={} count={}",
                jobId, integrationId, projectId, targetSource, resolved.size());
            setStatus(jobId, null, 10);

            ParseResult combined = new ParseResult();
            List<ShodanHostParser.VulnRef> allVulns = new ArrayList<>();
            int processed = 0;
            List<String> errors = new ArrayList<>();
            for (String target : resolved) {
                try {
                    for (Map<String, Object> host : lookup(target, apiKey)) {
                        allVulns.addAll(parser.parseHost(host, combined));
                    }
                } catch (Exception e) {
                    log.warn("Shodan enrich: error for target={} job={} — {}", target, jobId, e.getMessage());
                    errors.add(target + ": " + e.getMessage());
                }
                processed++;
                setStatus(jobId, null, 10 + (resolved.isEmpty() ? 70 : (processed * 70 / resolved.size())));
            }

            int detectionsFound = attachDetections(combined, allVulns);
            setStatus(jobId, null, 85);

            IngestResult result = ingestFacade.ingest(projectId, orgId, TYPE, combined);
            setStatus(jobId, null, 98);

            completeJob(jobId, Map.of(
                "targetsProcessed", processed,
                "targetsTotal", resolved.size(),
                "vulnsFound", detectionsFound,
                "assetsCreated", result.assetsCreated(),
                "detectionsCreated", result.detectionsCreated(),
                "detectionsUpdated", result.detectionsUpdated(),
                "errors", errors.size()
            ));
            log.info("Shodan enrich done job={} targets={} assetsCreated={} detections={}/{}",
                jobId, resolved.size(), result.assetsCreated(), result.detectionsCreated(), result.detectionsUpdated());

        } catch (Exception e) {
            log.error("Shodan enrich failed job={}", jobId, e);
            safeFailJob(jobId, e.getMessage());
        }
    }

    /** A target that looks like a bare IPv4 address gets a direct host lookup (one result); a
     *  domain/hostname has no single-endpoint Shodan equivalent, so it goes through {@code
     *  hostname:} search instead, synthesizing a host-shaped record per match. */
    private List<Map<String, Object>> lookup(String target, String apiKey) throws Exception {
        if (looksLikeIp(target)) {
            return List.of(shodanClient.getHostInfo(target, apiKey));
        }
        Map<String, Object> searchResult = shodanClient.search("hostname:" + target, SEARCH_LIMIT, apiKey);
        return synthesizeFromSearch(searchResult);
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> synthesizeFromSearch(Map<String, Object> searchResult) {
        Object matchesRaw = searchResult.get("matches");
        if (!(matchesRaw instanceof List<?> matches)) return List.of();
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object m : matches) {
            if (!(m instanceof Map<?, ?> match)) continue;
            Map<String, Object> synthetic = new LinkedHashMap<>();
            putIfPresent(synthetic, "ip_str", match.get("ip_str"));
            putIfPresent(synthetic, "hostnames", match.get("hostnames"));
            putIfPresent(synthetic, "domains", match.get("domains"));
            putIfPresent(synthetic, "vulns", match.get("vulns"));

            Object port = match.get("port");
            if (port instanceof Number) {
                Map<String, Object> portEntry = new LinkedHashMap<>();
                portEntry.put("port", port);
                Object transport = match.get("transport");
                portEntry.put("transport", transport != null ? transport : "tcp");
                putIfPresent(portEntry, "product", match.get("product"));
                putIfPresent(portEntry, "version", match.get("version"));
                putIfPresent(portEntry, "cpe", match.get("cpe"));
                putIfPresent(portEntry, "vulns", match.get("vulns"));
                synthetic.put("data", List.of(portEntry));
            } else {
                synthetic.put("data", List.of());
            }
            if (synthetic.get("ip_str") != null) out.add(synthetic);
        }
        return out;
    }

    /** Resolves every CVE id collected across every target processed in this run in ONE bulk
     *  {@link CveFacade} query (not per-host — {@code vulns} can repeat the same CVE across
     *  many hosts in a search), then builds one {@link ParsedDetection} per distinct (CVE, asset)
     *  pair with severity/CVSS from Ares' own KB when known, "info"/no-CVSS otherwise — a CVE
     *  Shodan reports is still worth recording even before this instance's KB has synced it.
     *  Returns the number of distinct vulnerabilities attached, for the job's own summary. */
    private int attachDetections(ParseResult result, List<ShodanHostParser.VulnRef> vulns) {
        if (vulns.isEmpty()) return 0;

        Set<String> normalizedIds = vulns.stream().map(v -> normalizeCveId(v.cveId())).collect(Collectors.toSet());
        Map<String, CveInfo> byId = cveFacade.findByCveIds(normalizedIds).stream()
            .collect(Collectors.toMap(CveInfo::cveId, e -> e, (a, b) -> a));

        Set<String> seen = new HashSet<>();
        int count = 0;
        for (ShodanHostParser.VulnRef v : vulns) {
            String normalized = normalizeCveId(v.cveId());
            String dedupKey = normalized + "|" + v.assetIdentifier();
            if (!seen.add(dedupKey)) continue;
            count++;

            CveInfo entry = byId.get(normalized);
            String severity = entry != null && entry.severity() != null ? entry.severity().toLowerCase() : "info";
            String rawData = null;
            if (v.raw() != null) {
                try { rawData = objectMapper.writeValueAsString(v.raw()); } catch (Exception ignored) { /* best effort */ }
            }

            ParsedDetection pd = new ParsedDetection(normalized, severity, null, v.assetIdentifier(), normalized, rawData);
            if (entry != null) {
                if (entry.cvssScore() != null) pd.setCvssScore(BigDecimal.valueOf(entry.cvssScore()));
                if (entry.cvssVector() != null) pd.setCvssVector(entry.cvssVector());
                if (entry.cvssVersion() != null) pd.setCvssVersion("CVSS " + entry.cvssVersion());
            }
            result.addDetection(pd);
        }
        return count;
    }

    private static String normalizeCveId(String id) {
        String upper = id.toUpperCase();
        return upper.startsWith("CVE-") ? upper : "CVE-" + upper;
    }

    /** {@code manual}: explicit IPs/domains typed into the workflow node. {@code assets}: every
     *  IP/domain/host asset the project already knows about (see {@code TargetResolverFacade}'s
     *  {@code project_assets} selector). {@code scope} (the default): in-scope IP/domain scope
     *  entries — covers "a domain or IP, as an asset or as text" either way the config panel offers it. */
    private List<String> resolveTargets(String targetSource, List<String> manual, Long projectId) {
        if ("manual".equals(targetSource) && manual != null) {
            return manual.stream().filter(t -> t != null && !t.isBlank()).toList();
        }
        if ("assets".equals(targetSource)) {
            return targetResolverFacade.resolveTargets(projectId,
                Map.of("type", "project_assets", "assetTypes", List.of("ip", "domain", "host")));
        }
        return targetResolverFacade.resolveTargets(projectId,
            Map.of("type", "scope_entries", "kinds", List.of("ip", "domain")));
    }

    private static boolean looksLikeIp(String s) {
        return s.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    private Long organizationIdFor(Long projectId) {
        try {
            return projectFacade.getOrganizationId(projectId);
        } catch (Exception e) {
            return null;
        }
    }

    private static void putIfPresent(Map<String, Object> m, String key, Object v) {
        if (v != null) m.put(key, v);
    }

    private static String stringParam(Map<String, Object> params, String key) {
        Object v = params == null ? null : params.get(key);
        return v == null ? null : String.valueOf(v);
    }

    @SuppressWarnings("unchecked")
    private static List<String> stringListParam(Map<String, Object> params, String key) {
        Object v = params == null ? null : params.get(key);
        if (v instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object o : list) if (o != null) out.add(String.valueOf(o));
            return out;
        }
        if (v instanceof String s && !s.isBlank()) {
            List<String> out = new ArrayList<>();
            for (String t : s.split(",")) if (!t.isBlank()) out.add(t.trim());
            return out;
        }
        return List.of();
    }

    private void setStatus(Long jobId, String status, Integer progress) {
        try { jobFacade.update(jobId, status, progress, null, null); }
        catch (Exception e) { log.warn("job update failed: {}", e.getMessage()); }
    }

    private void completeJob(Long jobId, Map<String, Object> resultData) {
        try {
            String json = objectMapper.writeValueAsString(resultData);
            jobFacade.update(jobId, "completed", 100, json, null);
        } catch (Exception e) { log.warn("Could not complete job {}: {}", jobId, e.getMessage()); }
    }

    private void safeFailJob(Long jobId, String error) {
        try { jobFacade.update(jobId, "failed", null, null, error); }
        catch (Exception ignored) {}
    }
}
