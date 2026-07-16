package com.security.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.security.burp.ai.AiClient;
import com.security.burp.ai.AiFieldDiscovery;
import com.security.burp.ai.AiTriage;
import com.security.burp.checks.active.BrokenAuthCheck;
import com.security.burp.checks.active.BrokenObjectAuthCheck;
import com.security.burp.checks.active.DeprecatedVersionProbeCheck;
import com.security.burp.checks.active.FunctionLevelAuthCheck;
import com.security.burp.checks.active.GraphQlCheck;
import com.security.burp.checks.active.InjectionCheck;
import com.security.burp.checks.active.MassAssignmentCheck;
import com.security.burp.checks.active.MethodFuzzingCheck;
import com.security.burp.checks.active.ParameterPollutionCheck;
import com.security.burp.checks.active.SsrfCheck;
import com.security.burp.checks.passive.BusinessFlowCheck;
import com.security.burp.checks.passive.ExcessiveDataExposureCheck;
import com.security.burp.checks.passive.InventoryManagementCheck;
import com.security.burp.checks.passive.ResourceConsumptionCheck;
import com.security.burp.checks.passive.SecurityMisconfigCheck;
import com.security.burp.checks.passive.UnsafeApiConsumptionCheck;
import com.security.burp.scanner.EndpointRegistry;
import com.security.burp.ui.ScannerTab;

import javax.swing.SwingUtilities;
import java.util.Set;

/**
 * Extension entry point.
 *
 * <p>Responsibilities are intentionally narrow:
 * <ul>
 *   <li>declare the {@link EnhancedCapability#AI_FEATURES} capability so
 *       Burp grants {@code api.ai()} access;</li>
 *   <li>construct shared collaborators (registry, AI client/triage/field
 *       discovery);</li>
 *   <li>register each scan check individually with its appropriate
 *       {@link ScanCheckType};</li>
 *   <li>register the UI tab (Professional / Community only);</li>
 *   <li>register an unloading handler that releases all resources.</li>
 * </ul>
 *
 * <p>All other behaviour lives in collaborators.
 */
public final class BurpExtender implements BurpExtension {

    private static final String EXTENSION_NAME = "OWASP API Security Top 10 Scanner";

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        // Required for api.ai().isEnabled() to return true.
        return Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        BurpSuiteEdition edition = api.burpSuite().version().edition();
        // The DAST edition runs headless and ships no UI surface; skip the
        // suite tab in that case. Naming follows the current product line —
        // the Montoya enum constant is still ENTERPRISE_EDITION for backward
        // compatibility.
        boolean isDast = edition == BurpSuiteEdition.ENTERPRISE_EDITION;

        EndpointRegistry endpoints = new EndpointRegistry();
        AiClient aiClient = new AiClient(api);
        AiTriage triage = new AiTriage(api, aiClient);
        AiFieldDiscovery fieldDiscovery = new AiFieldDiscovery(api, aiClient);

        registerScanChecks(api, endpoints, triage, fieldDiscovery);

        ScannerTab tab = isDast ? null : registerUiTab(api, endpoints);
        registerUnloadingHandler(api, aiClient, endpoints, tab);

        logBanner(api, edition, aiClient.isAvailable());
    }

    // ---- Scan-check registration -------------------------------------------

    private void registerScanChecks(MontoyaApi api,
                                    EndpointRegistry endpoints,
                                    AiTriage triage,
                                    AiFieldDiscovery fieldDiscovery) {
        // Full OWASP API Top 10 (2023) coverage in one extension. Several
        // checks overlap Burp's native scanner (injection, SSRF, TRACE/PUT,
        // JWT/auth, CORS/CSP/misconfig) — that overlap is intentional so the
        // extension gives complete, OWASP-labelled coverage in one place. Each
        // overlapping issue carries a "Related Burp Scanner checks" line in its
        // detail pointing to the native check, which detects the same class at
        // higher confidence (see the vulnerabilities-list links in the issues).

        // Active checks. Frequency reflects what each check operates on.
        // PER_INSERTION_POINT — checks that mutate parameters.
        api.scanner().registerActiveScanCheck(
                new InjectionCheck(api),                          ScanCheckType.PER_INSERTION_POINT);
        api.scanner().registerActiveScanCheck(
                new SsrfCheck(api),                               ScanCheckType.PER_INSERTION_POINT);
        api.scanner().registerActiveScanCheck(
                new MassAssignmentCheck(api, fieldDiscovery),     ScanCheckType.PER_INSERTION_POINT);
        api.scanner().registerActiveScanCheck(
                new ParameterPollutionCheck(api),                 ScanCheckType.PER_INSERTION_POINT);
        // PER_HOST — checks that operate on endpoints/methods rather than parameters.
        api.scanner().registerActiveScanCheck(
                new MethodFuzzingCheck(api),                      ScanCheckType.PER_HOST);
        api.scanner().registerActiveScanCheck(
                new BrokenObjectAuthCheck(api),                   ScanCheckType.PER_HOST);
        api.scanner().registerActiveScanCheck(
                new FunctionLevelAuthCheck(api),                  ScanCheckType.PER_HOST);
        api.scanner().registerActiveScanCheck(
                new BrokenAuthCheck(api),                         ScanCheckType.PER_HOST);
        api.scanner().registerActiveScanCheck(
                new DeprecatedVersionProbeCheck(api),             ScanCheckType.PER_HOST);
        api.scanner().registerActiveScanCheck(
                new GraphQlCheck(api),                            ScanCheckType.PER_HOST);

        // Passive checks. PER_REQUEST runs once per HTTP transaction. AiTriage
        // filters out contextual false positives for each before they surface.
        api.scanner().registerPassiveScanCheck(
                new BusinessFlowCheck(api, endpoints, triage),           ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(
                new ExcessiveDataExposureCheck(api, endpoints, triage),  ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(
                new InventoryManagementCheck(api, endpoints, triage),    ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(
                new ResourceConsumptionCheck(api, endpoints, triage),    ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(
                new SecurityMisconfigCheck(api, endpoints, triage),      ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(
                new UnsafeApiConsumptionCheck(api, endpoints, triage),   ScanCheckType.PER_REQUEST);
    }

    // ---- UI ----------------------------------------------------------------

    private ScannerTab registerUiTab(MontoyaApi api, EndpointRegistry endpoints) {
        ScannerTab tab = new ScannerTab(api, endpoints, api.userInterface().swingUtils());
        SwingUtilities.invokeLater(() -> {
            // Pick up Burp's current theme (light / dark / high-contrast). Without
            // this the tab uses Swing defaults and looks out of place against a
            // dark Burp theme.
            api.userInterface().applyThemeToComponent(tab.component());
            api.userInterface().registerSuiteTab("API Scanner", tab.component());
        });
        return tab;
    }

    // ---- Unloading ---------------------------------------------------------

    private void registerUnloadingHandler(MontoyaApi api,
                                          AiClient aiClient,
                                          EndpointRegistry endpoints,
                                          ScannerTab tab) {
        api.extension().registerUnloadingHandler(() -> {
            aiClient.shutdown();
            endpoints.clear();
            if (tab != null) tab.dispose();
            api.logging().logToOutput("[" + EXTENSION_NAME + "] Unloaded cleanly.");
        });
    }

    // ---- Banner ------------------------------------------------------------

    private void logBanner(MontoyaApi api, BurpSuiteEdition edition, boolean aiAvailable) {
        api.logging().logToOutput("====================================");
        api.logging().logToOutput(EXTENSION_NAME + " v2.4.0");
        api.logging().logToOutput("OWASP API Security Top 10 (2023) coverage");
        api.logging().logToOutput("Edition: " + edition.displayName());
        api.logging().logToOutput("AI features: " + (aiAvailable ? "enabled" : "disabled"));
        api.logging().logToOutput("====================================");
    }
}
