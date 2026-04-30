package com.security.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.security.burp.checks.*;
import com.security.burp.scanner.EndpointRegistry;
import com.security.burp.ui.ScannerTab;

import javax.swing.SwingUtilities;

public class BurpExtender implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Advanced API Security Scanner V1");

        // Detect edition once (replaces legacy headless hack).
        BurpSuiteEdition edition = api.burpSuite().version().edition();
        boolean isEnterprise = edition == BurpSuiteEdition.ENTERPRISE_EDITION;

        EndpointRegistry registry = new EndpointRegistry();

        // ---------- Active scan checks ----------
        // PER_INSERTION_POINT: mutate parameters
        api.scanner().registerActiveScanCheck(
                new InjectionCheck(api, isEnterprise), ScanCheckType.PER_INSERTION_POINT);
        api.scanner().registerActiveScanCheck(
                new SsrfCheck(api, isEnterprise), ScanCheckType.PER_INSERTION_POINT);
        api.scanner().registerActiveScanCheck(
                new MassAssignmentCheck(api, isEnterprise), ScanCheckType.PER_INSERTION_POINT);

        // PER_HOST: test endpoints / methods rather than parameters
        api.scanner().registerActiveScanCheck(
                new MethodFuzzingCheck(api, isEnterprise), ScanCheckType.PER_HOST);
        api.scanner().registerActiveScanCheck(
                new BrokenObjectAuthCheck(api, isEnterprise), ScanCheckType.PER_HOST);
        api.scanner().registerActiveScanCheck(
                new FunctionLevelAuthCheck(api, isEnterprise), ScanCheckType.PER_HOST);

        // BrokenAuth - JWT analysis is per response; PER_HOST covers most token scenarios.
        api.scanner().registerActiveScanCheck(
                new BrokenAuthCheck(api, isEnterprise), ScanCheckType.PER_HOST);

        // ---------- Passive scan checks ----------
        api.scanner().registerPassiveScanCheck(
                new ExcessiveDataExposureCheck(api, registry), ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(
                new SecurityMisconfigCheck(api, registry), ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(
                new ResourceConsumptionCheck(api, registry), ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(
                new BusinessFlowCheck(api, registry), ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(
                new InventoryManagementCheck(api, registry), ScanCheckType.PER_REQUEST);
        api.scanner().registerPassiveScanCheck(
                new UnsafeApiConsumptionCheck(api, registry), ScanCheckType.PER_REQUEST);

        // UI tab - skip for Enterprise (headless).
        if (!isEnterprise) {
            try {
                SwingUtilities.invokeLater(() -> {
                    try {
                        ScannerTab tab = new ScannerTab(registry);
                        api.userInterface().registerSuiteTab("API Scanner", tab.getUiComponent());
                        api.logging().logToOutput("UI tab loaded successfully");
                    } catch (Exception e) {
                        api.logging().logToOutput("UI tab disabled: " + e.getMessage());
                    }
                });
            } catch (Exception e) {
                api.logging().logToOutput("UI initialization skipped: " + e.getMessage());
            }
        } else {
            api.logging().logToOutput("Running in Burp Enterprise Edition - UI tab disabled");
        }

        // Banner
        api.logging().logToOutput("====================================");
        api.logging().logToOutput("Advanced API Security Scanner V1");
        api.logging().logToOutput("OWASP API Security Top 10 2023");
        api.logging().logToOutput("Enhanced OWASP Categorization & Severity Levels");
        api.logging().logToOutput("Compatible with Burp Suite Professional & Enterprise Edition");
        api.logging().logToOutput("====================================");
        api.logging().logToOutput("Features:");
        api.logging().logToOutput("  API1:2023 - Broken Object Level Authorization");
        api.logging().logToOutput("  API2:2023 - Broken Authentication");
        api.logging().logToOutput("  API3:2023 - Broken Object Property Level Authorization");
        api.logging().logToOutput("  API4:2023 - Unrestricted Resource Consumption");
        api.logging().logToOutput("  API5:2023 - Broken Function Level Authorization");
        api.logging().logToOutput("  API6:2023 - Unrestricted Access to Sensitive Business Flows");
        api.logging().logToOutput("  API7:2023 - Server Side Request Forgery");
        api.logging().logToOutput("  API8:2023 - Security Misconfiguration");
        api.logging().logToOutput("  API9:2023 - Improper Inventory Management");
        api.logging().logToOutput("  API10:2023 - Unsafe Consumption of APIs");
        api.logging().logToOutput("====================================");
        api.logging().logToOutput("Key Features:");
        api.logging().logToOutput("  - HTTP Method Fuzzing (9 methods tested)");
        api.logging().logToOutput("  - Active + Passive Scanning");
        api.logging().logToOutput("  - JWT Security Testing");
        api.logging().logToOutput("  - Mass Assignment Detection");
        api.logging().logToOutput("  - SSRF Detection");
        api.logging().logToOutput("  - SQL/NoSQL/Command Injection");
        api.logging().logToOutput("====================================");
        api.logging().logToOutput("Extension loaded successfully!");
        api.logging().logToOutput("Mode: " + (isEnterprise ? "Enterprise (headless)" : "Interactive (Pro/Community)"));
    }
}
