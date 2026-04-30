package com.security.burp.ui;

import com.security.burp.scanner.EndpointRegistry;
import com.security.burp.utils.ApiEndpoint;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.Map;

public class ScannerTab {

    private final EndpointRegistry registry;
    private JPanel mainPanel;
    private JTable endpointTable;
    private DefaultTableModel tableModel;
    private JTextArea statsArea;
    private Timer refreshTimer;

    public ScannerTab(EndpointRegistry registry) {
        this.registry = registry;
        initializeUI();
        startAutoRefresh();
    }

    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel headerPanel = createHeaderPanel();
        mainPanel.add(headerPanel, BorderLayout.NORTH);

        JPanel centerPanel = createCenterPanel();
        mainPanel.add(centerPanel, BorderLayout.CENTER);

        JPanel bottomPanel = createBottomPanel();
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);
    }

    private JPanel createHeaderPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));

        JLabel titleLabel = new JLabel("Advanced API Security Scanner");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 18));
        panel.add(titleLabel, BorderLayout.NORTH);

        statsArea = new JTextArea(8, 50);
        statsArea.setEditable(false);
        statsArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        statsArea.setBackground(new Color(245, 245, 245));
        statsArea.setText("Waiting for API traffic...\n\n" +
                         "Features:\n" +
                         "  - HTTP Method Fuzzing (tests all methods on each endpoint)\n" +
                         "  - OWASP API Security Top 10 checks\n" +
                         "  - Broken Object Level Authorization (BOLA)\n" +
                         "  - Mass Assignment detection\n" +
                         "  - Injection vulnerabilities (SQL, NoSQL, Command, XSS)\n" +
                         "  - SSRF detection\n" +
                         "  - Security misconfiguration checks\n");
        JScrollPane statsScroll = new JScrollPane(statsArea);
        panel.add(statsScroll, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createCenterPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));

        JLabel tableLabel = new JLabel("Discovered API Endpoints:");
        tableLabel.setFont(new Font("Arial", Font.BOLD, 14));
        panel.add(tableLabel, BorderLayout.NORTH);

        String[] columnNames = {"Host", "Path", "Methods", "Requests"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        endpointTable = new JTable(tableModel);
        endpointTable.setAutoCreateRowSorter(true);
        endpointTable.getTableHeader().setReorderingAllowed(false);

        endpointTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        endpointTable.getColumnModel().getColumn(1).setPreferredWidth(300);
        endpointTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        endpointTable.getColumnModel().getColumn(3).setPreferredWidth(80);

        JScrollPane tableScroll = new JScrollPane(endpointTable);
        panel.add(tableScroll, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createBottomPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

        JButton refreshButton = new JButton("Refresh Endpoints");
        refreshButton.addActionListener(e -> refreshEndpointTable());
        panel.add(refreshButton);

        JButton clearButton = new JButton("Clear Table");
        clearButton.addActionListener(e -> {
            tableModel.setRowCount(0);
            updateStats();
        });
        panel.add(clearButton);

        JCheckBox autoRefreshCheck = new JCheckBox("Auto-refresh (5s)", true);
        autoRefreshCheck.addActionListener(e -> {
            if (autoRefreshCheck.isSelected()) {
                startAutoRefresh();
            } else {
                stopAutoRefresh();
            }
        });
        panel.add(autoRefreshCheck);

        JLabel statusLabel = new JLabel("Active scan checks will appear in Burp's Issues tab");
        statusLabel.setForeground(Color.BLUE);
        panel.add(Box.createHorizontalStrut(20));
        panel.add(statusLabel);

        return panel;
    }

    private void refreshEndpointTable() {
        Map<String, ApiEndpoint> endpoints = registry.snapshot();

        tableModel.setRowCount(0);

        for (ApiEndpoint endpoint : endpoints.values()) {
            Object[] row = {
                endpoint.getHost(),
                endpoint.getPath(),
                String.join(", ", endpoint.getMethods()),
                endpoint.getRequestCount()
            };
            tableModel.addRow(row);
        }

        updateStats();
    }

    private void updateStats() {
        Map<String, ApiEndpoint> endpoints = registry.snapshot();
        int totalEndpoints = endpoints.size();
        int totalRequests = endpoints.values().stream()
                                    .mapToInt(ApiEndpoint::getRequestCount)
                                    .sum();

        statsArea.setText(String.format(
            "API Scanning Statistics%n" +
            "======================%n" +
            "Discovered Endpoints: %d%n" +
            "Total API Requests:   %d%n%n" +
            "Active Checks:%n" +
            "  HTTP Method Fuzzing%n" +
            "  BOLA (Broken Object Level Authorization)%n" +
            "  Broken Authentication (JWT, tokens)%n" +
            "  Mass Assignment%n" +
            "  Excessive Data Exposure%n" +
            "  Injection Attacks (SQL, NoSQL, Command, XSS)%n" +
            "  SSRF Detection%n" +
            "  Security Misconfiguration%n%n" +
            "Check the Issues tab for discovered vulnerabilities.",
            totalEndpoints, totalRequests
        ));
    }

    private void startAutoRefresh() {
        if (refreshTimer == null) {
            refreshTimer = new Timer(5000, e -> refreshEndpointTable());
            refreshTimer.start();
        }
    }

    private void stopAutoRefresh() {
        if (refreshTimer != null) {
            refreshTimer.stop();
            refreshTimer = null;
        }
    }

    public Component getUiComponent() {
        return mainPanel;
    }
}
