package com.belch.ui;

import burp.api.montoya.MontoyaApi;
import com.belch.config.ApiConfig;
import com.belch.database.DatabaseService;
import com.belch.database.TrafficQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.CompoundBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.Map;

/**
 * Configuration panel for Belch v1.0.
 * Provides a user-friendly interface for configuring extension settings with dark mode support.
 * 
 * @author Charlie Campbell
 * @version 1.0.0
 */
public class ConfigurationPanel extends JPanel {
    
    private static final Logger logger = LoggerFactory.getLogger(ConfigurationPanel.class);
    
    private final ApiConfig config;
    private final DatabaseService databaseService;
    private final TrafficQueue trafficQueue;
    
    // Theme management
    private boolean isDarkMode;
    private JButton themeToggleButton;
    
    // Light theme colors
    private static final Color LIGHT_BACKGROUND_COLOR = new Color(248, 249, 250);
    private static final Color LIGHT_SECTION_BACKGROUND = new Color(255, 255, 255);
    private static final Color LIGHT_BORDER_COLOR = new Color(221, 221, 221);
    private static final Color LIGHT_TEXT_COLOR = new Color(33, 37, 41);
    private static final Color LIGHT_TEXT_MUTED = new Color(108, 117, 125);
    
    // Dark theme colors
    private static final Color DARK_BACKGROUND_COLOR = new Color(18, 18, 18);
    private static final Color DARK_SECTION_BACKGROUND = new Color(28, 28, 28);
    private static final Color DARK_BORDER_COLOR = new Color(68, 68, 68);
    private static final Color DARK_TEXT_COLOR = new Color(255, 255, 255);
    private static final Color DARK_TEXT_MUTED = new Color(170, 170, 170);
    
    // Accent colors (same for both themes)
    private static final Color PRIMARY_COLOR = new Color(0, 123, 255);
    private static final Color SUCCESS_COLOR = new Color(40, 167, 69);
    private static final Color WARNING_COLOR = new Color(255, 193, 7);
    private static final Color DANGER_COLOR = new Color(220, 53, 69);
    
    // Dynamic colors (will be set based on theme)
    private Color backgroundColor;
    private Color sectionBackground;
    private Color borderColor;
    private Color textColor;
    private Color textMuted;
    
    // UI Components
    private JSpinner portSpinner;
    private JTextField databasePathField;
    private JButton databaseBrowseButton;
    private JTextField sessionTagField;
    private JCheckBox verboseLoggingCheckbox;
    private JButton saveButton;
    private JButton resetButton;
    private JButton testConnectionButton;
    private JLabel statusLabel;
    
    // Live status components
    private JLabel dbStatusLabel;
    private JLabel queueStatusLabel;
    private JLabel trafficCountLabel;
    private Timer statusUpdateTimer;
    
    // Configuration file path
    private static final String CONFIG_DIR = System.getProperty("user.home") + File.separator + ".belch";
    private static final String CONFIG_FILE = CONFIG_DIR + File.separator + "extension.properties";
    
    /**
     * Constructor for the configuration panel.
     * 
     * @param config The current configuration
     * @param databaseService The database service instance
     * @param trafficQueue The traffic queue instance
     */
    public ConfigurationPanel(ApiConfig config, DatabaseService databaseService, TrafficQueue trafficQueue) {
        this.config = config;
        this.databaseService = databaseService;
        this.trafficQueue = trafficQueue;
        
        // Detect and set initial theme
        detectAndSetTheme();
        
        initializeUI();
        loadCurrentSettings();
        setupEventHandlers();
        startStatusUpdates();
    }
    
    /**
     * Detects system dark mode preference and sets the theme accordingly.
     */
    private void detectAndSetTheme() {
        isDarkMode = isSystemDarkMode();
        updateThemeColors();
        logger.info("Theme detected: {}", isDarkMode ? "Dark" : "Light");
    }
    
    /**
     * Detects if the system is in dark mode.
     * 
     * @return true if dark mode is detected
     */
    private boolean isSystemDarkMode() {
        try {
            // Method 1: Check macOS dark mode via system property
            String osName = System.getProperty("os.name").toLowerCase();
            if (osName.contains("mac")) {
                try {
                    // Try to detect macOS dark mode
                    Process process = Runtime.getRuntime().exec("defaults read -g AppleInterfaceStyle");
                    process.waitFor();
                    if (process.exitValue() == 0) {
                        java.util.Scanner scanner = new java.util.Scanner(process.getInputStream());
                        if (scanner.hasNext()) {
                            String result = scanner.next();
                            return "Dark".equals(result);
                        }
                    }
                } catch (Exception e) {
                    logger.debug("Could not detect macOS dark mode via defaults command: {}", e.getMessage());
                }
            }
            
            // Method 2: Check Look and Feel background color
            Color background = UIManager.getColor("Panel.background");
            if (background != null) {
                // Calculate luminance (perception of brightness)
                double luminance = 0.299 * background.getRed() + 0.587 * background.getGreen() + 0.114 * background.getBlue();
                return luminance < 128; // Dark if luminance is low
            }
            
            // Method 3: Check if using a dark Look and Feel
            String lafName = UIManager.getLookAndFeel().getName().toLowerCase();
            if (lafName.contains("dark") || lafName.contains("nimbus") || lafName.contains("metal")) {
                Color controlColor = UIManager.getColor("control");
                if (controlColor != null) {
                    return controlColor.getRed() + controlColor.getGreen() + controlColor.getBlue() < 384; // Dark if sum < 128*3
                }
            }
            
        } catch (Exception e) {
            logger.debug("Error detecting dark mode: {}", e.getMessage());
        }
        
        // Default to light mode if detection fails
        return false;
    }
    
    /**
     * Updates theme colors based on current dark mode setting.
     */
    private void updateThemeColors() {
        if (isDarkMode) {
            backgroundColor = DARK_BACKGROUND_COLOR;
            sectionBackground = DARK_SECTION_BACKGROUND;
            borderColor = DARK_BORDER_COLOR;
            textColor = DARK_TEXT_COLOR;
            textMuted = DARK_TEXT_MUTED;
        } else {
            backgroundColor = LIGHT_BACKGROUND_COLOR;
            sectionBackground = LIGHT_SECTION_BACKGROUND;
            borderColor = LIGHT_BORDER_COLOR;
            textColor = LIGHT_TEXT_COLOR;
            textMuted = LIGHT_TEXT_MUTED;
        }
    }
    
    /**
     * Toggles between dark and light mode.
     */
    private void toggleTheme() {
        isDarkMode = !isDarkMode;
        updateThemeColors();
        refreshUI();
        updateStatus("Switched to " + (isDarkMode ? "dark" : "light") + " mode", SUCCESS_COLOR);
    }
    
    /**
     * Refreshes the entire UI with the current theme.
     */
    private void refreshUI() {
        SwingUtilities.invokeLater(() -> {
            // Stop status updates during refresh
            if (statusUpdateTimer != null) {
                statusUpdateTimer.stop();
            }
            
            // Store current values before refresh
            int currentPort = (Integer) portSpinner.getValue();
            String currentDbPath = databasePathField.getText();
            String currentSessionTag = sessionTagField.getText();
            boolean currentVerboseLogging = verboseLoggingCheckbox.isSelected();
            
            // Remove all components and recreate with new theme
            removeAll();
            initializeUI();
            
            // Restore values
            portSpinner.setValue(currentPort);
            databasePathField.setText(currentDbPath);
            sessionTagField.setText(currentSessionTag);
            verboseLoggingCheckbox.setSelected(currentVerboseLogging);
            
            // Restart status updates
            startStatusUpdates();
            
            // Force complete repaint
            invalidate();
            revalidate();
            repaint();
            
            // Update parent containers
            Container parent = getParent();
            while (parent != null) {
                parent.repaint();
                parent = parent.getParent();
            }
            
            logger.info("UI refreshed with {} theme", isDarkMode ? "dark" : "light");
        });
    }
    
    /**
     * Initializes the user interface components.
     */
    private void initializeUI() {
        setLayout(new BorderLayout());
        setBackground(backgroundColor);
        
        // Create main panel with better styling
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBackground(backgroundColor);
        
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(new EmptyBorder(20, 20, 20, 20));
        contentPanel.setBackground(backgroundColor);
        
        // Enhanced title section
        contentPanel.add(createTitleSection());
        contentPanel.add(Box.createVerticalStrut(25));
        
        // Configuration sections with better styling
        contentPanel.add(createServerConfigSection());
        contentPanel.add(Box.createVerticalStrut(20));
        
        contentPanel.add(createDatabaseConfigSection());
        contentPanel.add(Box.createVerticalStrut(20));
        
        contentPanel.add(createSessionConfigSection());
        contentPanel.add(Box.createVerticalStrut(20));
        
        contentPanel.add(createLoggingConfigSection());
        contentPanel.add(Box.createVerticalStrut(20));
        
        contentPanel.add(createLiveStatusSection());
        contentPanel.add(Box.createVerticalStrut(25));
        
        // Enhanced button panel
        contentPanel.add(createButtonPanel());
        contentPanel.add(Box.createVerticalStrut(15));
        
        // Enhanced status label
        statusLabel = createStyledStatusLabel();
        contentPanel.add(statusLabel);
        
        // Add content to scroll pane with modern styling
        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setBorder(null);
        scrollPane.getViewport().setBackground(backgroundColor);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        
        // Enhanced info panel
        JPanel infoPanel = createInfoPanel();
        mainPanel.add(infoPanel, BorderLayout.SOUTH);
        
        add(mainPanel, BorderLayout.CENTER);
    }
    
    /**
     * Creates an enhanced title section.
     */
    private JPanel createTitleSection() {
        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setBackground(backgroundColor);
        titlePanel.setBorder(new EmptyBorder(0, 0, 10, 0));
        
        // Title and subtitle in center
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.setBackground(backgroundColor);
        
        JLabel titleLabel = new JLabel("Belch Configuration");
        titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 24));
        titleLabel.setForeground(textColor);
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        
        JLabel subtitleLabel = new JLabel("Configure your Belch v1.0 extension settings");
        subtitleLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14));
        subtitleLabel.setForeground(textMuted);
        subtitleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        
        centerPanel.add(titleLabel, BorderLayout.CENTER);
        centerPanel.add(subtitleLabel, BorderLayout.SOUTH);
        
        // Theme toggle button in top right
        JPanel topRightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        topRightPanel.setBackground(backgroundColor);
        
        themeToggleButton = createThemeToggleButton();
        topRightPanel.add(themeToggleButton);
        
        titlePanel.add(centerPanel, BorderLayout.CENTER);
        titlePanel.add(topRightPanel, BorderLayout.EAST);
        
        return titlePanel;
    }
    
    /**
     * Creates the theme toggle button.
     */
    private JButton createThemeToggleButton() {
        String buttonText = isDarkMode ? "Light Mode" : "Dark Mode";
        JButton toggleButton = new JButton(buttonText);
        
        toggleButton.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        toggleButton.setBackground(isDarkMode ? new Color(60, 60, 60) : new Color(230, 230, 230));
        toggleButton.setForeground(textColor);
        toggleButton.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 12));
        toggleButton.setFocusPainted(false);
        toggleButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        toggleButton.setToolTipText("Toggle between dark and light theme");
        
        // Add hover effect
        Color normalBg = toggleButton.getBackground();
        toggleButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                toggleButton.setBackground(normalBg.brighter());
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                toggleButton.setBackground(normalBg);
            }
        });
        
        // Add click handler
        toggleButton.addActionListener(e -> toggleTheme());
        
        return toggleButton;
    }
    
    /**
     * Creates a styled section panel with better alignment.
     */
    private JPanel createStyledSection(String title) {
        JPanel section = new JPanel(new GridBagLayout());
        section.setBackground(sectionBackground);
        section.setOpaque(true);  // Ensure background is painted
        
        // Create custom border with modern styling
        TitledBorder titledBorder = BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(borderColor, 1), 
            title
        );
        titledBorder.setTitleFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        titledBorder.setTitleColor(textColor);
        
        CompoundBorder compoundBorder = BorderFactory.createCompoundBorder(
            titledBorder,
            new EmptyBorder(10, 15, 10, 15)  // Reduced vertical padding
        );
        
        section.setBorder(compoundBorder);
        return section;
    }
    
    /**
     * Creates the server configuration section.
     */
    private JPanel createServerConfigSection() {
        JPanel section = createStyledSection("Server Configuration");
        GridBagConstraints gbc = new GridBagConstraints();
        
        // Port field with proper alignment
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;  // Top-left align
        gbc.insets = new Insets(5, 5, 5, 10);
        gbc.weightx = 0.0;  // Don't expand label
        JLabel portLabel = new JLabel("API Port:");
        portLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        portLabel.setForeground(textColor);
        section.add(portLabel, gbc);
        
        gbc.gridx = 1;
        gbc.insets = new Insets(5, 0, 5, 10);
        gbc.weightx = 0.0;  // Don't expand spinner
        portSpinner = new JSpinner(new SpinnerNumberModel(7850, 1024, 65535, 1));
        portSpinner.setToolTipText("Port number for the REST API server (1024-65535)");
        portSpinner.setPreferredSize(new Dimension(120, 28));
        
        // Style the spinner properly
        JSpinner.NumberEditor editor = new JSpinner.NumberEditor(portSpinner, "#");
        portSpinner.setEditor(editor);
        JTextField spinnerTextField = ((JSpinner.DefaultEditor) portSpinner.getEditor()).getTextField();
        styleTextField(spinnerTextField);
        portSpinner.setBackground(sectionBackground);
        section.add(portSpinner, gbc);
        
        gbc.gridx = 2;
        gbc.insets = new Insets(5, 0, 5, 5);
        gbc.weightx = 1.0;  // Help text can expand
        gbc.anchor = GridBagConstraints.WEST;
        JLabel portHelpLabel = new JLabel("Restart required after changing");
        portHelpLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        portHelpLabel.setForeground(textMuted);
        section.add(portHelpLabel, gbc);
        
        return section;
    }
    
    /**
     * Creates the database configuration section.
     */
    private JPanel createDatabaseConfigSection() {
        JPanel section = createStyledSection("Database Configuration");
        GridBagConstraints gbc = new GridBagConstraints();
        
        // Database path field with button next to it
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(5, 5, 5, 10);
        gbc.weightx = 0.0;
        JLabel dbLabel = new JLabel("Database Path:");
        dbLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        dbLabel.setForeground(textColor);
        section.add(dbLabel, gbc);
        
        // Create a panel to hold the text field and button together
        JPanel dbFieldPanel = new JPanel(new BorderLayout(5, 0));
        dbFieldPanel.setBackground(sectionBackground);
        dbFieldPanel.setOpaque(true);
        
        databasePathField = new JTextField(30);
        databasePathField.setToolTipText("Full path to the SQLite database file");
        databasePathField.setPreferredSize(new Dimension(300, 28));
        styleTextField(databasePathField);
        dbFieldPanel.add(databasePathField, BorderLayout.CENTER);
        
        databaseBrowseButton = createStyledButton("Browse...", PRIMARY_COLOR);
        databaseBrowseButton.setToolTipText("Select database file location");
        dbFieldPanel.add(databaseBrowseButton, BorderLayout.EAST);
        
        gbc.gridx = 1;
        gbc.insets = new Insets(5, 0, 5, 5);
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        section.add(dbFieldPanel, gbc);
        
        return section;
    }
    
    /**
     * Creates the session configuration section.
     */
    private JPanel createSessionConfigSection() {
        JPanel section = createStyledSection("Session Configuration");
        GridBagConstraints gbc = new GridBagConstraints();
        
        // Session tag field with button next to it
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(5, 5, 5, 10);
        gbc.weightx = 0.0;
        JLabel sessionLabel = new JLabel("Default Session Tag:");
        sessionLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        sessionLabel.setForeground(textColor);
        section.add(sessionLabel, gbc);
        
        // Create a panel to hold the text field and button together
        JPanel sessionFieldPanel = new JPanel(new BorderLayout(5, 0));
        sessionFieldPanel.setBackground(sectionBackground);
        sessionFieldPanel.setOpaque(true);
        
        sessionTagField = new JTextField(20);
        sessionTagField.setToolTipText("Default tag for new traffic records (leave empty to auto-generate)");
        sessionTagField.setPreferredSize(new Dimension(200, 28));
        styleTextField(sessionTagField);
        sessionFieldPanel.add(sessionTagField, BorderLayout.CENTER);
        
        JButton autoGenerateButton = createStyledButton("Auto-Generate", SUCCESS_COLOR);
        autoGenerateButton.setToolTipText("Generate a new session tag with current timestamp");
        autoGenerateButton.addActionListener(e -> {
            String autoTag = config.generateNewSessionTag(null);
            sessionTagField.setText(autoTag);
            updateStatus("Generated session tag: " + autoTag, SUCCESS_COLOR);
        });
        sessionFieldPanel.add(autoGenerateButton, BorderLayout.EAST);
        
        gbc.gridx = 1;
        gbc.insets = new Insets(5, 0, 5, 5);
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        section.add(sessionFieldPanel, gbc);
        
        // Help text on second row
        gbc.gridy = 1;
        gbc.gridx = 1;
        gbc.gridwidth = 1;
        gbc.insets = new Insets(2, 0, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        JLabel sessionHelpLabel = new JLabel("Empty = auto-generate (format: session_YYYY-MM-DD_HH-mm-ss)");
        sessionHelpLabel.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 11));
        sessionHelpLabel.setForeground(textMuted);
        section.add(sessionHelpLabel, gbc);
        
        return section;
    }
    
    /**
     * Enhanced logging configuration section with better alignment.
     */
    private JPanel createLoggingConfigSection() {
        JPanel section = createStyledSection("Logging Configuration");
        GridBagConstraints gbc = new GridBagConstraints();
        
        // Verbose logging checkbox
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.weightx = 1.0;
        verboseLoggingCheckbox = new JCheckBox("Enable Verbose Logging");
        verboseLoggingCheckbox.setToolTipText("Enable detailed debug logging for troubleshooting");
        verboseLoggingCheckbox.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        verboseLoggingCheckbox.setBackground(sectionBackground);
        verboseLoggingCheckbox.setForeground(textColor);
        verboseLoggingCheckbox.setOpaque(true);
        section.add(verboseLoggingCheckbox, gbc);
        
        return section;
    }
    
    /**
     * Creates the live status section with better alignment.
     */
    private JPanel createLiveStatusSection() {
        JPanel section = createStyledSection("Live Status");
        GridBagConstraints gbc = new GridBagConstraints();
        
        // Database status
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(5, 5, 5, 15);
        gbc.weightx = 0.0;
        JLabel dbLabel = new JLabel("Database Status:");
        dbLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        dbLabel.setForeground(textColor);
        section.add(dbLabel, gbc);
        
        gbc.gridx = 1;
        gbc.insets = new Insets(5, 0, 5, 5);
        gbc.weightx = 1.0;
        dbStatusLabel = createStatusLabel("Checking...", textMuted);
        section.add(dbStatusLabel, gbc);
        
        // Queue status
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.insets = new Insets(5, 5, 5, 15);
        gbc.weightx = 0.0;
        JLabel queueLabel = new JLabel("Queue Status:");
        queueLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        queueLabel.setForeground(textColor);
        section.add(queueLabel, gbc);
        
        gbc.gridx = 1;
        gbc.insets = new Insets(5, 0, 5, 5);
        gbc.weightx = 1.0;
        queueStatusLabel = createStatusLabel("Checking...", textMuted);
        section.add(queueStatusLabel, gbc);
        
        // Traffic count
        gbc.gridx = 0; gbc.gridy = 2;
        gbc.insets = new Insets(5, 5, 5, 15);
        gbc.weightx = 0.0;
        JLabel trafficLabel = new JLabel("Traffic Records:");
        trafficLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        trafficLabel.setForeground(textColor);
        section.add(trafficLabel, gbc);
        
        gbc.gridx = 1;
        gbc.insets = new Insets(5, 0, 5, 5);
        gbc.weightx = 1.0;
        trafficCountLabel = createStatusLabel("Loading...", textMuted);
        section.add(trafficCountLabel, gbc);
        
        return section;
    }
    
    /**
     * Creates the button panel.
     */
    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 15, 0));
        buttonPanel.setBackground(backgroundColor);
        
        saveButton = createStyledButton("Save Configuration", SUCCESS_COLOR);
        saveButton.setToolTipText("Save settings and apply changes");
        saveButton.setPreferredSize(new Dimension(160, 35));
        buttonPanel.add(saveButton);
        
        resetButton = createStyledButton("Reset to Defaults", WARNING_COLOR);
        resetButton.setToolTipText("Reset all settings to default values");
        resetButton.setPreferredSize(new Dimension(160, 35));
        buttonPanel.add(resetButton);
        
        testConnectionButton = createStyledButton("Test Database", PRIMARY_COLOR);
        testConnectionButton.setToolTipText("Test database connection with current settings");
        testConnectionButton.setPreferredSize(new Dimension(160, 35));
        buttonPanel.add(testConnectionButton);
        
        return buttonPanel;
    }
    
    /**
     * Creates a styled button.
     */
    private JButton createStyledButton(String text, Color backgroundColor) {
        JButton button = new JButton(text);
        button.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        button.setBackground(backgroundColor);
        button.setForeground(Color.WHITE);
        button.setBorder(BorderFactory.createEmptyBorder(8, 16, 8, 16));
        button.setFocusPainted(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        // Add hover effect
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                button.setBackground(backgroundColor.darker());
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                button.setBackground(backgroundColor);
            }
        });
        
        return button;
    }
    
    /**
     * Styles a text field.
     */
    private void styleTextField(JTextField textField) {
        textField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(borderColor, 1),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));
        textField.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        textField.setBackground(sectionBackground);
        textField.setForeground(textColor);
        textField.setCaretColor(textColor);
        textField.setOpaque(true);  // Ensure background is painted
    }
    
    /**
     * Creates a status label with styling.
     */
    private JLabel createStatusLabel(String text, Color color) {
        JLabel label = new JLabel(text);
        label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        label.setForeground(color);
        label.setOpaque(false);  // Status labels don't need background
        return label;
    }
    
    /**
     * Creates a styled status label for the main status.
     */
    private JLabel createStyledStatusLabel() {
        JLabel label = new JLabel("Ready");
        label.setHorizontalAlignment(SwingConstants.CENTER);
        label.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 13));
        label.setForeground(textMuted);
        label.setAlignmentX(Component.CENTER_ALIGNMENT);
        label.setOpaque(false);
        
        // Add padding around status
        label.setBorder(new EmptyBorder(10, 0, 10, 0));
        
        return label;
    }
    
    /**
     * Creates the enhanced information panel at the bottom.
     */
    private JPanel createInfoPanel() {
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createLineBorder(borderColor, 1));
        infoPanel.setBackground(sectionBackground);
        infoPanel.setOpaque(true);
        
        JTextArea infoText = new JTextArea(3, 50);
        infoText.setText(
            "Configuration is saved to: " + CONFIG_FILE + "\n" +
            "Changes to port and database path require extension reload to take effect.\n" +
            "Use 'Test Database' to verify database connectivity before saving."
        );
        infoText.setEditable(false);
        infoText.setBackground(sectionBackground);
        infoText.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        infoText.setForeground(textMuted);
        infoText.setBorder(new EmptyBorder(15, 15, 15, 15));
        infoText.setOpaque(true);
        
        infoPanel.add(infoText, BorderLayout.CENTER);
        
        return infoPanel;
    }
    
    /**
     * Loads current settings into the UI components.
     */
    private void loadCurrentSettings() {
        // Load from saved configuration if exists, otherwise use current config
        Properties savedProps = loadSavedConfiguration();
        
        if (savedProps != null) {
            portSpinner.setValue(Integer.parseInt(savedProps.getProperty("api.port", String.valueOf(config.getPort()))));
            databasePathField.setText(savedProps.getProperty("database.path", config.getDatabasePath()));
            sessionTagField.setText(savedProps.getProperty("session.tag", config.getSessionTag()));
            verboseLoggingCheckbox.setSelected(Boolean.parseBoolean(savedProps.getProperty("logging.verbose", String.valueOf(config.isVerboseLogging()))));
        } else {
            // Use current config values (which now have smart defaults)
            portSpinner.setValue(config.getPort());
            databasePathField.setText(config.getDatabasePath());
            sessionTagField.setText(config.getSessionTag());
            verboseLoggingCheckbox.setSelected(config.isVerboseLogging());
        }
        
        updateStatus("Configuration loaded - using smart defaults if no saved config exists");
    }
    
    /**
     * Sets up event handlers for UI components.
     */
    private void setupEventHandlers() {
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                saveConfiguration();
            }
        });
        
        resetButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                resetToDefaults();
            }
        });
        
        testConnectionButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                testDatabaseConnection();
            }
        });
        
        databaseBrowseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                browseDatabasePath();
            }
        });
    }
    
    /**
     * Saves the current configuration.
     */
    private void saveConfiguration() {
        try {
            updateStatus("Saving configuration...");
            
            Properties props = new Properties();
            props.setProperty("api.port", portSpinner.getValue().toString());
            props.setProperty("database.path", databasePathField.getText().trim());
            props.setProperty("session.tag", sessionTagField.getText().trim());
            props.setProperty("logging.verbose", String.valueOf(verboseLoggingCheckbox.isSelected()));
            
            // Create config directory if it doesn't exist
            File configDir = new File(CONFIG_DIR);
            if (!configDir.exists()) {
                configDir.mkdirs();
            }
            
            // Save properties file
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream(CONFIG_FILE)) {
                props.store(fos, "Belch v1.0 Extension Configuration");
            }
            
            // Update current config object (for immediate use)
            config.setPort((Integer) portSpinner.getValue());
            config.setDatabasePath(databasePathField.getText().trim());
            config.setSessionTag(sessionTagField.getText().trim());
            config.setVerboseLogging(verboseLoggingCheckbox.isSelected());
            
            updateStatus("Configuration saved successfully! Some changes require extension reload.");
            
            // Show success message
            JOptionPane.showMessageDialog(this, 
                "Configuration saved successfully!\n\n" +
                "Note: Changes to port and database path require\n" +
                "unloading and reloading the extension to take effect.",
                "Configuration Saved", 
                JOptionPane.INFORMATION_MESSAGE);
                
        } catch (Exception e) {
            logger.error("Failed to save configuration", e);
            updateStatus("Failed to save configuration: " + e.getMessage());
            
            JOptionPane.showMessageDialog(this, 
                "Failed to save configuration:\n" + e.getMessage(),
                "Save Error", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * Resets all settings to default values.
     */
    private void resetToDefaults() {
        int result = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to reset all settings to default values?",
            "Reset Configuration",
            JOptionPane.YES_NO_OPTION);
            
        if (result == JOptionPane.YES_OPTION) {
            portSpinner.setValue(7850);
            databasePathField.setText("belch.db");
            sessionTagField.setText("");
            verboseLoggingCheckbox.setSelected(false);
            
            updateStatus("Configuration reset to defaults");
        }
    }
    
    /**
     * Tests the database connection with current settings.
     */
    private void testDatabaseConnection() {
        updateStatus("Testing database connection...");
        
        SwingWorker<Boolean, Void> worker = new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() throws Exception {
                String dbPath = databasePathField.getText().trim();
                
                // Test database connection
                Class.forName("org.sqlite.JDBC");
                try (java.sql.Connection conn = java.sql.DriverManager.getConnection("jdbc:sqlite:" + dbPath)) {
                    try (java.sql.Statement stmt = conn.createStatement()) {
                        stmt.execute("CREATE TABLE IF NOT EXISTS test_connection (id INTEGER PRIMARY KEY)");
                        stmt.execute("DROP TABLE test_connection");
                    }
                    return true;
                }
            }
            
            @Override
            protected void done() {
                try {
                    Boolean success = get();
                    if (success) {
                        updateStatus("Database connection test successful!");
                        JOptionPane.showMessageDialog(ConfigurationPanel.this,
                            "Database connection test successful!\n" +
                            "The database path is valid and writable.",
                            "Connection Test",
                            JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (Exception e) {
                    String errorMsg = "Database connection failed: " + e.getMessage();
                    updateStatus(errorMsg);
                    
                    JOptionPane.showMessageDialog(ConfigurationPanel.this,
                        "Database connection test failed:\n\n" + 
                        e.getMessage() + "\n\n" +
                        "Please check the database path and ensure the directory is writable.",
                        "Connection Test Failed",
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        
        worker.execute();
    }
    
    /**
     * Opens a file browser for selecting database path.
     */
    private void browseDatabasePath() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Database File Location");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        
        // Set current directory based on current path
        String currentPath = databasePathField.getText().trim();
        if (!currentPath.isEmpty()) {
            File currentFile = new File(currentPath);
            if (currentFile.getParentFile() != null && currentFile.getParentFile().exists()) {
                fileChooser.setCurrentDirectory(currentFile.getParentFile());
                fileChooser.setSelectedFile(currentFile);
            }
        }
        
        // Add file filter for database files
        javax.swing.filechooser.FileNameExtensionFilter filter = 
            new javax.swing.filechooser.FileNameExtensionFilter("Database files (*.db, *.sqlite)", "db", "sqlite");
        fileChooser.setFileFilter(filter);
        
        int result = fileChooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String path = selectedFile.getAbsolutePath();
            
            // Add .db extension if not present
            if (!path.toLowerCase().endsWith(".db") && !path.toLowerCase().endsWith(".sqlite")) {
                path += ".db";
            }
            
            databasePathField.setText(path);
            updateStatus("Database path updated");
        }
    }
    
    /**
     * Loads saved configuration from file.
     * 
     * @return Properties object or null if file doesn't exist
     */
    private Properties loadSavedConfiguration() {
        File configFile = new File(CONFIG_FILE);
        if (!configFile.exists()) {
            return null;
        }
        
        try {
            Properties props = new Properties();
            try (java.io.FileInputStream fis = new java.io.FileInputStream(configFile)) {
                props.load(fis);
            }
            return props;
        } catch (Exception e) {
            logger.warn("Failed to load saved configuration", e);
            return null;
        }
    }
    
    /**
     * Updates the status label.
     * 
     * @param message Status message
     */
    private void updateStatus(String message) {
        updateStatus(message, textMuted);
    }
    
    /**
     * Updates the status label with custom color.
     * 
     * @param message Status message
     * @param color Text color
     */
    private void updateStatus(String message, Color color) {
        statusLabel.setText(message);
        statusLabel.setForeground(color);
        statusLabel.setToolTipText(message);
        
        // Auto-clear status after 5 seconds
        Timer timer = new Timer(5000, e -> {
            if (statusLabel.getText().equals(message)) {
                statusLabel.setText("Ready");
                statusLabel.setForeground(textMuted);
                statusLabel.setToolTipText(null);
            }
        });
        timer.setRepeats(false);
        timer.start();
    }
    
    /**
     * Starts periodic status updates for live monitoring.
     */
    private void startStatusUpdates() {
        // Update status every 2 seconds
        statusUpdateTimer = new Timer(2000, e -> updateLiveStatus());
        statusUpdateTimer.setRepeats(true);
        statusUpdateTimer.start();
        
        // Do initial update
        updateLiveStatus();
    }
    
    /**
     * Stops status updates when panel is disposed.
     */
    public void stopStatusUpdates() {
        if (statusUpdateTimer != null) {
            statusUpdateTimer.stop();
        }
    }
    
    /**
     * Updates live status displays.
     */
    private void updateLiveStatus() {
        SwingUtilities.invokeLater(() -> {
            // Update database status
            if (databaseService != null && databaseService.isInitialized()) {
                dbStatusLabel.setText("Connected");
                dbStatusLabel.setForeground(SUCCESS_COLOR); // Use themed green
                
                // Get traffic count
                try {
                    Map<String, String> emptyParams = new java.util.HashMap<>();
                    Map<String, Object> stats = databaseService.getTrafficStats(emptyParams);
                    Object totalRecords = stats.get("total_requests");
                    if (totalRecords != null) {
                        trafficCountLabel.setText(totalRecords.toString() + " requests");
                        trafficCountLabel.setForeground(textColor);
                    } else {
                        trafficCountLabel.setText("No data");
                        trafficCountLabel.setForeground(textMuted);
                    }
                } catch (Exception e) {
                    trafficCountLabel.setText("Error loading count");
                    trafficCountLabel.setForeground(DANGER_COLOR);
                }
            } else {
                dbStatusLabel.setText("Disconnected");
                dbStatusLabel.setForeground(DANGER_COLOR);
                trafficCountLabel.setText("N/A");
                trafficCountLabel.setForeground(textMuted);
            }
            
            // Update queue status
            if (trafficQueue != null) {
                try {
                    Map<String, Object> metrics = trafficQueue.getMetrics();
                    Object currentSize = metrics.get("current_size");
                    Object capacity = metrics.get("capacity");
                    if (currentSize != null && capacity != null) {
                        queueStatusLabel.setText(currentSize + "/" + capacity + " items");
                        queueStatusLabel.setForeground(textColor);
                    } else {
                        queueStatusLabel.setText("Active");
                        queueStatusLabel.setForeground(SUCCESS_COLOR);
                    }
                } catch (Exception e) {
                    queueStatusLabel.setText("Error");
                    queueStatusLabel.setForeground(DANGER_COLOR);
                }
            } else {
                queueStatusLabel.setText("Not available");
                queueStatusLabel.setForeground(textMuted);
            }
        });
    }
    
    /**
     * Gets the saved configuration file path.
     * 
     * @return Configuration file path
     */
    public static String getConfigFilePath() {
        return CONFIG_FILE;
    }
    
    /**
     * Loads configuration from saved file into the provided ApiConfig.
     * 
     * @param config The ApiConfig to update
     */
    public static void loadSavedConfigInto(ApiConfig config) {
        File configFile = new File(CONFIG_FILE);
        if (!configFile.exists()) {
            return;
        }
        
        try {
            Properties props = new Properties();
            try (java.io.FileInputStream fis = new java.io.FileInputStream(configFile)) {
                props.load(fis);
            }
            
            if (props.containsKey("api.port")) {
                config.setPort(Integer.parseInt(props.getProperty("api.port")));
            }
            if (props.containsKey("database.path")) {
                config.setDatabasePath(props.getProperty("database.path"));
            }
            if (props.containsKey("session.tag")) {
                config.setSessionTag(props.getProperty("session.tag"));
            }
            if (props.containsKey("logging.verbose")) {
                config.setVerboseLogging(Boolean.parseBoolean(props.getProperty("logging.verbose")));
            }
            
        } catch (Exception e) {
            LoggerFactory.getLogger(ConfigurationPanel.class).warn("Failed to load saved configuration", e);
        }
    }
} 