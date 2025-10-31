import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.File;
import java.util.Arrays;

/**
 * EncryptionApp - JavaFX GUI for File Encryption & Decryption Tool
 *
 * This replaces the command-line interface with a graphical user interface.
 * All the core encryption logic remains in the existing classes.
 */
public class EncryptionApp extends Application {

    // UI Components
    private RadioButton encryptRadio;
    private RadioButton decryptRadio;
    private TextField inputFileField;
    private TextField outputFileField;
    private PasswordField passwordField;
    private CheckBox showPasswordCheckBox;
    private TextField passwordVisibleField;
    private Button startButton;
    private TextArea logArea;
    private File selectedInputFile;
    private File selectedOutputFile;

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("File Encryption & Decryption Tool");

        // Create main layout
        VBox root = new VBox(15);
        root.setPadding(new Insets(20));
        root.setAlignment(Pos.TOP_CENTER);

        // Title
        Label titleLabel = new Label("File Encryption & Decryption Tool");
        titleLabel.setStyle("-fx-font-size: 18px; -fx-font-weight: bold;");

        // Mode selection
        HBox modeBox = createModeSelection();

        // File selection section
        VBox fileSection = createFileSection();

        // Password section
        VBox passwordSection = createPasswordSection();

        // Start button
        startButton = new Button("START");
        startButton.setPrefWidth(200);
        startButton.setStyle("-fx-font-size: 14px; -fx-font-weight: bold;");
        startButton.setOnAction(e -> handleStart());

        // Log area
        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setPrefHeight(150);
        logArea.setWrapText(true);
        logArea.setPromptText("Activity log will appear here...");

        // Add all components to root
        root.getChildren().addAll(
                titleLabel,
                new Separator(),
                modeBox,
                fileSection,
                passwordSection,
                startButton,
                new Label("Activity Log:"),
                logArea
        );

        // Create scene and show
        Scene scene = new Scene(root, 600, 600);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    /**
     * Creates the mode selection section (Encrypt/Decrypt radio buttons)
     */
    private HBox createModeSelection() {
        HBox modeBox = new HBox(20);
        modeBox.setAlignment(Pos.CENTER);

        Label modeLabel = new Label("Mode:");
        modeLabel.setStyle("-fx-font-weight: bold;");

        // Radio buttons for mode selection
        ToggleGroup modeGroup = new ToggleGroup();

        encryptRadio = new RadioButton("Encrypt");
        encryptRadio.setToggleGroup(modeGroup);
        encryptRadio.setSelected(true); // Default to encrypt
        encryptRadio.setOnAction(e -> updateOutputFieldPrompt());

        decryptRadio = new RadioButton("Decrypt");
        decryptRadio.setToggleGroup(modeGroup);
        decryptRadio.setOnAction(e -> updateOutputFieldPrompt());

        modeBox.getChildren().addAll(modeLabel, encryptRadio, decryptRadio);
        return modeBox;
    }

    /**
     * Creates the file selection section
     */
    private VBox createFileSection() {
        VBox fileSection = new VBox(10);

        // Input file row
        HBox inputRow = new HBox(10);
        inputRow.setAlignment(Pos.CENTER_LEFT);
        Label inputLabel = new Label("Input File:");
        inputLabel.setPrefWidth(80);
        inputFileField = new TextField();
        inputFileField.setPromptText("Enter file path or browse...");
        inputFileField.setEditable(true);  // NOW EDITABLE
        inputFileField.setPrefWidth(350);
        Button inputBrowseBtn = new Button("Browse...");
        inputBrowseBtn.setOnAction(e -> browseInputFile());
        inputRow.getChildren().addAll(inputLabel, inputFileField, inputBrowseBtn);

        // Output file row
        HBox outputRow = new HBox(10);
        outputRow.setAlignment(Pos.CENTER_LEFT);
        Label outputLabel = new Label("Output File:");
        outputLabel.setPrefWidth(80);
        outputFileField = new TextField();
        outputFileField.setPromptText("Enter output path or browse...");
        outputFileField.setEditable(true);  // NOW EDITABLE
        outputFileField.setPrefWidth(350);
        Button outputBrowseBtn = new Button("Browse...");
        outputBrowseBtn.setOnAction(e -> browseOutputFile());
        outputRow.getChildren().addAll(outputLabel, outputFileField, outputBrowseBtn);

        fileSection.getChildren().addAll(inputRow, outputRow);
        return fileSection;
    }

    /**
     * Creates the password section with show/hide functionality
     */
    private VBox createPasswordSection() {
        VBox passwordSection = new VBox(10);

        HBox passwordRow = new HBox(10);
        passwordRow.setAlignment(Pos.CENTER_LEFT);
        Label passwordLabel = new Label("Password:");
        passwordLabel.setPrefWidth(80);

        // Stack password field and visible field on top of each other
        StackPane passwordStack = new StackPane();
        passwordField = new PasswordField();
        passwordField.setPromptText("Enter password");
        passwordField.setPrefWidth(350);

        passwordVisibleField = new TextField();
        passwordVisibleField.setPromptText("Enter password");
        passwordVisibleField.setPrefWidth(350);
        passwordVisibleField.setVisible(false);
        passwordVisibleField.setManaged(false);

        // Bind the text fields together
        passwordField.textProperty().bindBidirectional(passwordVisibleField.textProperty());

        passwordStack.getChildren().addAll(passwordField, passwordVisibleField);
        passwordRow.getChildren().addAll(passwordLabel, passwordStack);

        // Show password checkbox
        showPasswordCheckBox = new CheckBox("Show password");
        showPasswordCheckBox.setOnAction(e -> togglePasswordVisibility());

        passwordSection.getChildren().addAll(passwordRow, showPasswordCheckBox);
        return passwordSection;
    }

    /**
     * Updates the output field prompt based on mode
     */
    private void updateOutputFieldPrompt() {
        if (decryptRadio.isSelected()) {
            outputFileField.setPromptText("Select output directory (filename auto-restored)...");
        } else {
            outputFileField.setPromptText("Enter output path or browse...");
        }
        outputFileField.clear();
    }

    /**
     * Toggles password visibility
     */
    private void togglePasswordVisibility() {
        if (showPasswordCheckBox.isSelected()) {
            passwordVisibleField.setVisible(true);
            passwordVisibleField.setManaged(true);
            passwordField.setVisible(false);
            passwordField.setManaged(false);
        } else {
            passwordField.setVisible(true);
            passwordField.setManaged(true);
            passwordVisibleField.setVisible(false);
            passwordVisibleField.setManaged(false);
        }
    }

    /**
     * Opens file chooser for input file
     */
    private void browseInputFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select Input File");

        selectedInputFile = fileChooser.showOpenDialog(null);
        if (selectedInputFile != null) {
            inputFileField.setText(selectedInputFile.getAbsolutePath());
            log("Input file selected: " + selectedInputFile.getName());
        }
    }

    /**
     * Opens file chooser for output file (changes based on mode)
     */
    private void browseOutputFile() {
        if (decryptRadio.isSelected()) {
            // DECRYPT MODE: Only ask for directory
            javafx.stage.DirectoryChooser dirChooser = new javafx.stage.DirectoryChooser();
            dirChooser.setTitle("Select Output Directory");

            File selectedDir = dirChooser.showDialog(null);
            if (selectedDir != null) {
                outputFileField.setText(selectedDir.getAbsolutePath());
                log("Output directory selected: " + selectedDir.getName());
            }
        } else {
            // ENCRYPT MODE: Ask for full file path (full freedom)
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Select Output Location");

            selectedOutputFile = fileChooser.showSaveDialog(null);
            if (selectedOutputFile != null) {
                outputFileField.setText(selectedOutputFile.getAbsolutePath());
                log("Output file selected: " + selectedOutputFile.getName());
            }
        }
    }

    /**
     * Handles the START button click
     */
    private void handleStart() {
        // Get file paths from text fields (could be typed or browsed)
        String inputPath = inputFileField.getText().trim();
        String outputPath = outputFileField.getText().trim();

        // Validate inputs
        if (inputPath.isEmpty()) {
            showError("Please select or enter an input file path");
            return;
        }

        if (outputPath.isEmpty()) {
            showError("Please select or enter an output path");
            return;
        }

        // Validate input file exists
        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            showError("Input file does not exist:\n" + inputPath);
            return;
        }

        String password = passwordField.getText();
        if (password.isEmpty()) {
            showError("Please enter a password");
            return;
        }

        // Disable button during operation
        startButton.setDisable(true);
        logArea.clear();

        // Perform encryption or decryption
        try {
            char[] passwordChars = password.toCharArray();

            if (encryptRadio.isSelected()) {
                // ENCRYPTION MODE
                log("Starting encryption...");
                log("Input: " + inputFile.getName());
                log("Output: " + outputPath);

                FileEncryptor.encryptFile(
                        inputPath,
                        outputPath,
                        passwordChars
                );

                log("✓ Encryption completed successfully!");
                showSuccess("File encrypted successfully!");

            } else {
                // DECRYPTION MODE
                log("Starting decryption...");
                log("Input: " + inputFile.getName());

                // Validate encrypted file
                if (!FileDecryptor.isValidEncryptedFile(inputPath)) {
                    showError("Invalid encrypted file");
                    return;
                }

                // Check if output path is a directory
                File outputLocation = new File(outputPath);
                String finalOutputPath;

                if (outputLocation.isDirectory()) {
                    // Output is a directory - decrypt will auto-generate filename
                    // We'll get the original filename from decryption
                    // For now, use a temp path, then rename

                    // Decrypt to temp file first to get original filename
                    String tempPath = outputPath + File.separator + "temp_decrypt";
                    String originalFilename = FileDecryptor.decryptFile(
                            inputPath,
                            tempPath,
                            passwordChars
                    );

                    // Rename to original filename
                    finalOutputPath = outputPath + File.separator + originalFilename;
                    File tempFile = new File(tempPath);
                    File finalFile = new File(finalOutputPath);

                    // Handle if file already exists
                    if (finalFile.exists()) {
                        boolean overwrite = showConfirmation(
                                "File already exists:\n" + originalFilename +
                                        "\n\nOverwrite it?"
                        );
                        if (!overwrite) {
                            tempFile.delete();
                            log("Decryption cancelled by user");
                            return;
                        }
                        finalFile.delete();
                    }

                    tempFile.renameTo(finalFile);
                    log("Output: " + originalFilename);

                } else {
                    // Output is a full file path - use as is
                    finalOutputPath = outputPath;
                    FileDecryptor.decryptFile(
                            inputPath,
                            finalOutputPath,
                            passwordChars
                    );
                    log("Output: " + finalOutputPath);
                }

                log("✓ Decryption completed successfully!");
                showSuccess("File decrypted successfully!\nRestored as: " +
                        new File(finalOutputPath).getName());
            }

            // Clear password from memory
            Arrays.fill(passwordChars, '0');

        } catch (javax.crypto.BadPaddingException e) {
            log("✗ Decryption failed!");
            showError("Decryption failed! Possible causes:\n" +
                    "- Incorrect password\n" +
                    "- Corrupted file\n" +
                    "- File not encrypted by this tool");
        } catch (Exception e) {
            log("✗ Error: " + e.getMessage());
            showError("An error occurred: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Re-enable button
            startButton.setDisable(false);
        }
    }

    /**
     * Logs a message to the log area
     */
    private void log(String message) {
        logArea.appendText(message + "\n");
    }

    /**
     * Shows an error alert
     */
    private void showError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    /**
     * Shows a success alert
     */
    private void showSuccess(String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Success");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    /**
     * Shows a confirmation dialog
     */
    private boolean showConfirmation(String message) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Confirmation");
        alert.setHeaderText(null);
        alert.setContentText(message);

        return alert.showAndWait()
                .filter(response -> response == ButtonType.OK)
                .isPresent();
    }

    public static void main(String[] args) {
        launch(args);
    }
}