import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.DirectoryChooser;
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
    private ProgressBar progressBar;
    private Label progressLabel;
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

        // Progress bar
        progressBar = new ProgressBar(0);
        progressBar.setPrefWidth(400);
        progressBar.setVisible(false);

        progressLabel = new Label();
        progressLabel.setVisible(false);

        VBox progressBox = new VBox(5, progressBar, progressLabel);
        progressBox.setAlignment(Pos.CENTER);

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
                progressBox,
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
     * Opens unified file/folder chooser for input
     */
    private void browseInputFile() {
        if (encryptRadio.isSelected()) {
            // ENCRYPT MODE: Show custom chooser with both options
            Stage chooserStage = new Stage();
            chooserStage.setTitle("Select Input");

            VBox layout = new VBox(15);
            layout.setPadding(new Insets(20));
            layout.setAlignment(Pos.CENTER);

            Label promptLabel = new Label("What would you like to encrypt?");
            promptLabel.setStyle("-fx-font-size: 14px; -fx-font-weight: bold;");

            Button selectFileBtn = new Button("Select File");
            selectFileBtn.setPrefWidth(200);
            selectFileBtn.setOnAction(e -> {
                chooserStage.close();
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Select File to Encrypt");

                File file = fileChooser.showOpenDialog(null);
                if (file != null) {
                    selectedInputFile = file;
                    inputFileField.setText(file.getAbsolutePath());
                    log("Input file selected: " + file.getName());
                }
            });

            Button selectFolderBtn = new Button("Select Folder");
            selectFolderBtn.setPrefWidth(200);
            selectFolderBtn.setOnAction(e -> {
                chooserStage.close();
                DirectoryChooser dirChooser = new DirectoryChooser();
                dirChooser.setTitle("Select Folder to Encrypt");

                File folder = dirChooser.showDialog(null);
                if (folder != null) {
                    selectedInputFile = folder;
                    inputFileField.setText(folder.getAbsolutePath());
                    log("Input folder selected: " + folder.getName());
                }
            });

            Button cancelBtn = new Button("Cancel");
            cancelBtn.setPrefWidth(200);
            cancelBtn.setOnAction(e -> chooserStage.close());

            layout.getChildren().addAll(promptLabel, selectFileBtn, selectFolderBtn, cancelBtn);

            Scene scene = new Scene(layout, 300, 220);
            chooserStage.setScene(scene);
            chooserStage.showAndWait();

        } else {
            // DECRYPT MODE: Only files
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Select Encrypted File");

            selectedInputFile = fileChooser.showOpenDialog(null);
            if (selectedInputFile != null) {
                inputFileField.setText(selectedInputFile.getAbsolutePath());
                log("Encrypted file selected: " + selectedInputFile.getName());
            }
        }
    }

    /**
     * Opens file chooser for output file (changes based on mode)
     */
    private void browseOutputFile() {
        if (decryptRadio.isSelected()) {
            // DECRYPT MODE: Only ask for directory
            DirectoryChooser dirChooser = new DirectoryChooser();
            dirChooser.setTitle("Select Output Directory");

            File selectedDir = dirChooser.showDialog(null);
            if (selectedDir != null) {
                outputFileField.setText(selectedDir.getAbsolutePath());
                log("Output directory selected: " + selectedDir.getName());
            }
        } else {
            // ENCRYPT MODE: Ask for output file location
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save Encrypted File As");

            // Auto-suggest filename based on input if available
            if (selectedInputFile != null) {
                fileChooser.setInitialFileName(selectedInputFile.getName() + ".enc");
            }

            File selectedFile = fileChooser.showSaveDialog(null);
            if (selectedFile != null) {
                outputFileField.setText(selectedFile.getAbsolutePath());
                log("Output file location: " + selectedFile.getName());
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
            showError("Input file/folder does not exist:\n" + inputPath);
            return;
        }

        // Auto-generate output filename if only directory provided (for encryption)
        if (encryptRadio.isSelected()) {
            File outputFile = new File(outputPath);
            if (outputFile.isDirectory()) {
                // User only provided directory - auto-generate filename
                outputPath = outputPath + File.separator + inputFile.getName() + ".enc";
                log("Auto-generated output filename: " + new File(outputPath).getName());
            }
        }

        String password = passwordField.getText();
        if (password.isEmpty()) {
            showError("Please enter a password");
            return;
        }

        // Make variables final for lambda
        final String finalOutputPath = outputPath;
        final String finalPassword = password;

        // Disable button during operation
        startButton.setDisable(true);
        logArea.clear();
        progressBar.setVisible(true);
        progressLabel.setVisible(true);
        progressBar.setProgress(0);

        // Run encryption/decryption in background thread
        new Thread(() -> {
            try {
                performOperation(inputFile, finalOutputPath, finalPassword);
            } finally {
                Platform.runLater(() -> {
                    startButton.setDisable(false);
                    progressBar.setVisible(false);
                    progressLabel.setVisible(false);
                });
            }
        }).start();
    }

    /**
     * Performs the actual encryption/decryption operation
     */
    private void performOperation(File inputFile, String outputPath, String password) {
        // Perform encryption or decryption
        try {
            char[] passwordChars = password.toCharArray();

            if (encryptRadio.isSelected()) {
                // ENCRYPTION MODE
                log("Starting encryption...");

                if (inputFile.isDirectory()) {
                    // FOLDER ENCRYPTION
                    log("Input: Folder - " + inputFile.getName());
                    log("Output: " + outputPath);

                    FolderEncryptor.encryptFolder(
                            inputFile.getAbsolutePath(),
                            outputPath,
                            passwordChars,
                            (current, total, currentFile) -> {
                                Platform.runLater(() -> {
                                    double progress = (double) current / total;
                                    progressBar.setProgress(progress);
                                    progressLabel.setText("Encrypting file " + current + " of " + total +
                                            ": " + currentFile);
                                });
                            }
                    );

                    log("✓ Folder encryption completed successfully!");
                    Platform.runLater(() -> showSuccess("Folder encrypted successfully!"));

                } else {
                    // SINGLE FILE ENCRYPTION
                    log("Input: File - " + inputFile.getName());
                    log("Output: " + outputPath);

                    Platform.runLater(() -> {
                        progressBar.setProgress(-1); // Indeterminate
                        progressLabel.setText("Encrypting file...");
                    });

                    FileEncryptor.encryptFile(
                            inputFile.getAbsolutePath(),
                            outputPath,
                            passwordChars
                    );

                    log("✓ Encryption completed successfully!");
                    Platform.runLater(() -> showSuccess("File encrypted successfully!"));
                }

            } else {
                // DECRYPTION MODE
                log("Starting decryption...");
                log("Input: " + inputFile.getName());

                // Validate encrypted file
                if (!FileDecryptor.isValidEncryptedFile(inputFile.getAbsolutePath())) {
                    Platform.runLater(() -> showError("Invalid encrypted file"));
                    return;
                }

                // Check if it's a folder or file
                boolean isFolder = FolderEncryptor.isEncryptedFolder(inputFile.getAbsolutePath());

                if (isFolder) {
                    // FOLDER DECRYPTION
                    log("Detected: Encrypted folder");

                    // Output path should be a directory
                    File outputLocation = new File(outputPath);
                    if (!outputLocation.isDirectory()) {
                        outputLocation = outputLocation.getParentFile();
                    }

                    String folderName = FolderEncryptor.decryptFolder(
                            inputFile.getAbsolutePath(),
                            outputLocation.getAbsolutePath(),
                            passwordChars,
                            (current, total, currentFile) -> {
                                Platform.runLater(() -> {
                                    double progress = (double) current / total;
                                    progressBar.setProgress(progress);
                                    progressLabel.setText("Decrypting file " + current + " of " + total);
                                });
                            }
                    );

                    log("Output: Folder restored - " + folderName);
                    log("✓ Folder decryption completed successfully!");
                    Platform.runLater(() -> showSuccess("Folder decrypted successfully!\nRestored as: " + folderName));

                } else {
                    // SINGLE FILE DECRYPTION
                    log("Detected: Encrypted file");

                    Platform.runLater(() -> {
                        progressBar.setProgress(-1); // Indeterminate
                        progressLabel.setText("Decrypting file...");
                    });

                    // Check if output path is a directory
                    File outputLocation = new File(outputPath);
                    String finalOutputPath;

                    if (outputLocation.isDirectory()) {
                        // Output is a directory - decrypt will auto-generate filename
                        String tempPath = outputPath + File.separator + "temp_decrypt";
                        String originalFilename = FileDecryptor.decryptFile(
                                inputFile.getAbsolutePath(),
                                tempPath,
                                passwordChars
                        );

                        // Rename to original filename
                        finalOutputPath = outputPath + File.separator + originalFilename;
                        File tempFile = new File(tempPath);
                        File finalFile = new File(finalOutputPath);

                        // Handle if file already exists
                        if (finalFile.exists()) {
                            boolean[] overwrite = {false};
                            Platform.runLater(() -> {
                                overwrite[0] = showConfirmation(
                                        "File already exists:\n" + originalFilename +
                                                "\n\nOverwrite it?"
                                );
                            });

                            // Wait for user response
                            Thread.sleep(100);

                            if (!overwrite[0]) {
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
                                inputFile.getAbsolutePath(),
                                finalOutputPath,
                                passwordChars
                        );
                        log("Output: " + finalOutputPath);
                    }

                    log("✓ Decryption completed successfully!");
                    Platform.runLater(() -> showSuccess("File decrypted successfully!\nRestored as: " +
                            new File(finalOutputPath).getName()));
                }
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