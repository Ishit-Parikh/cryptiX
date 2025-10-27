import java.io.Console;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Main - Entry point for the File Encryption & Decryption Tool
 *
 * This class provides a command-line interface for users to:
 * 1. Encrypt files with a password
 * 2. Decrypt files with a password
 *
 * USAGE:
 *   java Main
 *   Then follow the interactive prompts
 */
public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Display welcome message
        System.out.println("=====================================");
        System.out.println("  File Encryption & Decryption Tool  ");
        System.out.println("=====================================");
        System.out.println();

        try {
            // STEP 1: Ask user what they want to do
            System.out.println("What would you like to do?");
            System.out.println("1. Encrypt a file");
            System.out.println("2. Decrypt a file");
            System.out.print("Enter your choice (1 or 2): ");

            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume the newline

            if (choice == 1) {
                // ENCRYPTION PATH
                encryptFile(scanner);
            } else if (choice == 2) {
                // DECRYPTION PATH
                decryptFile(scanner);
            } else {
                System.out.println("Invalid choice. Please run the program again.");
            }

        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }

    /**
     * Handles the file encryption process.
     * Prompts user for input file, output file, and password.
     */
    private static void encryptFile(Scanner scanner) throws Exception {
        System.out.println("\n--- FILE ENCRYPTION ---");

        // Get input file path
        System.out.print("Enter the path of the file to encrypt: ");
        String inputFile = scanner.nextLine().trim();

        // Get output file path
        System.out.print("Enter the path for the encrypted file (e.g., output.enc): ");
        String outputFile = scanner.nextLine().trim();

        // Get password
        char[] password = getPassword(scanner, "Enter encryption password: ");

        // Confirm password to avoid typos
        char[] confirmPassword = getPassword(scanner, "Confirm password: ");

        // Check if passwords match
        if (!Arrays.equals(password, confirmPassword)) {
            System.out.println("Passwords do not match! Encryption cancelled.");
            // Clear passwords from memory for security
            Arrays.fill(password, '0');
            Arrays.fill(confirmPassword, '0');
            return;
        }

        // Clear the confirmation password (we only need one copy)
        Arrays.fill(confirmPassword, '0');

        // Display file info before encryption
        System.out.println("\nOriginal file:");
        FileEncryptor.displayFileInfo(inputFile);

        // Perform encryption
        System.out.println("\nStarting encryption...");
        FileEncryptor.encryptFile(inputFile, outputFile, password);

        // Display encrypted file info
        System.out.println("\nEncrypted file:");
        FileEncryptor.displayFileInfo(outputFile);

        // Clear password from memory
        Arrays.fill(password, '0');

        System.out.println("\n✓ Encryption successful!");
    }

    /**
     * Handles the file decryption process.
     * Prompts user for encrypted file, output file, and password.
     */
    private static void decryptFile(Scanner scanner) throws Exception {
        System.out.println("\n--- FILE DECRYPTION ---");

        // Get encrypted file path
        System.out.print("Enter the path of the encrypted file: ");
        String encryptedFile = scanner.nextLine().trim();

        // Validate it looks like an encrypted file
        if (!FileDecryptor.isValidEncryptedFile(encryptedFile)) {
            System.out.println("Invalid encrypted file. Decryption cancelled.");
            return;
        }

        // Get output file path
        System.out.print("Enter the path for the decrypted file: ");
        String outputFile = scanner.nextLine().trim();

        // Get password
        char[] password = getPassword(scanner, "Enter decryption password: ");

        // Display encrypted file info
        System.out.println("\nEncrypted file:");
        FileEncryptor.displayFileInfo(encryptedFile);

        // Perform decryption
        System.out.println("\nStarting decryption...");
        try {
            FileDecryptor.decryptFile(encryptedFile, outputFile, password);

            // Display decrypted file info
            System.out.println("\nDecrypted file:");
            FileEncryptor.displayFileInfo(outputFile);

            System.out.println("\n✓ Decryption successful!");

        } catch (javax.crypto.BadPaddingException e) {
            // This usually means wrong password!
            System.err.println("\n✗ Decryption failed!");
            System.err.println("Possible causes:");
            System.err.println("  - Incorrect password");
            System.err.println("  - Corrupted encrypted file");
            System.err.println("  - File was not encrypted by this tool");
        } finally {
            // Always clear password from memory
            Arrays.fill(password, '0');
        }
    }

    /**
     * Safely reads a password from the user.
     *
     * SECURITY NOTE: We try to use Console for hidden input (password won't show on screen).
     * If Console is unavailable (like when running in some IDEs), we fall back to Scanner.
     *
     * @param scanner Scanner for fallback input
     * @param prompt The prompt to display
     * @return Password as char array (more secure than String)
     */
    private static char[] getPassword(Scanner scanner, String prompt) {
        Console console = System.console();

        if (console != null) {
            // Console available - password will be hidden
            return console.readPassword(prompt);
        } else {
            // Console not available - password will be visible
            // This happens in some IDEs
            System.out.print(prompt + "(WARNING: Password will be visible) ");
            String passwordStr = scanner.nextLine();
            return passwordStr.toCharArray();
        }
    }
}