import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;

/**
 * FileDecryptor - Handles file decryption operations
 *
 * This class takes an encrypted file and decrypts it back to its original form
 * using the same password that was used for encryption.
 *
 * CRITICAL: The decryption process mirrors encryption but in reverse!
 */
public class FileDecryptor {

    // Must match the encryption transformation exactly
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    // Salt and IV sizes must match what FileEncryptor used
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 16;

    /**
     * Decrypts a file using the provided password.
     *
     * WHAT HAPPENS STEP BY STEP:
     * 1. Read the salt from the beginning of encrypted file (first 16 bytes)
     * 2. Read the IV from encrypted file (next 16 bytes)
     * 3. Derive the decryption key using password + salt (same process as encryption!)
     * 4. Initialize decryption cipher with key + IV
     * 5. Read and decrypt the remaining file content
     * 6. Write decrypted data to output file
     *
     * @param encryptedFilePath Path to the encrypted file
     * @param outputFilePath Path where decrypted file will be saved
     * @param password The same password used during encryption
     * @throws Exception If decryption fails (wrong password, corrupted file, etc.)
     */
    public static void decryptFile(String encryptedFilePath, String outputFilePath, char[] password)
            throws Exception {

        // Open the encrypted file for reading
        try (FileInputStream fis = new FileInputStream(encryptedFilePath);
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {

            // STEP 1: Read the salt (first 16 bytes of the file)
            System.out.println("Reading encryption metadata...");
            byte[] salt = new byte[SALT_LENGTH];
            int saltBytesRead = fis.read(salt);

            // Validate we read the expected amount
            if (saltBytesRead != SALT_LENGTH) {
                throw new IOException("Invalid encrypted file: Cannot read salt");
            }

            // STEP 2: Read the IV (next 16 bytes of the file)
            byte[] iv = new byte[IV_LENGTH];
            int ivBytesRead = fis.read(iv);

            // Validate we read the expected amount
            if (ivBytesRead != IV_LENGTH) {
                throw new IOException("Invalid encrypted file: Cannot read IV");
            }

            // STEP 3: Derive the key from password + salt
            // This MUST produce the same key as during encryption if password is correct!
            System.out.println("Deriving decryption key from password...");
            SecretKey key = CryptoUtils.deriveKeyFromPassword(password, salt);

            // STEP 4: Initialize the decryption cipher
            // Notice: Cipher.DECRYPT_MODE instead of ENCRYPT_MODE
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            // STEP 5 & 6: Decrypt and write the file content
            System.out.println("Decrypting file content...");

            // CipherInputStream automatically decrypts data as we read
            // This is the opposite of CipherOutputStream we used in encryption!
            try (CipherInputStream cis = new CipherInputStream(fis, cipher)) {

                // Read and decrypt in 4KB chunks (same as encryption)
                byte[] buffer = new byte[4096];
                int bytesRead;

                // Keep reading until we've processed the entire encrypted content
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    // Each read automatically decrypts the data!
                }
            }

            System.out.println("Decryption complete! File saved to: " + outputFilePath);
        }
    }

    /**
     * Validates if a file appears to be encrypted by our tool.
     *
     * This is a simple check - it verifies the file is at least large enough
     * to contain the metadata (salt + IV = 32 bytes).
     *
     * @param filePath Path to check
     * @return true if file might be encrypted, false otherwise
     */
    public static boolean isValidEncryptedFile(String filePath) {
        File file = new File(filePath);

        // File must exist and be at least 32 bytes (salt + IV)
        if (!file.exists()) {
            System.out.println("File does not exist: " + filePath);
            return false;
        }

        if (file.length() < SALT_LENGTH + IV_LENGTH) {
            System.out.println("File too small to be encrypted: " + file.length() + " bytes");
            return false;
        }

        return true;
    }
}