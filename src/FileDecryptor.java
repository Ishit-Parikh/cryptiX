import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * FileDecryptor - Handles file decryption operations
 *
 * This class takes an encrypted file and decrypts it back to its original form
 * using the same password that was used for encryption.
 *
 * UPDATED: Now extracts original filename from encrypted file metadata
 * for automatic restoration.
 */
public class FileDecryptor {

    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 16;
    private static final int FILENAME_LENGTH_BYTES = 4;

    /**
     * Decrypts a file using the provided password.
     *
     * READS ENCRYPTED FILE STRUCTURE:
     * 1. Salt (16 bytes)
     * 2. IV (16 bytes)
     * 3. Filename Length (4 bytes)
     * 4. Original Filename (variable length)
     * 5. Encrypted content
     *
     * @param encryptedFilePath Path to the encrypted file
     * @param outputFilePath Path where decrypted file will be saved
     * @param password The same password used during encryption
     * @return The original filename extracted from metadata
     * @throws Exception If decryption fails (wrong password, corrupted file, etc.)
     */
    public static String decryptFile(String encryptedFilePath, String outputFilePath, char[] password)
            throws Exception {

        String originalFilename = null;

        // Open the encrypted file for reading
        try (FileInputStream fis = new FileInputStream(encryptedFilePath);
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {

            // STEP 1: Read the salt (first 16 bytes)
            System.out.println("Reading encryption metadata...");
            byte[] salt = new byte[SALT_LENGTH];
            int saltBytesRead = fis.read(salt);

            if (saltBytesRead != SALT_LENGTH) {
                throw new IOException("Invalid encrypted file: Cannot read salt");
            }

            // STEP 2: Read the IV (next 16 bytes)
            byte[] iv = new byte[IV_LENGTH];
            int ivBytesRead = fis.read(iv);

            if (ivBytesRead != IV_LENGTH) {
                throw new IOException("Invalid encrypted file: Cannot read IV");
            }

            // STEP 3: Read the filename length (next 4 bytes)
            byte[] filenameLengthBytes = new byte[FILENAME_LENGTH_BYTES];
            int lengthBytesRead = fis.read(filenameLengthBytes);

            if (lengthBytesRead != FILENAME_LENGTH_BYTES) {
                throw new IOException("Invalid encrypted file: Cannot read filename length");
            }

            int filenameLength = ByteBuffer.wrap(filenameLengthBytes).getInt();

            // Validate filename length is reasonable (prevent attacks)
            if (filenameLength < 1 || filenameLength > 1000) {
                throw new IOException("Invalid encrypted file: Filename length out of bounds");
            }

            // STEP 4: Read the original filename
            byte[] filenameBytes = new byte[filenameLength];
            int filenameBytesRead = fis.read(filenameBytes);

            if (filenameBytesRead != filenameLength) {
                throw new IOException("Invalid encrypted file: Cannot read filename");
            }

            originalFilename = new String(filenameBytes, StandardCharsets.UTF_8);
            System.out.println("Original filename: " + originalFilename);

            // STEP 5: Derive the key from password + salt
            System.out.println("Deriving decryption key from password...");
            SecretKey key = CryptoUtils.deriveKeyFromPassword(password, salt);

            // STEP 6: Initialize the decryption cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            // STEP 7: Decrypt and write the file content
            System.out.println("Decrypting file content...");

            try (CipherInputStream cis = new CipherInputStream(fis, cipher)) {

                byte[] buffer = new byte[4096];
                int bytesRead;

                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
            }

            System.out.println("Decryption complete! File saved to: " + outputFilePath);
        }

        return originalFilename;
    }

    /**
     * Validates if a file appears to be encrypted by our tool.
     *
     * Now checks for minimum size including filename metadata.
     */
    public static boolean isValidEncryptedFile(String filePath) {
        File file = new File(filePath);

        // File must exist and be at least 36 bytes (salt + IV + filename length + 1 byte filename)
        if (!file.exists()) {
            System.out.println("File does not exist: " + filePath);
            return false;
        }

        int minSize = SALT_LENGTH + IV_LENGTH + FILENAME_LENGTH_BYTES + 1;
        if (file.length() < minSize) {
            System.out.println("File too small to be encrypted: " + file.length() + " bytes");
            return false;
        }

        return true;
    }
}