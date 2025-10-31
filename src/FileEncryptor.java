import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * FileEncryptor - Handles file encryption operations
 *
 * This class takes any file (text, image, video, etc.) and encrypts it
 * using AES-256 encryption in CBC mode.
 *
 * UPDATED: Now stores original filename in encrypted file metadata
 * for automatic restoration during decryption.
 */
public class FileEncryptor {

    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_LENGTH = 16;

    /**
     * Encrypts a file using the provided password.
     *
     * NEW ENCRYPTED FILE STRUCTURE:
     * 1. Salt (16 bytes)
     * 2. IV (16 bytes)
     * 3. Filename Length (4 bytes - as integer)
     * 4. Original Filename (variable length UTF-8 bytes)
     * 5. Encrypted file content
     *
     * @param inputFilePath Path to the file you want to encrypt
     * @param outputFilePath Path where encrypted file will be saved
     * @param password The password to use for encryption
     * @throws Exception If encryption fails for any reason
     */
    public static void encryptFile(String inputFilePath, String outputFilePath, char[] password)
            throws Exception {

        // Extract original filename from input path
        File inputFile = new File(inputFilePath);
        String originalFilename = inputFile.getName();

        System.out.println("Original filename: " + originalFilename);

        // STEP 1 & 2: Generate salt and derive key from password
        System.out.println("Generating encryption key from password...");
        CryptoUtils.SaltAndKey saltAndKey = CryptoUtils.generateSaltAndKey(password);
        byte[] salt = saltAndKey.salt;
        SecretKey key = saltAndKey.key;

        // STEP 3: Generate random IV
        System.out.println("Generating initialization vector (IV)...");
        byte[] iv = generateIV();

        // STEP 4: Initialize the encryption cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        // STEP 5: Prepare filename metadata
        byte[] filenameBytes = originalFilename.getBytes(StandardCharsets.UTF_8);
        int filenameLength = filenameBytes.length;

        // Convert filename length to 4 bytes
        byte[] filenameLengthBytes = ByteBuffer.allocate(4).putInt(filenameLength).array();

        // STEP 6: Create file streams and write metadata + encrypted content
        try (FileInputStream fis = new FileInputStream(inputFilePath);
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {

            // Write metadata to the beginning of encrypted file
            System.out.println("Writing encryption metadata...");
            fos.write(salt);                    // Write salt (16 bytes)
            fos.write(iv);                      // Write IV (16 bytes)
            fos.write(filenameLengthBytes);     // Write filename length (4 bytes)
            fos.write(filenameBytes);           // Write original filename (variable bytes)

            // STEP 7: Encrypt the file content
            System.out.println("Encrypting file content...");
            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {

                // Read and encrypt in 4KB chunks
                byte[] buffer = new byte[4096];
                int bytesRead;

                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                }
            }

            System.out.println("Encryption complete! File saved to: " + outputFilePath);
        }
    }

    /**
     * Generates a random Initialization Vector (IV).
     */
    private static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Utility method to display file information.
     */
    public static void displayFileInfo(String filePath) {
        File file = new File(filePath);
        if (file.exists()) {
            System.out.println("File: " + file.getName());
            System.out.println("Size: " + file.length() + " bytes");
        } else {
            System.out.println("File not found: " + filePath);
        }
    }
}