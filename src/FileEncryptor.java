import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.SecureRandom;

/**
 * FileEncryptor - Handles file encryption operations
 *
 * This class takes any file (text, image, video, etc.) and encrypts it
 * using AES-256 encryption in CBC mode.
 */
public class FileEncryptor {

    // AES algorithm with CBC mode and PKCS5 padding
    // CBC = Cipher Block Chaining (a secure mode of operation)
    // PKCS5Padding = automatically handles files that aren't perfect multiples of block size
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    // IV size for AES is always 16 bytes (128 bits)
    private static final int IV_LENGTH = 16;

    /**
     * Encrypts a file using the provided password.
     *
     * WHAT HAPPENS STEP BY STEP:
     * 1. Generate a random salt for key derivation
     * 2. Derive encryption key from password + salt
     * 3. Generate a random IV (Initialization Vector)
     * 4. Write salt to output file (so we can decrypt later)
     * 5. Write IV to output file (so we can decrypt later)
     * 6. Read input file in chunks and encrypt each chunk
     * 7. Write encrypted chunks to output file
     *
     * @param inputFilePath Path to the file you want to encrypt
     * @param outputFilePath Path where encrypted file will be saved
     * @param password The password to use for encryption
     * @throws Exception If encryption fails for any reason
     */
    public static void encryptFile(String inputFilePath, String outputFilePath, char[] password)
            throws Exception {

        // STEP 1 & 2: Generate salt and derive key from password
        System.out.println("Generating encryption key from password...");
        CryptoUtils.SaltAndKey saltAndKey = CryptoUtils.generateSaltAndKey(password);
        byte[] salt = saltAndKey.salt;
        SecretKey key = saltAndKey.key;

        // STEP 3: Generate random IV
        // Remember: IV ensures the same file encrypted twice produces different outputs
        System.out.println("Generating initialization vector (IV)...");
        byte[] iv = generateIV();

        // STEP 4: Initialize the encryption cipher
        // Think of Cipher as the "encryption engine"
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        // STEP 5: Create file streams
        // FileInputStream reads the original file
        // FileOutputStream writes the encrypted file
        try (FileInputStream fis = new FileInputStream(inputFilePath);
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {

            // STEP 6: Write metadata (salt and IV) to the beginning of encrypted file
            // This is crucial! Without this, we can't decrypt later
            System.out.println("Writing encryption metadata...");
            fos.write(salt);  // Write salt (16 bytes)
            fos.write(iv);    // Write IV (16 bytes)

            // STEP 7: Encrypt the file content
            // CipherOutputStream automatically encrypts data as we write
            System.out.println("Encrypting file content...");
            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {

                // Read and encrypt in 4KB chunks
                // This is memory-efficient - we don't load the entire file at once!
                byte[] buffer = new byte[4096];
                int bytesRead;

                // Keep reading until we've processed the entire file
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                    // Each write automatically encrypts the data!
                }
            }

            System.out.println("Encryption complete! File saved to: " + outputFilePath);
        }
    }

    /**
     * Generates a random Initialization Vector (IV).
     *
     * The IV is the "random starting point" we discussed earlier.
     * It ensures encryption is non-deterministic (same input = different output each time).
     *
     * @return A byte array containing the random IV
     */
    private static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Utility method to display file information.
     * Helps you see the file size changes after encryption.
     *
     * @param filePath Path to the file
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
