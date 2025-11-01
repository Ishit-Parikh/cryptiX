import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * FolderEncryptor - Handles folder encryption and decryption
 *
 * This class encrypts entire folders into a single encrypted file
 * and can restore the complete folder structure during decryption.
 */
public class FolderEncryptor {

    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_LENGTH = 16;
    private static final byte TYPE_FILE = 0;
    private static final byte TYPE_FOLDER = 1;

    /**
     * Progress listener interface for tracking encryption progress
     */
    public interface ProgressListener {
        void onProgress(int current, int total, String currentFile);
    }

    /**
     * Encrypts an entire folder into a single encrypted file.
     *
     * @param folderPath Path to the folder to encrypt
     * @param outputFilePath Path where encrypted file will be saved
     * @param password Encryption password
     * @param progressListener Optional progress listener (can be null)
     * @throws Exception If encryption fails
     */
    public static void encryptFolder(String folderPath, String outputFilePath,
                                     char[] password, ProgressListener progressListener)
            throws Exception {

        File folder = new File(folderPath);
        String folderName = folder.getName();

        System.out.println("Scanning folder: " + folderName);

        // Get all files in folder recursively
        List<FileEntry> files = getAllFiles(folder);
        System.out.println("Found " + files.size() + " files to encrypt");

        // Generate salt and key
        CryptoUtils.SaltAndKey saltAndKey = CryptoUtils.generateSaltAndKey(password);
        byte[] salt = saltAndKey.salt;
        SecretKey key = saltAndKey.key;

        // Generate IV
        byte[] iv = generateIV();

        // Initialize cipher
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        // Write encrypted folder file
        try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {

            // Write metadata
            fos.write(salt);                    // Salt
            fos.write(iv);                      // IV
            fos.write(TYPE_FOLDER);             // Type flag (folder)

            // Write folder name
            byte[] folderNameBytes = folderName.getBytes(StandardCharsets.UTF_8);
            fos.write(ByteBuffer.allocate(4).putInt(folderNameBytes.length).array());
            fos.write(folderNameBytes);

            // Write number of files
            fos.write(ByteBuffer.allocate(4).putInt(files.size()).array());

            // Encrypt each file
            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {

                for (int i = 0; i < files.size(); i++) {
                    FileEntry entry = files.get(i);

                    if (progressListener != null) {
                        progressListener.onProgress(i + 1, files.size(), entry.relativePath);
                    }

                    System.out.println("Encrypting: " + entry.relativePath);

                    // Write relative path
                    byte[] pathBytes = entry.relativePath.getBytes(StandardCharsets.UTF_8);
                    cos.write(ByteBuffer.allocate(4).putInt(pathBytes.length).array());
                    cos.write(pathBytes);

                    // Write file size
                    cos.write(ByteBuffer.allocate(8).putLong(entry.file.length()).array());

                    // Write encrypted file content
                    try (FileInputStream fis = new FileInputStream(entry.file)) {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = fis.read(buffer)) != -1) {
                            cos.write(buffer, 0, bytesRead);
                        }
                    }
                }
            }
        }

        System.out.println("Folder encryption complete!");
    }

    /**
     * Decrypts a folder from an encrypted file.
     *
     * @param encryptedFilePath Path to encrypted folder file
     * @param outputDirectory Directory where folder will be restored
     * @param password Decryption password
     * @param progressListener Optional progress listener (can be null)
     * @return The original folder name
     * @throws Exception If decryption fails
     */
    public static String decryptFolder(String encryptedFilePath, String outputDirectory,
                                       char[] password, ProgressListener progressListener)
            throws Exception {

        try (FileInputStream fis = new FileInputStream(encryptedFilePath)) {

            // Read salt
            byte[] salt = new byte[16];
            fis.read(salt);

            // Read IV
            byte[] iv = new byte[IV_LENGTH];
            fis.read(iv);

            // Read type flag
            int typeFlag = fis.read();
            if (typeFlag != TYPE_FOLDER) {
                throw new IOException("Not a folder encrypted file");
            }

            // Read folder name
            byte[] folderNameLengthBytes = new byte[4];
            fis.read(folderNameLengthBytes);
            int folderNameLength = ByteBuffer.wrap(folderNameLengthBytes).getInt();

            byte[] folderNameBytes = new byte[folderNameLength];
            fis.read(folderNameBytes);
            String folderName = new String(folderNameBytes, StandardCharsets.UTF_8);

            System.out.println("Restoring folder: " + folderName);

            // Read number of files
            byte[] fileCountBytes = new byte[4];
            fis.read(fileCountBytes);
            int fileCount = ByteBuffer.wrap(fileCountBytes).getInt();

            System.out.println("Files to restore: " + fileCount);

            // Derive key
            SecretKey key = CryptoUtils.deriveKeyFromPassword(password, salt);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            // Create output folder
            File outputFolder = new File(outputDirectory, folderName);
            outputFolder.mkdirs();

            // Decrypt each file
            try (javax.crypto.CipherInputStream cis = new javax.crypto.CipherInputStream(fis, cipher)) {

                for (int i = 0; i < fileCount; i++) {

                    if (progressListener != null) {
                        progressListener.onProgress(i + 1, fileCount, "Decrypting files...");
                    }

                    // Read relative path
                    byte[] pathLengthBytes = new byte[4];
                    cis.read(pathLengthBytes);
                    int pathLength = ByteBuffer.wrap(pathLengthBytes).getInt();

                    byte[] pathBytes = new byte[pathLength];
                    cis.read(pathBytes);
                    String relativePath = new String(pathBytes, StandardCharsets.UTF_8);

                    // Read file size
                    byte[] fileSizeBytes = new byte[8];
                    cis.read(fileSizeBytes);
                    long fileSize = ByteBuffer.wrap(fileSizeBytes).getLong();

                    System.out.println("Decrypting: " + relativePath + " (" + fileSize + " bytes)");

                    // Create output file
                    File outputFile = new File(outputFolder, relativePath);
                    outputFile.getParentFile().mkdirs();

                    // Write decrypted content
                    try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                        byte[] buffer = new byte[4096];
                        long remaining = fileSize;

                        while (remaining > 0) {
                            int toRead = (int) Math.min(buffer.length, remaining);
                            int bytesRead = cis.read(buffer, 0, toRead);
                            if (bytesRead == -1) break;
                            fos.write(buffer, 0, bytesRead);
                            remaining -= bytesRead;
                        }
                    }
                }
            }

            System.out.println("Folder decryption complete!");
            return folderName;
        }
    }

    /**
     * Checks if an encrypted file is a folder or single file.
     */
    public static boolean isEncryptedFolder(String encryptedFilePath) throws IOException {
        try (FileInputStream fis = new FileInputStream(encryptedFilePath)) {
            // Skip salt and IV
            fis.skip(16 + 16);

            // Read type flag
            int typeFlag = fis.read();
            return typeFlag == TYPE_FOLDER;
        }
    }

    /**
     * Gets all files in a folder recursively.
     */
    private static List<FileEntry> getAllFiles(File folder) throws IOException {
        List<FileEntry> files = new ArrayList<>();
        Path basePath = folder.toPath();

        try (Stream<Path> paths = Files.walk(basePath)) {
            List<Path> filePaths = paths
                    .filter(Files::isRegularFile)
                    .collect(Collectors.toList());

            for (Path path : filePaths) {
                String relativePath = basePath.relativize(path).toString();
                files.add(new FileEntry(path.toFile(), relativePath));
            }
        }

        return files;
    }

    /**
     * Generates a random IV.
     */
    private static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Helper class to store file and its relative path.
     */
    private static class FileEntry {
        File file;
        String relativePath;

        FileEntry(File file, String relativePath) {
            this.file = file;
            this.relativePath = relativePath;
        }
    }
}