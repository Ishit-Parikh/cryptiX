import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * CryptoUtils - Utility class for cryptographic operations
 *
 * This class handles the conversion of user passwords into encryption keys.
 * Think of it as a "password processor" that transforms human-readable
 * passwords into the mathematical keys that encryption algorithms need.
 */
public class CryptoUtils {

    // AES requires 256-bit (32-byte) keys for maximum security
    private static final int KEY_LENGTH = 256;

    // Salt size: 16 bytes (128 bits) - this is the "random seasoning" we discussed
    private static final int SALT_LENGTH = 16;

    // Iteration count: how many times we apply the hash function
    // More iterations = harder for attackers to crack, but slower for us
    // 65,536 is a good balance recommended by security experts
    private static final int ITERATION_COUNT = 65536;

    // The algorithm we'll use for password hashing
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";

    /**
     * Generates a random salt for key derivation.
     *
     * Remember: The salt makes sure that even if two people use the same
     * password, they'll get different encryption keys!
     *
     * @return A byte array containing random salt data
     */
    public static byte[] generateSalt() {
        // SecureRandom is Java's cryptographically secure random number generator
        // It's much better than regular Random for security purposes
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt); // Fill the array with random bytes
        return salt;
    }

    /**
     * Derives an encryption key from a password and salt.
     *
     * This is the magic function that converts your password into a key!
     *
     * HOW IT WORKS:
     * 1. Takes your password (any length)
     * 2. Combines it with the salt
     * 3. Hashes it 65,536 times (makes it super hard to crack)
     * 4. Returns exactly 256 bits for AES encryption
     *
     * @param password The user's password as a char array (more secure than String)
     * @param salt The random salt (either newly generated or read from file)
     * @return A SecretKey object ready for encryption/decryption
     * @throws NoSuchAlgorithmException If PBKDF2 algorithm isn't available
     * @throws InvalidKeySpecException If key generation fails
     */
    public static SecretKey deriveKeyFromPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        // Step 1: Create a "key specification" with our parameters
        // Think of this as the "recipe" for creating the key
        KeySpec spec = new PBEKeySpec(
                password,           // The password
                salt,              // The random salt
                ITERATION_COUNT,   // How many times to hash
                KEY_LENGTH         // Output size (256 bits)
        );

        // Step 2: Get the key factory that knows how to make PBKDF2 keys
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);

        // Step 3: Generate the key using our recipe
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        // Step 4: Convert raw bytes into an AES-compatible key object
        // "AES" tells Java this key is specifically for AES encryption
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Convenience method: Generate salt AND derive key in one step.
     *
     * Use this when ENCRYPTING (you need a new random salt).
     *
     * @param password The user's password
     * @return An object containing both the salt and the derived key
     * @throws NoSuchAlgorithmException If algorithms aren't available
     * @throws InvalidKeySpecException If key generation fails
     */
    public static SaltAndKey generateSaltAndKey(char[] password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = generateSalt();
        SecretKey key = deriveKeyFromPassword(password, salt);
        return new SaltAndKey(salt, key);
    }

    /**
     * Helper class to return both salt and key together.
     *
     * Java methods can only return one thing, so we use this container
     * to return both the salt and the key at the same time.
     */
    public static class SaltAndKey {
        public final byte[] salt;
        public final SecretKey key;

        public SaltAndKey(byte[] salt, SecretKey key) {
            this.salt = salt;
            this.key = key;
        }
    }
}