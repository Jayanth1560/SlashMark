import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class PasswordGenerator {
    // Enhanced character sets for better password complexity
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String NUMBERS = "0123456789";
    private static final String SPECIAL = "!@#$%^&*()-_+=<>?/";
    
    private static final SecureRandom random = new SecureRandom();
    private static SecretKey secretKey;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    public PasswordGenerator() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Increased to 256-bit key for better security
        secretKey = keyGen.generateKey();
    }

    // Enhanced password generation with guaranteed character types
    public String generatePassword(int length) {
        if (length < 12) length = 12; // Minimum secure length
        
        StringBuilder password = new StringBuilder();
        // Ensure at least one of each character type
        password.append(UPPERCASE.charAt(random.nextInt(UPPERCASE.length())));
        password.append(LOWERCASE.charAt(random.nextInt(LOWERCASE.length())));
        password.append(NUMBERS.charAt(random.nextInt(NUMBERS.length())));
        password.append(SPECIAL.charAt(random.nextInt(SPECIAL.length())));
        
        // Fill the rest randomly
        String allChars = UPPERCASE + LOWERCASE + NUMBERS + SPECIAL;
        for (int i = password.length(); i < length; i++) {
            password.append(allChars.charAt(random.nextInt(allChars.length())));
        }
        
        // Shuffle the password
        char[] passwordArray = password.toString().toCharArray();
        for (int i = passwordArray.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = passwordArray[i];
            passwordArray[i] = passwordArray[j];
            passwordArray[j] = temp;
        }
        
        return new String(passwordArray);
    }

    // Enhanced encryption using AES/GCM
    public String encryptPassword(String password) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        byte[] encryptedBytes = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
        
        return Base64.getEncoder().encodeToString(combined);
    }

    // Enhanced decryption using AES/GCM
    public String decryptPassword(String encryptedPassword) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encryptedPassword);
        
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] cipherText = new byte[decoded.length - GCM_IV_LENGTH];
        
        System.arraycopy(decoded, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(decoded, GCM_IV_LENGTH, cipherText, 0, cipherText.length);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        
        byte[] decryptedBytes = cipher.doFinal(cipherText);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            PasswordGenerator generator = new PasswordGenerator();

            // Generate a password
            int passwordLength = 12;
            String generatedPassword = generator.generatePassword(passwordLength);
            System.out.println("Generated Password: " + generatedPassword);

            // Encrypt the password
            String encryptedPassword = generator.encryptPassword(generatedPassword);
            System.out.println("Encrypted Password: " + encryptedPassword);

            // Decrypt the password
            String decryptedPassword = generator.decryptPassword(encryptedPassword);
            System.out.println("Decrypted Password: " + decryptedPassword);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}