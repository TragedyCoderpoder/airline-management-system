package airlinemanagement;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import java.util.Base64;

public class RSAUtil {

    private static final String PUBLIC_KEY_FILE = "public.key";
    private static final String PRIVATE_KEY_FILE = "private.key";
    private static KeyPair keyPair;

    static {
        try {
            File pubFile = new File(PUBLIC_KEY_FILE);
            File privFile = new File(PRIVATE_KEY_FILE);

            if (pubFile.exists() && privFile.exists()) {
                keyPair = loadKeyPair();
            } else {
                keyPair = generateKeyPair();
                saveKeyPair(keyPair);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static void saveKeyPair(KeyPair keyPair) throws Exception {
        Files.write(new File(PUBLIC_KEY_FILE).toPath(), keyPair.getPublic().getEncoded());
        Files.write(new File(PRIVATE_KEY_FILE).toPath(), keyPair.getPrivate().getEncoded());
    }

    private static KeyPair loadKeyPair() throws Exception {
        byte[] publicBytes = Files.readAllBytes(new File(PUBLIC_KEY_FILE).toPath());
        byte[] privateBytes = Files.readAllBytes(new File(PRIVATE_KEY_FILE).toPath());

        KeyFactory factory = KeyFactory.getInstance("RSA");

        PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(publicBytes));
        PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));

        return new KeyPair(publicKey, privateKey);
    }

    public static String encrypt(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    public static String decrypt(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }
}
