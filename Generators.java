import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

public class Generators {

    public static BigInteger GenerateRSAModulus(int byteLength) {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        kpg.initialize(byteLength);
        PrivateKey priv = kpg.generateKeyPair().getPrivate();
        KeyFactory keyFac = null;
        try {
            keyFac = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        RSAPrivateCrtKeySpec pkSpec = null;
        try {
            pkSpec = keyFac.getKeySpec(priv, RSAPrivateCrtKeySpec.class);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        BigInteger bigInteger = pkSpec.getModulus();
        return bigInteger;
    }
}
