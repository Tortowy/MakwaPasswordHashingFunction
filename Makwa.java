import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class Makwa {

    private boolean preHashing;
    private boolean postHashing;
    private int mCost;
    private int postHashingLength;
    private static BigInteger modulus;
    private static byte[] modulusBytes;
    private byte[] saltBytes;
    private final byte[] hexZero = {0x00};


    public Makwa(boolean preHashing, boolean postHashing, int mCost, int postHashLength, String mod){
        this.preHashing = preHashing;
        this.postHashing = postHashing;
        this.mCost = mCost;
        this.postHashingLength = postHashLength;
        this.modulus = Utility.ByteArrayToBigInteger(Utility.HexStringToByteArray(mod));


        byte[] modu = Utility.HexStringToByteArray(mod);
        if(modu[0] == 0){
            modu = Arrays.copyOfRange(modu,1,modu.length);
        }

        modulusBytes = modu;

        if (!CheckInitialParams()) {
            try {
                throw new Exception("Invalid initial params");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }



    public byte[] CreateHash(String password, String salt) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] passBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] saltBytes = Utility.HexStringToByteArray(salt);
        if(saltBytes[0] == 0){
            saltBytes = Arrays.copyOfRange(saltBytes,1,saltBytes.length);
        }
        this.saltBytes = saltBytes;
        return CreateHashFinal(passBytes);
    }

    public byte[] CreateHash(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] passBytes = password.getBytes(StandardCharsets.UTF_8);
        if(salt[0] == 0){
            salt = Arrays.copyOfRange(salt,1,salt.length);
        }
        this.saltBytes = salt;
        return CreateHashFinal(passBytes);
    }

    public byte[] CreateHash(byte[] password, String salt) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] saltBytes = Utility.HexStringToByteArray(salt);
        if(saltBytes[0] == 0){
            saltBytes = Arrays.copyOfRange(saltBytes,1,saltBytes.length);
        }
        this.saltBytes = saltBytes;
        return CreateHashFinal(password);
    }

    public byte[] CreateHash(byte[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException {
        if(salt[0] == 0){
            salt = Arrays.copyOfRange(salt,1,salt.length);
        }
        this.saltBytes = salt;
        return CreateHashFinal(password);
    }



    public byte[] CreateHashFinal(byte[] password) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] passBytes = password;

        int u = passBytes.length;
        int k = modulusBytes.length;

        if (preHashing){
            passBytes = KDF(passBytes, 64);
        }

        if (u > 255 || u > (k - 32)) {
            try {
                throw new Exception("invalid password length");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        byte[] uByte =  BigInteger.valueOf(u).toByteArray();
        List<byte[]> tmp = new ArrayList<>();
        tmp.add(saltBytes);
        tmp.add(passBytes);
        tmp.add(uByte);

        byte[] sb = KDF(Utility.ConcatenateByteArrays(tmp), k - 2 - u);
        List<byte[]> tmp2 = new ArrayList<>();
        tmp2.add(hexZero);
        tmp2.add(sb);
        tmp2.add(passBytes);
        tmp2.add(uByte);

        byte[] xb = Utility.ConcatenateByteArrays(tmp2);
        BigInteger x = Utility.ByteArrayToBigInteger(xb);

        for (int i = 0; i < mCost + 1; i++){
            x = x.modPow(BigInteger.valueOf(2), modulus);
        }
        byte[] Y = Utility.BigIntegerToByteArray(x);

        Y = Arrays.copyOfRange(Y,1,Y.length);
        if (postHashing){
            Y = KDF(Y, postHashingLength);
        }

        return Y;
    }

    private static byte[] KDF(byte[] data, int outLength) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");

        int r = sha256_HMAC.getMacLength();
        byte[] V = new byte[r];
        for (int i = 0; i < r; i ++) {
            V[i] = 0x01;
        }
        byte[] K = new byte[r];

        sha256_HMAC.init(new SecretKeySpec(K,"HmacSHA256"));

        sha256_HMAC.update(V);
        sha256_HMAC.update((byte)0x00);
        sha256_HMAC.update(data, 0, data.length);

        K=sha256_HMAC.doFinal();

        sha256_HMAC.init(new SecretKeySpec(K,"HmacSHA256"));

        sha256_HMAC.update(V);
        V=sha256_HMAC.doFinal();


        sha256_HMAC.update(V);
        sha256_HMAC.update((byte)0x01);
        sha256_HMAC.update(data, 0, data.length);

        K = sha256_HMAC.doFinal();

        sha256_HMAC.init(new SecretKeySpec(K,"HmacSHA256"));

        sha256_HMAC.update(V);
        V=sha256_HMAC.doFinal();


        byte[] output = new byte[outLength];
        int outOff = 0;

        while (outLength > 0) {
            sha256_HMAC.update(V);
            V=sha256_HMAC.doFinal();
            int clen = Math.min(r, outLength);
            System.arraycopy(V, 0, output, outOff, clen);
            outOff += clen;
            outLength -= clen;
        }

        return output;
    }


    private boolean CheckInitialParams(){
        if (mCost <= 0){
            return false;
        }
        else if (modulusBytes.length < 160){
            return false;
        }

        return true;
    }

    public static class Output{

        private byte[] saltBytes;
        private boolean preHash;
        private int postHashLength;
        private int workFactor;
        private byte[] hash;


        Output(byte[] salt, boolean preHash, int postHashLength, int workFactor, byte[] hash) throws Exception {

            if(salt[0] == 0){
                salt = Arrays.copyOfRange(salt,1,salt.length);
            }

            this.saltBytes = salt;
            this.preHash = preHash;
            this.postHashLength = postHashLength;
            this.workFactor = workFactor;
            this.hash = hash;
             if (postHashLength < 10) {
                throw new Exception("invalid parameters");
            } else {
                if (hash.length != postHashLength) {
                    throw new Exception("invalid parameters");
                }
            }
        }


        public void changeParameters(byte[] salt, boolean preHash, int postHashLength, int workFactor, byte[] hash){

            if(salt[0] == 0){
                salt = Arrays.copyOfRange(salt,1,salt.length);
            }

            this.saltBytes = salt;
            this.preHash = preHash;
            this.postHashLength = postHashLength;
            this.workFactor = workFactor;
            this.hash = hash;
            if (postHashLength < 10) {
                try {
                    throw new Exception("invalid parameters");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else if (hash.length != postHashLength) {
                    try {
                        throw new Exception(
                                "invalid parameters");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
            }


        }


        public String toString(){

            StringBuilder sb = new StringBuilder();
            try {
                sb.append(Base64.getEncoder().withoutPadding().encodeToString(KDF(modulusBytes,8)));
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                e.printStackTrace();
            }
            sb.append('_');
            if (preHash) {
                if (postHashLength > 0) {
                    sb.append('b');
                } else {
                    sb.append('r');
                }
            } else {
                if (postHashLength > 0) {
                    sb.append('s');
                } else {
                    sb.append('n');
                }
            }
            try {
                sb.append((char)('0' + getWFMant(workFactor)));
            } catch (Exception e) {
                e.printStackTrace();
            }

            int wl = 0;
            try {
                wl = getWFLog(workFactor);
            } catch (Exception e) {
                e.printStackTrace();
            }
            sb.append((char)('0' + (wl / 10)));
            sb.append((char)('0' + (wl % 10)));
            sb.append('_');
            sb.append(Base64.getEncoder().withoutPadding().encodeToString(saltBytes));
            sb.append('_');
            sb.append(Base64.getEncoder().withoutPadding().encodeToString(hash));
            return sb.toString();
        }
    }


    private static int getWFMant(int wf) throws Exception {

        while (wf > 3 && (wf & 1) == 0) {
            wf >>>= 1;
        }
        switch (wf) {
            case 2:
            case 3:
                return wf;
            default:
                throw new Exception("EXCEPTION - in getWFMant");
        }
    }

    private static int getWFLog(int wf) throws Exception {
        int j = 0;
        while (wf > 3 && (wf & 1) == 0) {
            wf >>>= 1;
            j ++;
        }
        switch (wf) {
            case 2:
            case 3:
                return j;
            default:
                throw new Exception("EXCEPTION - in getWFLog");
        }
    }

}
