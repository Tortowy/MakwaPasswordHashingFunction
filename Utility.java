import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

public class Utility {


    public static byte[] HexStringToByteArray(String s) {

        BigInteger tmp = new BigInteger(s,16);

        byte[] data = tmp.toByteArray();

        return data;
    }

    public static BigInteger ByteArrayToBigInteger(byte[] data) {
        return new BigInteger(data);
    }

    public static byte[] BigIntegerToByteArray(BigInteger bigInt){
        return bigInt.toByteArray();
    }


    public static byte[] ConcatenateByteArrays(List<byte[]> arrays){

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        if(arrays!=null){
            for(byte[] b: arrays){
                if(b!=null){
                    try {
                        outputStream.write( b );
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

            }
        }


        byte c[] = outputStream.toByteArray( );

        return c;

    }

    public static String BigIntegerToHexString(BigInteger bigInt){
        return bigInt.toString(16);
    }

}
