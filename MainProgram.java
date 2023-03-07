import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class MainProgram {

    public static void main(String[] args) throws Exception {

        //test vector - expected hash value C9-CE-A0-E6-EF-09-39-3A-B1-71-0A-08

        Makwa makwaTestVector = new Makwa(false, true, 4096, 12,"C22C40BBD056BB213AAD7C830519101AB926AE18E3E9FC9699C806E0AE5C259414A01AC1D52E873EC08046A68E344C8D74A508952842EF0F03F71A6EDC077FAA14899A79F83C3AE136F774FA6EB88F1D1AEA5EA02FC0CCAF96E2CE86F3490F4993B4B566C0079641472DEFC14BECCF48984A7946F1441EA144EA4C802A457550BA3DF0F14C090A75FE9E6A77CF0BE98B71D56251A86943E719D27865A489566C1DC57FCDEFACA6AB043F8E13F6C0BE7B39C92DA86E1D87477A189E73CE8E311D3D51361F8B00249FB3D8435607B14A1E70170F9AF36784110A3F2E67428FC18FB013B30FE6782AECB4428D7C8E354A0FBD061B01917C727ABEE0FE3FD3CEF761");
        byte[] salt = Utility.HexStringToByteArray("C72703C22A96D9992F3DEA876497E392");
        byte[] passwordBytes = Utility.HexStringToByteArray("4765676F206265736877616A692761616B656E20617765206D616B77613B206F6E7A61616D206E616E69697A61616E697A692E");

        String passwordText = "Gego beshwaji'aaken awe makwa; onzaam naniizaanizi."; //Don't get friendly with the bear; he's too dangerous.

        byte[] testHash1 = makwaTestVector.CreateHash(passwordBytes, salt);
        Makwa.Output output = new Makwa.Output(salt,false,12,4096,testHash1);

        System.out.println();
        System.out.println("TEST VECTORS:");
        System.out.println();


        System.out.println("Hash created from PasswordBytes and saltByteArray:");
        System.out.println("preHashing: OFF");
        System.out.println("postHashing: ON");
        System.out.println("Hash text: " + output);

        System.out.println();

        byte[] testHash2 = makwaTestVector.CreateHash(passwordText,salt);
        output.changeParameters(salt,false,12,4096,testHash2);

        System.out.println("Hash created from PasswordText and saltByteArray:");
        System.out.println("preHashing: OFF");
        System.out.println("postHashing: ON");
        System.out.println("Hash hex:");
        for(byte b :testHash2){
            int tmp = b & 0xFF;
            System.out.print(Integer.toHexString(tmp) + "-");
        }


        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println();

        byte[] exampleHash = makwaTestVector.CreateHash(passwordText, "C72703C22A96D9992F3DEA876497E392");
        System.out.println("Hash created from PasswordText and saltText:");
        System.out.println("preHashing: OFF");
        System.out.println("postHashing: ON");
        System.out.println("Hash hex:");

        for(byte b :exampleHash){
            int tmp = b & 0xFF;
            System.out.print(Integer.toHexString(tmp) + "-");
        }

        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println();


        byte[] exampleHash2 = makwaTestVector.CreateHash(passwordBytes,"C72703C22A96D9992F3DEA876497E392");
        System.out.println("Hash created from PasswordByteArray and saltText:");
        System.out.println("preHashing: OFF");
        System.out.println("postHashing: ON");
        System.out.println("Hash hex:");
        for(byte b :exampleHash2){
            int tmp = b & 0xFF;
            System.out.print(Integer.toHexString(tmp) + "-");
        }

        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println();

        // GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR
        // GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR
        // GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR -- GENERATOR


        System.out.println();
        System.out.println("RANDOM GENERATE:");
        System.out.println();

        String mod2048 = Utility.BigIntegerToHexString(Generators.GenerateRSAModulus(2048));
        String salt512 = Utility.BigIntegerToHexString(Generators.GenerateRSAModulus(512));

        Makwa makwaExampleGenerator = new Makwa(true, true, 4096, 32, mod2048);
        byte[] exampleHashGenerator = makwaExampleGenerator.CreateHash(passwordText, salt512);

        System.out.println("2048bit mod, 512bit salt random generated:");
        System.out.println("preHashing: ON");
        System.out.println("postHashing: ON");
        System.out.println("Hash text: " +  Base64.getEncoder().encodeToString(exampleHashGenerator));
        System.out.println("Hash hex: ");

        for(byte b :exampleHashGenerator){
            int tmp = b & 0xFF;
            System.out.print(Integer.toHexString(tmp) + "-");
        }

        System.out.println();
        System.out.println();


        Makwa makwaExampleGeneratorPostOff = new Makwa(true, false, 4096, 32, mod2048);
        byte[] exampleHashGeneratorPostOff = makwaExampleGeneratorPostOff.CreateHash(passwordText, salt512);
        System.out.println("2048bit mod, 512bit salt random generated:");
        System.out.println("preHashing: ON");
        System.out.println("postHashing: OFF");
        System.out.println("Hash text: " +  Base64.getEncoder().encodeToString(exampleHashGeneratorPostOff));
        System.out.println("Hash hex: ");

        for(byte b :exampleHashGeneratorPostOff){
            int tmp = b & 0xFF;
            System.out.print(Integer.toHexString(tmp) + "-");
        }


        System.out.println();
        System.out.println();



        Makwa makwaExampleGeneratorPreOff = new Makwa(false, true, 4096, 32, mod2048);
        byte[] exampleHashGeneratorPreOff = makwaExampleGeneratorPreOff.CreateHash(passwordText, salt512);
        System.out.println("2048bit mod, 512bit salt random generated:");
        System.out.println("preHashing: OFF");
        System.out.println("postHashing: ON");
        System.out.println("Hash text: " +  Base64.getEncoder().encodeToString(exampleHashGeneratorPreOff));
        System.out.println("Hash hex: ");

        for(byte b :exampleHashGeneratorPreOff){
            int tmp = b & 0xFF;
            System.out.print(Integer.toHexString(tmp) + "-");
        }



        System.out.println();
        System.out.println();



        Makwa makwaExampleGeneratorPreOffPostOff = new Makwa(false, false, 4096, 32, mod2048);
        byte[] exampleHashGeneratorPreOffPostOff = makwaExampleGeneratorPreOffPostOff.CreateHash(passwordText, salt512);
        System.out.println("2048bit mod, 512bit salt random generated:");
        System.out.println("preHashing: OFF");
        System.out.println("postHashing: OFF");
        System.out.println("Hash text: " +  Base64.getEncoder().encodeToString(exampleHashGeneratorPreOffPostOff));
        System.out.println("Hash hex: ");

        for(byte b :exampleHashGeneratorPreOffPostOff){
            int tmp = b & 0xFF;
            System.out.print(Integer.toHexString(tmp) + "-");
        }





        System.out.println();
        System.out.println();
        System.out.println();
        System.out.println();




        String mod4096 = Utility.BigIntegerToHexString(Generators.GenerateRSAModulus(4096));
        String salt1024 = Utility.BigIntegerToHexString(Generators.GenerateRSAModulus(1024));
        Makwa makwaExampleGenerator2 = new Makwa(true, true, 4096, 32, mod4096);
        byte[] exampleHashGenerator2 = makwaExampleGenerator2.CreateHash(passwordText, salt1024);
        Makwa.Output outputHashGenerator2 = new Makwa.Output(salt,true,32,4096,exampleHashGenerator2);
        System.out.println("4096bit mod, 1024bit salt random generated:");
        System.out.println("preHashing: ON");
        System.out.println("postHashing: ON");
        System.out.println("Hash text: " +  outputHashGenerator2);
        System.out.println("Hash hex: ");



        for(byte b :exampleHashGenerator2){
            int tmp = b & 0xFF;
            System.out.print(Integer.toHexString(tmp) + "-");
        }

        System.out.println();
        System.out.println();
        System.out.println();







    }



}
