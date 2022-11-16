package isp.secrecy;

import fri.isp.Agent;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.util.*;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of th last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {

    public static void main(String[] args) throws Exception {

        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);

        //Generate key
        Random rand = new Random();
        int upperbound = 999;
        int lowerbound = 100;
        int int_random = rand.nextInt(upperbound-lowerbound)+lowerbound;
        String Intit_key = "00000"+ int_random;
        System.out.println("My key: " + Intit_key);
        byte[] Raw_key_value = Intit_key.getBytes();
        DESKeySpec dks =  new DESKeySpec(Raw_key_value);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey Key = skf.generateSecret(dks);

        //encrypt text
        final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        final byte[] pt = message.getBytes();
        encrypt.init(Cipher.ENCRYPT_MODE,Key);
        final byte[] ct = encrypt.doFinal(pt);

        System.out.println("[CT] " + ct);

        //final Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //decrypt.init(Cipher.DECRYPT_MODE, Key);
        //final byte[] dt = decrypt.doFinal(cipherText);
        //System.out.println("[Test encryption:] " + new String(dt));
        // TODO

        bruteForceKey(ct,message);

    }

    public static String padLeftZeros(String inputString, int length) {
        if (inputString.length() >= length) {
            return inputString;
        }
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length - inputString.length()) {
            sb.append('0');
        }
        sb.append(inputString);

        return sb.toString();
    }


    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {

        for(int i=0;i<1000;i++){

            //Generate key brute force
            String temp;
            temp = padLeftZeros(Integer.toString(i),8);
            System.out.println(temp);
            String initkey =  temp;
            byte[] Rawkey = initkey.getBytes();
            DESKeySpec dks =  new DESKeySpec(Rawkey);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            SecretKey key = skf.generateSecret(dks);

            //use key to encrypt message
            final Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
            encrypt.init(Cipher.ENCRYPT_MODE,key);
            final byte[] pt = message.getBytes();
            final byte[] cipherText = encrypt.doFinal(pt);

            System.out.println(Agent.hex(cipherText));
            System.out.println(Agent.hex(ct));

            //check if cipherText is the same as ct
            if (Agent.hex(cipherText).equals(Agent.hex(ct))){
                System.out.println("We got the key");
                System.out.println(key);
                System.out.println(temp);
                final Cipher decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
                decrypt.init(Cipher.DECRYPT_MODE, key);
                final byte[] dt = decrypt.doFinal(ct);
                System.out.println(new String(dt));
                /* ok this code has a small problem I get multiple ciphers that are the same so i get multiple keys.
                I think it's a parity problem with the bits in the keys aka(lbs) and I don't know how to check when parity is adjusted. */
            }
        }


        // TODO
        return null;
    }

}
