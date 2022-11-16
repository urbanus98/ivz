package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */


public class A1AgentCommunicationHMAC {
    public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        /*
            FIXME: Defense #2

            The idea is to hide which bytes are actually being compared
            by MAC-ing the tags once more and then comparing those tags
         */
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();



        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                int i= 1;

                if(i==1) {
                    final String text = "I hope you get this message intact. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Mac aliceMac = Mac.getInstance("HmacSHA256");
                    aliceMac.init(key);

                    final byte[] tag1 = aliceMac.doFinal(pt);

                    send("bob", tag1);
                    send("bob", pt);

                    final byte[] receivedTag = receive("bob");
                    final byte[] receivedPt = receive("bob");

                    final Mac bobMac = Mac.getInstance("HmacSHA256");

                    bobMac.init(key);

                    final byte[] tag2 = bobMac.doFinal(receivedPt);

                    if(verify3(tag2,receivedTag, key)){
                        System.out.println("The data sent by bob is valid");
                    }else{
                        System.out.println("The data sent by bob is not valid");
                    }

                    i++;
                }

                if(i==2) {
                    final String text = "I hope you get this message intact. Kisses, Alice."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Mac aliceMac = Mac.getInstance("HmacSHA256");
                    aliceMac.init(key);

                    final byte[] tag1 = aliceMac.doFinal(pt);

                    send("bob", tag1);
                    send("bob", pt);

                    final byte[] receivedTag = receive("bob");
                    final byte[] receivedPt = receive("bob");

                    final Mac bobMac = Mac.getInstance("HmacSHA256");

                    bobMac.init(key);

                    final byte[] tag2 = bobMac.doFinal(receivedPt);

                    if(verify3(tag2,receivedTag, key)){
                        System.out.println("The data sent by bob is valid");
                    }else{
                        System.out.println("The data sent by bob is not valid");
                    }

                    i++;
                }

                if(i==3) {
                    final String text = "I hope you get this message intact. Kisses, Alice."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Mac aliceMac = Mac.getInstance("HmacSHA256");
                    aliceMac.init(key);

                    final byte[] tag1 = aliceMac.doFinal(pt);

                    send("bob", tag1);
                    send("bob", pt);

                    final byte[] receivedTag = receive("bob");
                    final byte[] receivedPt = receive("bob");

                    final Mac bobMac = Mac.getInstance("HmacSHA256");

                    bobMac.init(key);

                    final byte[] tag2 = bobMac.doFinal(receivedPt);

                    if(verify3(tag2,receivedTag, key)){
                        System.out.println("The data sent by bob is valid");
                    }else{
                        System.out.println("The data sent by bob is not valid");
                    }

                    i++;
                }

                if(i==4) {
                    final String text = "I hope you get this message intact. Kisses, Alice."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Mac aliceMac = Mac.getInstance("HmacSHA256");
                    aliceMac.init(key);

                    final byte[] tag1 = aliceMac.doFinal(pt);

                    send("bob", tag1);
                    send("bob", pt);

                    final byte[] receivedTag = receive("bob");
                    final byte[] receivedPt = receive("bob");

                    final Mac bobMac = Mac.getInstance("HmacSHA256");

                    bobMac.init(key);

                    final byte[] tag2 = bobMac.doFinal(receivedPt);

                    if(verify3(tag2,receivedTag, key)){
                        System.out.println("The data sent by bob is valid");
                    }else{
                        System.out.println("The data sent by bob is not valid");
                    }

                    i++;
                }

                if(i==5) {
                    final String text = "I hope you get this message intact. Kisses, Alice."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Mac aliceMac = Mac.getInstance("HmacSHA256");
                    aliceMac.init(key);

                    final byte[] tag1 = aliceMac.doFinal(pt);

                    send("bob", tag1);
                    send("bob", pt);

                    final byte[] receivedTag = receive("bob");
                    final byte[] receivedPt = receive("bob");

                    final Mac bobMac = Mac.getInstance("HmacSHA256");

                    bobMac.init(key);

                    final byte[] tag2 = bobMac.doFinal(receivedPt);

                    if(verify3(tag2,receivedTag, key)){
                        System.out.println("The data sent by bob is valid");
                    }else{
                        System.out.println("The data sent by bob is not valid");
                    }

                    i++;
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                int i =1;

                if(i ==1) {
                    final byte[] receivedTag = receive("alice");
                    final byte[] receivedPt = receive("alice");

                    final Mac bobMac = Mac.getInstance("HmacSHA256");

                    bobMac.init(key);

                    final byte[] tag2 = bobMac.doFinal(receivedPt);

                    System.out.println("1.----------------------------------");
                    if(verify3(tag2,receivedTag, key)){
                        System.out.println("The data sent by alice is valid");
                    }else{
                        System.out.println("The data sent by alice is not valid");
                    }

                    final String text = "I hope you get this message intact. Kisses, Bob.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Mac aliceMac = Mac.getInstance("HmacSHA256");
                    aliceMac.init(key);

                    final byte[] tag1 = aliceMac.doFinal(pt);

                    send("alice", tag1);
                    send("alice", pt);
                    i++;
                }

                if(i ==2) {
                    final byte[] receivedTag = receive("alice");
                    final byte[] receivedPt = receive("alice");

                    final Mac bobMac = Mac.getInstance("HmacSHA256");

                    bobMac.init(key);

                    final byte[] tag2 = bobMac.doFinal(receivedPt);

                    System.out.println("2.----------------------------------");
                    if(verify3(tag2,receivedTag, key)){
                        System.out.println("The data sent by alice is valid");
                    }else{
                        System.out.println("The data sent by alice is not valid");
                    }

                    final String text = "I hope you get this message intact. Kisses, Bob."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Mac aliceMac = Mac.getInstance("HmacSHA256");
                    aliceMac.init(key);

                    final byte[] tag1 = aliceMac.doFinal(pt);

                    send("alice", tag1);
                    send("alice", pt);
                    i++;
                }

                if(i ==3) {
                    final byte[] receivedTag = receive("alice");
                    final byte[] receivedPt = receive("alice");

                    final Mac bobMac = Mac.getInstance("HmacSHA256");

                    bobMac.init(key);

                    final byte[] tag2 = bobMac.doFinal(receivedPt);

                    System.out.println("3.----------------------------------");
                    if(verify3(tag2,receivedTag, key)){
                        System.out.println("The data sent by alice is valid");
                    }else{
                        System.out.println("The data sent by alice is not valid");
                    }

                    final String text = "I hope you get this message intact. Kisses, Bob."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Mac aliceMac = Mac.getInstance("HmacSHA256");
                    aliceMac.init(key);

                    final byte[] tag1 = aliceMac.doFinal(pt);

                    send("alice", tag1);
                    send("alice", pt);
                    i++;
                }

                if(i ==4) {
                    final byte[] receivedTag = receive("alice");
                    final byte[] receivedPt = receive("alice");

                    final Mac bobMac = Mac.getInstance("HmacSHA256");

                    bobMac.init(key);

                    final byte[] tag2 = bobMac.doFinal(receivedPt);

                    System.out.println("4.----------------------------------");
                    if(verify3(tag2,receivedTag, key)){
                        System.out.println("The data sent by alice is valid");
                    }else{
                        System.out.println("The data sent by alice is not valid");
                    }

                    final String text = "I hope you get this message intact. Kisses, Bob."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Mac aliceMac = Mac.getInstance("HmacSHA256");
                    aliceMac.init(key);

                    final byte[] tag1 = aliceMac.doFinal(pt);

                    send("alice", tag1);
                    send("alice", pt);
                    i++;
                }

                if(i ==5) {
                    final byte[] receivedTag = receive("alice");
                    final byte[] receivedPt = receive("alice");

                    final Mac bobMac = Mac.getInstance("HmacSHA256");

                    bobMac.init(key);

                    final byte[] tag2 = bobMac.doFinal(receivedPt);

                    System.out.println("5.----------------------------------");
                    if(verify3(tag2,receivedTag, key)){
                        System.out.println("The data sent by alice is valid");
                    }else{
                        System.out.println("The data sent by alice is not valid");
                    }

                    final String text = "I hope you get this message intact. Kisses, Bob."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    final Mac aliceMac = Mac.getInstance("HmacSHA256");
                    aliceMac.init(key);

                    final byte[] tag1 = aliceMac.doFinal(pt);

                    send("alice", tag1);
                    send("alice", pt);
                    i++;
                }

            }
        });


        env.connect("alice", "bob");
        env.start();
    }
}
