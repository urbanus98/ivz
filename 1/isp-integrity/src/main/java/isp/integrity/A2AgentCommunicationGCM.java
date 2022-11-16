package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationGCM {

    public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {

        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }

    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                int i =1;

                if(i==1) {
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("bob", pt);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("bob", ct);
                    send("bob", iv);

                    final byte[] receivedPt = receive("bob");
                    final byte[] receivedCt = receive("bob");
                    final byte[] receivedIv = receive("bob");

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receivedIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(receivedCt);
                    System.out.printf("[Alice]: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed_pt = digestAlgorithm.digest(receivedPt);
                    final byte[] hashed_ct = digestAlgorithm.digest(pt2);

                    if (verify3(hashed_ct, hashed_pt, key)) {
                        System.out.println("The data sent by bob is valid");
                    } else {
                        System.out.println("The data sent by bob is not valid");
                    }

                    i++;
                }

                if(i==2) {
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice." +i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("bob", pt);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("bob", ct);
                    send("bob", iv);

                    final byte[] receivedPt = receive("bob");
                    final byte[] receivedCt = receive("bob");
                    final byte[] receivedIv = receive("bob");

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receivedIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(receivedCt);
                    System.out.printf("[Alice]: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed_pt = digestAlgorithm.digest(receivedPt);
                    final byte[] hashed_ct = digestAlgorithm.digest(pt2);

                    if (verify3(hashed_ct, hashed_pt, key)) {
                        System.out.println("The data sent by bob is valid");
                    } else {
                        System.out.println("The data sent by bob is not valid");
                    }

                    i++;
                }

                if(i==3) {
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice." +i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("bob", pt);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("bob", ct);
                    send("bob", iv);

                    final byte[] receivedPt = receive("bob");
                    final byte[] receivedCt = receive("bob");
                    final byte[] receivedIv = receive("bob");

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receivedIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(receivedCt);
                    System.out.printf("[Alice]: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed_pt = digestAlgorithm.digest(receivedPt);
                    final byte[] hashed_ct = digestAlgorithm.digest(pt2);

                    if (verify3(hashed_ct, hashed_pt, key)) {
                        System.out.println("The data sent by bob is valid");
                    } else {
                        System.out.println("The data sent by bob is not valid");
                    }
                    i++;
                }

                if(i==4) {
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice." +i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("bob", pt);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("bob", ct);
                    send("bob", iv);

                    final byte[] receivedPt = receive("bob");
                    final byte[] receivedCt = receive("bob");
                    final byte[] receivedIv = receive("bob");

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receivedIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(receivedCt);
                    System.out.printf("[Alice]: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed_pt = digestAlgorithm.digest(receivedPt);
                    final byte[] hashed_ct = digestAlgorithm.digest(pt2);

                    if (verify3(hashed_ct, hashed_pt, key)) {
                        System.out.println("The data sent by bob is valid");
                    } else {
                        System.out.println("The data sent by bob is not valid");
                    }
                    i++;
                }

                if(i==5) {
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice." +i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("bob", pt);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("bob", ct);
                    send("bob", iv);

                    final byte[] receivedPt = receive("bob");
                    final byte[] receivedCt = receive("bob");
                    final byte[] receivedIv = receive("bob");

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receivedIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(receivedCt);
                    System.out.printf("[Alice]: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed_pt = digestAlgorithm.digest(receivedPt);
                    final byte[] hashed_ct = digestAlgorithm.digest(pt2);

                    if (verify3(hashed_ct, hashed_pt, key)) {
                        System.out.println("The data sent by bob is valid");
                    } else {
                        System.out.println("The data sent by bob is not valid");
                    }
                    i++;
                }
            }

        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                int i = 1;
                if(i ==1) {
                    final byte[] receivedPt = receive("alice");
                    final byte[] receivedCt = receive("alice");
                    final byte[] receivedIv = receive("alice");

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receivedIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(receivedCt);
                    System.out.println("1.----------------------------------");
                    System.out.printf("[BOB]: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed_pt = digestAlgorithm.digest(receivedPt);
                    final byte[] hashed_ct = digestAlgorithm.digest(pt2);

                    if (verify3(hashed_ct, hashed_pt, key)) {
                        System.out.println("The data sent by alice is valid");
                    } else {
                        System.out.println("The data sent by alice is not valid");
                    }

                    final String text = "I hope you get this message intact and in secret. Kisses, bob.";
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("alice", pt);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("alice", ct);
                    send("alice", iv);

                    i++;
                }
                if(i==2){
                    final byte[] receivedPt = receive("alice");
                    final byte[] receivedCt = receive("alice");
                    final byte[] receivedIv = receive("alice");

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receivedIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(receivedCt);
                    System.out.println(i+".----------------------------------");
                    System.out.printf("[BOB]: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed_pt = digestAlgorithm.digest(receivedPt);
                    final byte[] hashed_ct = digestAlgorithm.digest(pt2);

                    if (verify3(hashed_ct, hashed_pt, key)) {
                        System.out.println("The data sent by alice is valid");
                    } else {
                        System.out.println("The data sent by alice is not valid");
                    }

                    final String text = "I hope you get this message intact and in secret. Kisses, bob."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("alice", pt);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("alice", ct);
                    send("alice", iv);
                    i++;
                }
                if(i==3){
                    final byte[] receivedPt = receive("alice");
                    final byte[] receivedCt = receive("alice");
                    final byte[] receivedIv = receive("alice");

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receivedIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(receivedCt);
                    System.out.println(i+".----------------------------------");
                    System.out.printf("[BOB]: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed_pt = digestAlgorithm.digest(receivedPt);
                    final byte[] hashed_ct = digestAlgorithm.digest(pt2);

                    if (verify3(hashed_ct, hashed_pt, key)) {
                        System.out.println("The data sent by alice is valid");
                    } else {
                        System.out.println("The data sent by alice is not valid");
                    }

                    final String text = "I hope you get this message intact and in secret. Kisses, bob."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("alice", pt);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("alice", ct);
                    send("alice", iv);
                    i++;
                }

                if(i==4){
                    final byte[] receivedPt = receive("alice");
                    final byte[] receivedCt = receive("alice");
                    final byte[] receivedIv = receive("alice");

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receivedIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(receivedCt);
                    System.out.println(i+".----------------------------------");
                    System.out.printf("[BOB]: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed_pt = digestAlgorithm.digest(receivedPt);
                    final byte[] hashed_ct = digestAlgorithm.digest(pt2);

                    if (verify3(hashed_ct, hashed_pt, key)) {
                        System.out.println("The data sent by alice is valid");
                    } else {
                        System.out.println("The data sent by alice is not valid");
                    }

                    final String text = "I hope you get this message intact and in secret. Kisses, bob."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("alice", pt);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("alice", ct);
                    send("alice", iv);
                    i++;
                }

                if(i==5){
                    final byte[] receivedPt = receive("alice");
                    final byte[] receivedCt = receive("alice");
                    final byte[] receivedIv = receive("alice");

                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, receivedIv);
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt2 = bob.doFinal(receivedCt);
                    System.out.println(i+".----------------------------------");
                    System.out.printf("[BOB]: %s%n", new String(pt2, StandardCharsets.UTF_8));


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                    final byte[] hashed_pt = digestAlgorithm.digest(receivedPt);
                    final byte[] hashed_ct = digestAlgorithm.digest(pt2);

                    if (verify3(hashed_ct, hashed_pt, key)) {
                        System.out.println("The data sent by alice is valid");
                    } else {
                        System.out.println("The data sent by alice is not valid");
                    }

                    final String text = "I hope you get this message intact and in secret. Kisses, bob."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("alice", pt);
                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    final byte[] iv = alice.getIV();
                    send("alice", ct);
                    send("alice", iv);
                    i++;
                }

            }

        });

        env.connect("alice", "bob");
        env.start();
    }
}
