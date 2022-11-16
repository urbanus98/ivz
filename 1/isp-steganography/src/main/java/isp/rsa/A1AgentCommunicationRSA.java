package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Assuming Alice and Bob know each other's public key, secure the channel using a
 * RSA. Then exchange ten messages between Alice and Bob.
 *
 * (The remaining assignment(s) can be found in the isp.steganography.ImageSteganography
 * class.)
 */
public class A1AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        // Create two public-secret key pairs
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair bobKP = kpg.generateKeyPair();
        final KeyPair aliceKP = kpg.generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                int i =1;

                final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
                final Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");

                if(i==1) {
                    final String message = "A test message.";
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());

                    final byte[] ct = rsaEnc.doFinal(pt);
                    send("bob", ct);

                    final byte[] receivedBob = receive("bob");

                    rsaDec.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(receivedBob);

                    System.out.println("[Alice]: " + new String(decryptedText, StandardCharsets.UTF_8));

                    i++;
                }
                if(i==2) {
                    final String message = "A test message."+i;
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());

                    final byte[] ct = rsaEnc.doFinal(pt);
                    send("bob", ct);

                    final byte[] receivedBob = receive("bob");

                    rsaDec.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(receivedBob);

                    System.out.println("[Alice]: " + new String(decryptedText, StandardCharsets.UTF_8));

                    i++;
                }
                if(i==3) {
                    final String message = "A test message."+i;
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());

                    final byte[] ct = rsaEnc.doFinal(pt);
                    send("bob", ct);

                    final byte[] receivedBob = receive("bob");

                    rsaDec.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(receivedBob);

                    System.out.println("[Alice]: " + new String(decryptedText, StandardCharsets.UTF_8));

                    i++;
                }
                if(i==4) {
                    final String message = "A test message."+i;
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());

                    final byte[] ct = rsaEnc.doFinal(pt);
                    send("bob", ct);

                    final byte[] receivedBob = receive("bob");

                    rsaDec.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(receivedBob);

                    System.out.println("[Alice]: " + new String(decryptedText, StandardCharsets.UTF_8));

                    i++;
                }
                if(i==5) {
                    final String message = "A test message."+i;
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());

                    final byte[] ct = rsaEnc.doFinal(pt);
                    send("bob", ct);

                    final byte[] receivedBob = receive("bob");

                    rsaDec.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(receivedBob);

                    System.out.println("[Alice]: " + new String(decryptedText, StandardCharsets.UTF_8));

                    i++;
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                int i =1;
                final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
                final Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");

                if (i==1) {
                    final byte[] receivedAlice = receive("alice");

                    rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(receivedAlice);

                    System.out.println("");
                    System.out.println("[BOB]: " + new String(decryptedText, StandardCharsets.UTF_8));

                    final String message = "A new test message.";
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());

                    final byte[] ct = rsaEnc.doFinal(pt);
                    send("alice", ct);
                    i++;
                }
                if (i==2) {
                    final byte[] receivedAlice = receive("alice");

                    rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(receivedAlice);

                    System.out.println("");
                    System.out.println("[BOB]: " + new String(decryptedText, StandardCharsets.UTF_8));

                    final String message = "A new test message."+i;
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());

                    final byte[] ct = rsaEnc.doFinal(pt);
                    send("alice", ct);
                    i++;
                }
                if (i==3) {
                    final byte[] receivedAlice = receive("alice");

                    rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(receivedAlice);

                    System.out.println("");
                    System.out.println("[BOB]: " + new String(decryptedText, StandardCharsets.UTF_8));

                    final String message = "A new test message."+i;
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());

                    final byte[] ct = rsaEnc.doFinal(pt);
                    send("alice", ct);
                    i++;
                }
                if (i==4) {
                    final byte[] receivedAlice = receive("alice");

                    rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(receivedAlice);

                    System.out.println("");
                    System.out.println("[BOB]: " + new String(decryptedText, StandardCharsets.UTF_8));

                    final String message = "A new test message."+i;
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());

                    final byte[] ct = rsaEnc.doFinal(pt);
                    send("alice", ct);
                    i++;
                }
                if (i==5) {
                    final byte[] receivedAlice = receive("alice");

                    rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                    final byte[] decryptedText = rsaDec.doFinal(receivedAlice);

                    System.out.println("");
                    System.out.println("[BOB]: " + new String(decryptedText, StandardCharsets.UTF_8));

                    final String message = "A new test message."+i;
                    final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                    rsaEnc.init(Cipher.ENCRYPT_MODE, aliceKP.getPublic());

                    final byte[] ct = rsaEnc.doFinal(pt);
                    send("alice", ct);
                    i++;
                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
