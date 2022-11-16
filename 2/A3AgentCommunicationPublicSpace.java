package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.imageio.ImageTranscoder;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest (implemented)
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();
        final SecretKey key2 = KeyGenerator.getInstance("AES").generateKey();

        byte [] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        int counter = 5;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // A payload of 200 MB.
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Compute digest out of data.
                final MessageDigest dA = MessageDigest.getInstance("SHA-256");
                final byte[] hash = dA.digest(data);

                // Send data to Bob.
                send("bob", data);

                // Alice then computes the digest of the data and sends the digest to public-space
                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.
                final Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
                c.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(nonce));
                byte [] sendToPublic = c.doFinal(hash);
                send("public-space",sendToPublic);
            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {

                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice.
                byte[] recieveCtFromAlice  = receive("alice");
                final Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
                c.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(nonce));
                byte [] sendToBob = c.doFinal(recieveCtFromAlice);

                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob.
                final Cipher c2 = Cipher.getInstance("AES/GCM/NoPadding");
                c2.init(Cipher.ENCRYPT_MODE,key2);
                send("bob",c2.doFinal(sendToBob));
                send("bob", c2.getIV());
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                // Data from Alice.
                byte [] dataFromAlice = receive("alice");

                // Compute digest.
                final MessageDigest dfa = MessageDigest.getInstance("SHA-256");
                byte [] dataFromAliceHash = dfa.digest(dataFromAlice);

                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space
                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
                final byte [] encHashFromPublic = receive("public-space");
                final byte [] iV = receive("public-space");
                final Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE,key2,new GCMParameterSpec(128,iV));
                byte [] receivedHash = c.doFinal(encHashFromPublic);

                        if(verify(dataFromAliceHash,receivedHash)){
                            System.out.println("Data valid!");
                        }
                        else{
                            System.out.println("Data invalid!");
                        }
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
    static boolean verify(byte[] tag1, byte[] tag2){
        if (tag1 == tag2)
            return true;
        if (tag1 == null || tag2 == null)
            return false;

        int length = tag1.length;
        if (tag2.length != length)
            return false;

        // This loop never terminates prematurely
        byte result = 0;
        for (int i = 0; i < length; i++) {
            result |= tag1[i] ^ tag2[i];
        }
        return result == 0;
    }
}