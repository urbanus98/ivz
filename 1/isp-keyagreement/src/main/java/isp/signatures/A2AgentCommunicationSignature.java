package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final Environment env = new Environment();

        // Create key pairs
        final String signingAlgorithm = "SHA256withECDSA";
        final String keyAlgorithm = "EC";

        final KeyPair keyAlice = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();
        final KeyPair keyBob = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

        final Mac hmac = Mac.getInstance("HmacSHA256");
        final String password = "password2";
        final byte[] salt = "fasfasfa2e211dsa231".getBytes(StandardCharsets.UTF_8);
        final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt, 10000, 128);
        final SecretKey generatedKey = pbkdf.generateSecret(specs);


        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                int i =1;

                if(i==1) {
                    String message = "Hi bob this is alice";

                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(keyAlice.getPrivate());

                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
                    final byte[] tag = hmac.doFinal(message.getBytes());

                    signer.update(message.getBytes(StandardCharsets.UTF_8));

                    final byte[] signature = signer.sign();
                    System.out.println("[Alice]Signature: " + Agent.hex(signature));

                    send("bob", message.getBytes());
                    send("bob", signature);
                    send("bob", tag);

                    final byte[] meessagBOB = receive("bob");
                    final byte[] newtag = hmac.doFinal(meessagBOB);
                    final byte[] signatureBOB = receive("bob");
                    final byte[] tagBOB = receive("bob");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyBob.getPublic());
                    verifier.update(meessagBOB);

                    if (verifier.verify(signatureBOB))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                    if (Arrays.equals(tagBOB, newtag))
                        System.out.println("Valid tag.");
                    else
                        System.err.println("Invalid tag.");

                    System.out.println(new String(meessagBOB));
                    System.out.println("");

                    i++;
                }

                if(i==2) {
                    String message = "Hi bob this is alice"+i;

                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(keyAlice.getPrivate());

                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
                    final byte[] tag = hmac.doFinal(message.getBytes());

                    signer.update(message.getBytes(StandardCharsets.UTF_8));

                    final byte[] signature = signer.sign();
                    System.out.println("[Alice]Signature: " + Agent.hex(signature));

                    send("bob", message.getBytes());
                    send("bob", signature);
                    send("bob", tag);

                    final byte[] meessagBOB = receive("bob");
                    final byte[] newtag = hmac.doFinal(meessagBOB);
                    final byte[] signatureBOB = receive("bob");
                    final byte[] tagBOB = receive("bob");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyBob.getPublic());
                    verifier.update(meessagBOB);

                    if (verifier.verify(signatureBOB))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                    if (Arrays.equals(tagBOB, newtag))
                        System.out.println("Valid tag.");
                    else
                        System.err.println("Invalid tag.");

                    System.out.println(new String(meessagBOB));
                    System.out.println("");

                    i++;
                }

                if(i==3) {
                    String message = "Hi bob this is alice"+i;

                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(keyAlice.getPrivate());

                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
                    final byte[] tag = hmac.doFinal(message.getBytes());

                    signer.update(message.getBytes(StandardCharsets.UTF_8));

                    final byte[] signature = signer.sign();
                    System.out.println("[Alice]Signature: " + Agent.hex(signature));

                    send("bob", message.getBytes());
                    send("bob", signature);
                    send("bob", tag);

                    final byte[] meessagBOB = receive("bob");
                    final byte[] newtag = hmac.doFinal(meessagBOB);
                    final byte[] signatureBOB = receive("bob");
                    final byte[] tagBOB = receive("bob");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyBob.getPublic());
                    verifier.update(meessagBOB);

                    if (verifier.verify(signatureBOB))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                    if (Arrays.equals(tagBOB, newtag))
                        System.out.println("Valid tag.");
                    else
                        System.err.println("Invalid tag.");

                    System.out.println(new String(meessagBOB));
                    System.out.println("");

                    i++;
                }

                if(i==4) {
                    String message = "Hi bob this is alice"+i;

                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(keyAlice.getPrivate());

                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
                    final byte[] tag = hmac.doFinal(message.getBytes());

                    signer.update(message.getBytes(StandardCharsets.UTF_8));

                    final byte[] signature = signer.sign();
                    System.out.println("[Alice]Signature: " + Agent.hex(signature));

                    send("bob", message.getBytes());
                    send("bob", signature);
                    send("bob", tag);

                    final byte[] meessagBOB = receive("bob");
                    final byte[] newtag = hmac.doFinal(meessagBOB);
                    final byte[] signatureBOB = receive("bob");
                    final byte[] tagBOB = receive("bob");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyBob.getPublic());
                    verifier.update(meessagBOB);

                    if (verifier.verify(signatureBOB))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                    if (Arrays.equals(tagBOB, newtag))
                        System.out.println("Valid tag.");
                    else
                        System.err.println("Invalid tag.");

                    System.out.println(new String(meessagBOB));
                    System.out.println("");

                    i++;
                }

                if(i==5) {
                    String message = "Hi bob this is alice"+i;

                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(keyAlice.getPrivate());

                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
                    final byte[] tag = hmac.doFinal(message.getBytes());

                    signer.update(message.getBytes(StandardCharsets.UTF_8));

                    final byte[] signature = signer.sign();
                    System.out.println("[Alice]Signature: " + Agent.hex(signature));

                    send("bob", message.getBytes());
                    send("bob", signature);
                    send("bob", tag);

                    final byte[] meessagBOB = receive("bob");
                    final byte[] newtag = hmac.doFinal(meessagBOB);
                    final byte[] signatureBOB = receive("bob");
                    final byte[] tagBOB = receive("bob");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyBob.getPublic());
                    verifier.update(meessagBOB);

                    if (verifier.verify(signatureBOB))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                    if (Arrays.equals(tagBOB, newtag))
                        System.out.println("Valid tag.");
                    else
                        System.err.println("Invalid tag.");

                    System.out.println(new String(meessagBOB));
                    System.out.println("");

                    i++;
                }
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message signarure pair, verify the signature
                // repeat 10 times
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                int i=1;

                if(i==1) {
                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));

                    final byte[] meessagAlice = receive("alice");
                    final byte[] newtag = hmac.doFinal(meessagAlice);
                    final byte[] signatureAlice = receive("alice");
                    final byte[] tagAlice = receive("alice");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyAlice.getPublic());
                    verifier.update(meessagAlice);

                    if (verifier.verify(signatureAlice))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                    if (Arrays.equals(tagAlice, newtag))
                        System.out.println("Valid tag.");
                    else
                        System.err.println("Invalid tag.");

                    System.out.println(new String(meessagAlice));

                    String message = "Hi Alice this is bob";

                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(keyBob.getPrivate());


                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
                    final byte[] tag = hmac.doFinal(message.getBytes());

                    signer.update(message.getBytes(StandardCharsets.UTF_8));

                    final byte[] signature = signer.sign();
                    System.out.println("[BOB]Signature: " + Agent.hex(signature));

                    send("alice", message.getBytes());
                    send("alice", signature);
                    send("alice", tag);

                    i++;
                }

                if(i==2) {
                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));

                    final byte[] meessagAlice = receive("alice");
                    final byte[] newtag = hmac.doFinal(meessagAlice);
                    final byte[] signatureAlice = receive("alice");
                    final byte[] tagAlice = receive("alice");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyAlice.getPublic());
                    verifier.update(meessagAlice);

                    if (verifier.verify(signatureAlice))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                    if (Arrays.equals(tagAlice, newtag))
                        System.out.println("Valid tag.");
                    else
                        System.err.println("Invalid tag.");

                    System.out.println(new String(meessagAlice));

                    String message = "Hi Alice this is bob"+i;

                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(keyBob.getPrivate());


                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
                    final byte[] tag = hmac.doFinal(message.getBytes());

                    signer.update(message.getBytes(StandardCharsets.UTF_8));

                    final byte[] signature = signer.sign();
                    System.out.println("[BOB]Signature: " + Agent.hex(signature));

                    send("alice", message.getBytes());
                    send("alice", signature);
                    send("alice", tag);
                    i++;
                }

                if(i==3) {
                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));

                    final byte[] meessagAlice = receive("alice");
                    final byte[] newtag = hmac.doFinal(meessagAlice);
                    final byte[] signatureAlice = receive("alice");
                    final byte[] tagAlice = receive("alice");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyAlice.getPublic());
                    verifier.update(meessagAlice);

                    if (verifier.verify(signatureAlice))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                    if (Arrays.equals(tagAlice, newtag))
                        System.out.println("Valid tag.");
                    else
                        System.err.println("Invalid tag.");

                    System.out.println(new String(meessagAlice));

                    String message = "Hi Alice this is bob"+i;

                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(keyBob.getPrivate());


                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
                    final byte[] tag = hmac.doFinal(message.getBytes());

                    signer.update(message.getBytes(StandardCharsets.UTF_8));

                    final byte[] signature = signer.sign();
                    System.out.println("[BOB]Signature: " + Agent.hex(signature));

                    send("alice", message.getBytes());
                    send("alice", signature);
                    send("alice", tag);
                    i++;
                }

                if(i==4) {
                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));

                    final byte[] meessagAlice = receive("alice");
                    final byte[] newtag = hmac.doFinal(meessagAlice);
                    final byte[] signatureAlice = receive("alice");
                    final byte[] tagAlice = receive("alice");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyAlice.getPublic());
                    verifier.update(meessagAlice);

                    if (verifier.verify(signatureAlice))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                    if (Arrays.equals(tagAlice, newtag))
                        System.out.println("Valid tag.");
                    else
                        System.err.println("Invalid tag.");

                    System.out.println(new String(meessagAlice));

                    String message = "Hi Alice this is bob"+i;

                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(keyBob.getPrivate());


                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
                    final byte[] tag = hmac.doFinal(message.getBytes());

                    signer.update(message.getBytes(StandardCharsets.UTF_8));

                    final byte[] signature = signer.sign();
                    System.out.println("[BOB]Signature: " + Agent.hex(signature));

                    send("alice", message.getBytes());
                    send("alice", signature);
                    send("alice", tag);
                    i++;
                }

                if(i==5) {
                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));

                    final byte[] meessagAlice = receive("alice");
                    final byte[] newtag = hmac.doFinal(meessagAlice);
                    final byte[] signatureAlice = receive("alice");
                    final byte[] tagAlice = receive("alice");

                    final Signature verifier = Signature.getInstance(signingAlgorithm);
                    verifier.initVerify(keyAlice.getPublic());
                    verifier.update(meessagAlice);

                    if (verifier.verify(signatureAlice))
                        System.out.println("Valid signature.");
                    else
                        System.err.println("Invalid signature.");

                    if (Arrays.equals(tagAlice, newtag))
                        System.out.println("Valid tag.");
                    else
                        System.err.println("Invalid tag.");

                    System.out.println(new String(meessagAlice));

                    String message = "Hi Alice this is bob"+i;

                    final Signature signer = Signature.getInstance(signingAlgorithm);
                    signer.initSign(keyBob.getPrivate());


                    hmac.init(new SecretKeySpec(generatedKey.getEncoded(), "HmacSHA256"));
                    final byte[] tag = hmac.doFinal(message.getBytes());

                    signer.update(message.getBytes(StandardCharsets.UTF_8));

                    final byte[] signature = signer.sign();
                    System.out.println("[BOB]Signature: " + Agent.hex(signature));

                    send("alice", message.getBytes());
                    send("alice", signature);
                    send("alice", tag);
                    i++;
                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }

}