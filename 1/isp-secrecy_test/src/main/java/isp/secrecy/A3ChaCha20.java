package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                int i =1;

                final Cipher encrypt = Cipher.getInstance("ChaCha20");
                final Cipher decrypt = Cipher.getInstance("ChaCha20");

                if(i ==1) {
                    final byte[] noneA = new byte[12];
                    new SecureRandom().nextBytes(noneA);

                    final int counterA = 0;
                    ByteBuffer bbA = ByteBuffer.allocate(4);
                    bbA.putInt(counterA);

                    final String messageAlice = "I love you Bob. Kisses, Alice.";
                    final byte[] ptA = messageAlice.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] cipherText = encrypt.doFinal(ptA);

                    System.out.println("Alice c :" + Agent.hex(cipherText));

                    send("bob", cipherText);

                    send("bob", noneA);

                    send("bob", bbA.array());

                    final byte[] receivedB = receive("bob");

                    final byte[] noneB = receive("bob");

                    final byte[] bbB = receive("bob");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbB);
                    final int counterB = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));
                    final byte[] dt = decrypt.doFinal(receivedB);

                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    i++;
                }

                if(i ==2) {
                    final byte[] noneA = new byte[12];
                    new SecureRandom().nextBytes(noneA);

                    final int counterA = 0;
                    ByteBuffer bbA = ByteBuffer.allocate(4);
                    bbA.putInt(counterA);

                    final String messageAlice = "Aaaa tnx Bob let's go on a date.";
                    final byte[] ptA = messageAlice.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] cipherText = encrypt.doFinal(ptA);


                    send("bob", cipherText);

                    send("bob", noneA);

                    send("bob", bbA.array());

                    final byte[] receivedB = receive("bob");

                    final byte[] noneB = receive("bob");

                    final byte[] bbB = receive("bob");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbB);
                    final int counterB = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));
                    final byte[] dt = decrypt.doFinal(receivedB);

                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    i++;
                }

                if(i ==3) {
                    final byte[] noneA = new byte[12];
                    new SecureRandom().nextBytes(noneA);

                    final int counterA = 0;
                    ByteBuffer bbA = ByteBuffer.allocate(4);
                    bbA.putInt(counterA);

                    final String messageAlice = "Uuu I like Italian restaurants.";
                    final byte[] ptA = messageAlice.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] cipherText = encrypt.doFinal(ptA);


                    send("bob", cipherText);

                    send("bob", noneA);

                    send("bob", bbA.array());

                    final byte[] receivedB = receive("bob");

                    final byte[] noneB = receive("bob");

                    final byte[] bbB = receive("bob");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbB);
                    final int counterB = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));
                    final byte[] dt = decrypt.doFinal(receivedB);

                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    i++;
                }

                if(i ==4) {
                    final byte[] noneA = new byte[12];
                    new SecureRandom().nextBytes(noneA);

                    final int counterA = 0;
                    ByteBuffer bbA = ByteBuffer.allocate(4);
                    bbA.putInt(counterA);

                    final String messageAlice = "I've never tried sushi before.";
                    final byte[] ptA = messageAlice.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] cipherText = encrypt.doFinal(ptA);


                    send("bob", cipherText);

                    send("bob", noneA);

                    send("bob", bbA.array());

                    final byte[] receivedB = receive("bob");

                    final byte[] noneB = receive("bob");

                    final byte[] bbB = receive("bob");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbB);
                    final int counterB = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));
                    final byte[] dt = decrypt.doFinal(receivedB);

                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    i++;
                }

                if(i ==5) {
                    final byte[] noneA = new byte[12];
                    new SecureRandom().nextBytes(noneA);

                    final int counterA = 0;
                    ByteBuffer bbA = ByteBuffer.allocate(4);
                    bbA.putInt(counterA);

                    final String messageAlice = "Ok it's a date, i will meet you in the park at 6.";
                    final byte[] ptA = messageAlice.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] cipherText = encrypt.doFinal(ptA);


                    send("bob", cipherText);

                    send("bob", noneA);

                    send("bob", bbA.array());

                    final byte[] receivedB = receive("bob");

                    final byte[] noneB = receive("bob");

                    final byte[] bbB = receive("bob");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbB);
                    final int counterB = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));
                    final byte[] dt = decrypt.doFinal(receivedB);

                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    i++;
                }

                if(i ==6) {
                    final byte[] noneA = new byte[12];
                    new SecureRandom().nextBytes(noneA);

                    final int counterA = 0;
                    ByteBuffer bbA = ByteBuffer.allocate(4);
                    bbA.putInt(counterA);

                    final String messageAlice = "Hey where are you.";
                    final byte[] ptA = messageAlice.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] cipherText = encrypt.doFinal(ptA);


                    send("bob", cipherText);

                    send("bob", noneA);

                    send("bob", bbA.array());

                    final byte[] receivedB = receive("bob");

                    final byte[] noneB = receive("bob");

                    final byte[] bbB = receive("bob");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbB);
                    final int counterB = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));
                    final byte[] dt = decrypt.doFinal(receivedB);

                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    i++;
                }

                if(i ==7) {
                    final byte[] noneA = new byte[12];
                    new SecureRandom().nextBytes(noneA);

                    final int counterA = 0;
                    ByteBuffer bbA = ByteBuffer.allocate(4);
                    bbA.putInt(counterA);

                    final String messageAlice = "I don't see you.";
                    final byte[] ptA = messageAlice.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] cipherText = encrypt.doFinal(ptA);


                    send("bob", cipherText);

                    send("bob", noneA);

                    send("bob", bbA.array());

                    final byte[] receivedB = receive("bob");

                    final byte[] noneB = receive("bob");

                    final byte[] bbB = receive("bob");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbB);
                    final int counterB = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));
                    final byte[] dt = decrypt.doFinal(receivedB);

                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    i++;
                }

                if(i ==8) {
                    final byte[] noneA = new byte[12];
                    new SecureRandom().nextBytes(noneA);

                    final int counterA = 0;
                    ByteBuffer bbA = ByteBuffer.allocate(4);
                    bbA.putInt(counterA);

                    final String messageAlice = "Ok im looking for you.";
                    final byte[] ptA = messageAlice.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] cipherText = encrypt.doFinal(ptA);


                    send("bob", cipherText);

                    send("bob", noneA);

                    send("bob", bbA.array());

                    final byte[] receivedB = receive("bob");

                    final byte[] noneB = receive("bob");

                    final byte[] bbB = receive("bob");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbB);
                    final int counterB = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));
                    final byte[] dt = decrypt.doFinal(receivedB);

                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    i++;
                }

                if(i ==9) {
                    final byte[] noneA = new byte[12];
                    new SecureRandom().nextBytes(noneA);

                    final int counterA = 0;
                    ByteBuffer bbA = ByteBuffer.allocate(4);
                    bbA.putInt(counterA);

                    final String messageAlice = "Oh bob.";
                    final byte[] ptA = messageAlice.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] cipherText = encrypt.doFinal(ptA);


                    send("bob", cipherText);

                    send("bob", noneA);

                    send("bob", bbA.array());

                    final byte[] receivedB = receive("bob");

                    final byte[] noneB = receive("bob");

                    final byte[] bbB = receive("bob");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbB);
                    final int counterB = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));
                    final byte[] dt = decrypt.doFinal(receivedB);

                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    i++;
                }

                if(i ==10) {
                    final byte[] noneA = new byte[12];
                    new SecureRandom().nextBytes(noneA);

                    final int counterA = 0;
                    ByteBuffer bbA = ByteBuffer.allocate(4);
                    bbA.putInt(counterA);

                    final String messageAlice = "And they lived happily ever after.";
                    final byte[] ptA = messageAlice.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] cipherText = encrypt.doFinal(ptA);


                    send("bob", cipherText);

                    send("bob", noneA);

                    send("bob", bbA.array());

                    final byte[] receivedB = receive("bob");

                    final byte[] noneB = receive("bob");

                    final byte[] bbB = receive("bob");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbB);
                    final int counterB = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));
                    final byte[] dt = decrypt.doFinal(receivedB);

                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    i++;
                }
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                 */
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                int i = 1;

                final Cipher encrypt = Cipher.getInstance("ChaCha20");
                final Cipher decrypt = Cipher.getInstance("ChaCha20");

                if(i==1) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("Bob   m :" + Agent.hex(dt));
                    System.out.println("                                                  ");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "I love you to Alice. Love, Bob.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }

                if(i==2) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "Ok where would you like to go?";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }

                if(i==3) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "Im more of a sushi guy my self.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }

                if(i==4) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "Ok I know a very good location where we can go.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }

                if(i==5) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "Ok see you there.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }

                if(i==6) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "Ok see you there.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }

                if(i==6) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "At the old tree.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }

                if(i==7) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "I will move.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }

                if(i==8) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "Hey alice.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }

                if(i==9) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "Finally.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }

                if(i==10) {
                    final byte[] receivedA = receive("alice");

                    final byte[] noneA = receive("alice");

                    final byte[] bbA = receive("alice");
                    ByteBuffer wrapped = ByteBuffer.wrap(bbA);
                    final int counterA = wrapped.getShort();

                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(noneA, counterA));
                    final byte[] dt = decrypt.doFinal(receivedA);

                    System.out.println("");
                    System.out.println("[Bob] Alice's decrypted message: " + new String(dt));

                    final byte[] noneB = new byte[12];
                    new SecureRandom().nextBytes(noneB);

                    final int counterB = 0;
                    ByteBuffer bbB = ByteBuffer.allocate(4);
                    bbB.putInt(counterB);

                    final String messageBob = "The end.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(noneB, counterB));

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    send("alice", noneB);

                    send("alice", bbB.array());

                    i++;
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
