package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * AES in CBC mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AESInCBCMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                int i = 1;

                final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                final Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");

                if(i == 1) {
                    final String messageAlice = "I love you Bob. Kisses, Alice.";
                    final byte[] ptA = messageAlice.getBytes();
                    System.out.println("Alice m :" + Agent.hex(ptA));


                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(ptA);
                    System.out.println("Alice c :" + Agent.hex(cipherText));
                    send("bob", cipherText);

                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);

                    final byte[] received = receive("bob");

                    final byte[] ivB = receive("bob");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("[BOB] Alice's decrypted message: " + new String(dt));

                    i++;
                }

                if(i == 2) {
                    final String messageAlice = "Aaaa tnx Bob let's go on a date.";
                    final byte[] ptA = messageAlice.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(ptA);
                    send("bob", cipherText);

                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);

                    final byte[] received = receive("bob");

                    final byte[] ivB = receive("bob");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("[BOB] Alice's decrypted message: " + new String(dt));

                    i++;
                }

                if(i == 3) {
                    final String messageAlice = "Uuu I like Italian restaurants.";
                    final byte[] ptA = messageAlice.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(ptA);
                    send("bob", cipherText);

                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);

                    final byte[] received = receive("bob");

                    final byte[] ivB = receive("bob");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("[BOB] Alice's decrypted message: " + new String(dt));

                    i++;
                }

                if(i == 4) {
                    final String messageAlice = "I've never tried sushi before.";
                    final byte[] ptA = messageAlice.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(ptA);
                    send("bob", cipherText);

                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);

                    final byte[] received = receive("bob");

                    final byte[] ivB = receive("bob");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("[BOB] Alice's decrypted message: " + new String(dt));

                    i++;
                }

                if(i == 5) {
                    final String messageAlice = "Ok it's a date, i will meet you in the park at 6.";
                    final byte[] ptA = messageAlice.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(ptA);
                    send("bob", cipherText);

                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);

                    final byte[] received = receive("bob");

                    final byte[] ivB = receive("bob");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("[BOB] Alice's decrypted message: " + new String(dt));

                    i++;
                }

                if(i == 6) {
                    final String messageAlice = "Hey where are you.";
                    final byte[] ptA = messageAlice.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(ptA);
                    send("bob", cipherText);

                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);

                    final byte[] received = receive("bob");

                    final byte[] ivB = receive("bob");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("[BOB] Alice's decrypted message: " + new String(dt));

                    i++;
                }

                if(i == 7) {
                    final String messageAlice = "I don't see you.";
                    final byte[] ptA = messageAlice.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(ptA);
                    send("bob", cipherText);

                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);

                    final byte[] received = receive("bob");

                    final byte[] ivB = receive("bob");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("[BOB] Alice's decrypted message: " + new String(dt));

                    i++;
                }

                if(i == 8) {
                    final String messageAlice = "Ok im looking for you.";
                    final byte[] ptA = messageAlice.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(ptA);
                    send("bob", cipherText);

                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);

                    final byte[] received = receive("bob");

                    final byte[] ivB = receive("bob");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("[BOB] Alice's decrypted message: " + new String(dt));

                    i++;
                }

                if(i == 9) {
                    final String messageAlice = "Oh bob..";
                    final byte[] ptA = messageAlice.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(ptA);
                    send("bob", cipherText);

                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);

                    final byte[] received = receive("bob");

                    final byte[] ivB = receive("bob");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("[BOB] Alice's decrypted message: " + new String(dt));

                    i++;
                }

                if(i == 10) {
                    final String messageAlice = "And they lived happily ever after.";
                    final byte[] ptA = messageAlice.getBytes();

                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] cipherText = encrypt.doFinal(ptA);
                    send("bob", cipherText);

                    final byte[] iv = encrypt.getIV();
                    send("bob", iv);

                    final byte[] received = receive("bob");

                    final byte[] ivB = receive("bob");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("[BOB] Alice's decrypted message: " + new String(dt));

                    i++;
                }
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                int i = 1;

                final Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5PADDING");

                if(i == 1) {
                    final byte[] received = receive("alice");

                    final byte[] ivB = receive("alice");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("Bob m:" + Agent.hex(dt));
                    System.out.println("                                                  ");
                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    final String messageBob = "I love you to Alice. Love, Bob.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    final byte[] ivA = encrypt.getIV();
                    send("alice", ivA);

                    i++;
                }

                if(i == 2) {
                    final byte[] received = receive("alice");

                    final byte[] ivB = receive("alice");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("                                                  ");
                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    final String messageBob = "Ok where would you like to go?";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    final byte[] ivA = encrypt.getIV();
                    send("alice", ivA);

                    i++;
                }

                if(i == 3) {
                    final byte[] received = receive("alice");

                    final byte[] ivB = receive("alice");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("                                                  ");
                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    final String messageBob = "Im more of a sushi guy my self.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    final byte[] ivA = encrypt.getIV();
                    send("alice", ivA);

                    i++;
                }

                if(i == 4) {
                    final byte[] received = receive("alice");

                    final byte[] ivB = receive("alice");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("                                                  ");
                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    final String messageBob = "Ok I know a very good location where we can go.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    final byte[] ivA = encrypt.getIV();
                    send("alice", ivA);

                    i++;
                }

                if(i == 5) {
                    final byte[] received = receive("alice");

                    final byte[] ivB = receive("alice");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("                                                  ");
                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    final String messageBob = "At the old tree.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    final byte[] ivA = encrypt.getIV();
                    send("alice", ivA);

                    i++;
                }

                if(i == 6) {
                    final byte[] received = receive("alice");

                    final byte[] ivB = receive("alice");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("                                                  ");
                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    final String messageBob = "At the old tree";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    final byte[] ivA = encrypt.getIV();
                    send("alice", ivA);

                    i++;
                }

                if(i == 7) {
                    final byte[] received = receive("alice");

                    final byte[] ivB = receive("alice");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("                                                  ");
                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    final String messageBob = "I will move";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    final byte[] ivA = encrypt.getIV();
                    send("alice", ivA);

                    i++;
                }

                if(i == 8) {
                    final byte[] received = receive("alice");

                    final byte[] ivB = receive("alice");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("                                                  ");
                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    final String messageBob = "Hey alice.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    final byte[] ivA = encrypt.getIV();
                    send("alice", ivA);

                    i++;
                }

                if(i == 9) {
                    final byte[] received = receive("alice");

                    final byte[] ivB = receive("alice");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("                                                  ");
                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    final String messageBob = "Finally";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    final byte[] ivA = encrypt.getIV();
                    send("alice", ivA);

                    i++;
                }

                if(i == 10) {
                    final byte[] received = receive("alice");

                    final byte[] ivB = receive("alice");
                    IvParameterSpec ivSpecB = new IvParameterSpec(ivB);

                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpecB);
                    final byte[] dt = decrypt.doFinal(received);

                    System.out.println("                                                  ");
                    System.out.println("[Alice] Bob's decrypted message: " + new String(dt));

                    final String messageBob = "The end.";
                    final byte[] ptB = messageBob.getBytes();
                    encrypt.init(Cipher.ENCRYPT_MODE, key);

                    final byte[] cipherTextB = encrypt.doFinal(ptB);
                    send("alice", cipherTextB);

                    final byte[] ivA = encrypt.getIV();
                    send("alice", ivA);

                    i++;
                }
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
