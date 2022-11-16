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
 * AES in CTR mode. Then exchange ten messages between Alice and Bob.
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
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CTR (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */

                Cipher aesCTR  = Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte [] plainText = "I love you Bob. Kisses, Alice.".getBytes();

                for(int i=0; i<=1000;i++) {
                    if(i!=0){
                        byte [] received = receive("bob");
                        aesCTR.init(Cipher.ENCRYPT_MODE, key);
                        byte [] cipherText = aesCTR.doFinal(plainText);
                        aesCTR.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(receive("bob")));
                        System.out.println("Message: "+ new String(aesCTR.doFinal(received)));
                        System.out.println(i + ": CipherText: "+ Agent.hex( received));
                    }
                    else{
                        aesCTR.init(Cipher.ENCRYPT_MODE, key);
                        byte [] cipherText = aesCTR.doFinal(plainText);
                        send("bob", aesCTR.doFinal(plainText));
                        send("bob",aesCTR.getIV());
                        Thread.sleep(100);
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
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
                Cipher aesCTR  = Cipher.getInstance("AES/CBC/PKCS5Padding");


                byte[] received = receive("alice");
                byte[] iv = receive("alice");
                aesCTR.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                byte [] message = aesCTR.doFinal(received);


                byte [] plainTextw = "No love for you from me. Lp in lep pozdrav.".getBytes();
                aesCTR.init(Cipher.ENCRYPT_MODE,key, new IvParameterSpec(iv));;
                byte [] cipherText = aesCTR.doFinal(plainTextw);


                System.out.println("): CipherText: "+ Agent.hex(received));
                System.out.println("): Message received from alice: " + new String(message));

                send("alice", cipherText);
                send("alice",iv);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
