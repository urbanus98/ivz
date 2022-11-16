package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
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
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CTR (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */


                Cipher aesCTR  = Cipher.getInstance("ChaCha20");
                byte [] plainText = "I love you Bob. Kisses, Alice.".getBytes();
                byte [] nonce = new byte[12];
                new SecureRandom().nextBytes(nonce);
                int counter = 5;



                for(int i=0; i<=9;i++) {
                    if(i!=0){
                        byte[] recieved = receive("bob");
                        byte[] rec = receive("bob");
                        aesCTR.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(rec,i));
                        byte [] message = aesCTR.doFinal(recieved);
                        System.out.println("Bob shrug: "+ new String(message));
                    }
                    else{

                        aesCTR.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, i));
                        byte [] cipherText = aesCTR.doFinal(plainText);
                        send("bob", cipherText);
                        send("bob", nonce);

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
                Cipher aesCTR  = Cipher.getInstance("ChaCha20");
                byte [] nonce = new byte[12];
                new SecureRandom().nextBytes(nonce);
                int counter = 5;

                for(int  i = 0;i<=9;i++) {

if(i==0) {
    byte[] received = receive("alice");
    byte[] recNonce = receive("alice");

    aesCTR.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(recNonce, i));
    System.out.println("Ciphertext: " + received);
    System.out.println("Message" + new String(aesCTR.doFinal(received)));
}else {


    byte[] plainText = "No love from me. Lp in lep pozdrav.".getBytes();


    aesCTR.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, i));
    send("alice", aesCTR.doFinal(plainText));
    send("alice", nonce);
}
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}