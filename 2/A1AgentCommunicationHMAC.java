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
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */

        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        final String aliceSaysToBob [] = new String[]{
                "Leave me alone  6!",
                "Leave me alone  7!",
                "Leave me alone  8!",
                "Leave me alone  9!",
                "Leave me alone  10!"
        };

        final String bobSaysToAlice []  = new String[]{
                "Leave me alone  1!",
                "Leave me alone  2!",
                "Leave me alone  3!",
                "Leave me alone  4!",
                "Leave me alone  5!"
        };

            env.add(new Agent("alice") {
                @Override
                public void task() throws Exception {
                    final Mac a = Mac.getInstance("HmacSHA256");
                    a.init(key);
                    for(int j = 0; j< 2; j++)
                    {
                    for (byte i = 0; i < 5; i++) {
                        if (i % 2 == 0) {
                            byte[] aliceTag = a.doFinal(aliceSaysToBob[i].getBytes(StandardCharsets.UTF_8));
                            //  send("bob", new byte[]{i});
                            send("bob", aliceTag);
                        } else {
                            byte[] bobTag1 = receive("bob");
                            byte[] tag1 = a.doFinal(bobSaysToAlice[i].getBytes(StandardCharsets.UTF_8));

                            if (verify3(tag1, bobTag1, key)) {
                                System.out.println(new String(bobSaysToAlice[i]));
                            } else {
                                System.out.println("https://www.youtube.com/watch?v=2P5qbcRAXVk");
                            }
                        }
                        //   Thread.sleep(1000);
                    }
                }
                }
            });

            env.add(new Agent("bob") {
                @Override
                public void task() throws Exception {

                    final Mac b = Mac.getInstance("HmacSHA256");
                    b.init(key);
                    for (int j = 0; j<2; j++){
                    for (int i = 0; i < 5; i++) {
                        if (i % 2 == 1) {
                            byte[] bobTag = b.doFinal(bobSaysToAlice[i].getBytes(StandardCharsets.UTF_8));
                            send("alice", bobTag);
                        } else {

                            byte[] bobTag1 = receive("alice");
                            byte[] tag1 = b.doFinal(aliceSaysToBob[i].getBytes(StandardCharsets.UTF_8));

                            if (verify3(tag1, bobTag1, key)) {
                                System.out.println(new String(aliceSaysToBob[i]));
                            } else {
                                System.out.println("https://www.youtube.com/watch?v=2P5qbcRAXVk");
                            }
                        }
                        //Thread.sleep(1000);
                    }
                    }

                }
            });

            env.connect("alice", "bob");
            env.start();
        }

   // }
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
}
