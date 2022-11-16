package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;


public class ActiveMITM {
    public static void main(String[] args) throws Exception {
        // David and FMTP server both know the same shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();
        final Key key1 = KeyGenerator.getInstance("AES").generateKey();
        final Environment env = new Environment();

        env.add(new Agent("david") {
            @Override
            public void task() throws Exception {
                final String message = "prf.denis@fri.si\n" +
                        "david@fri.si\n" +
                        "Some ideas for the exam\n\n" +
                        "Hi! Find attached <some secret stuff>!";

                final Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aes.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();
                print("sending: '%s' (%s)", message, hex(ct));

                send("server", ct);
                send("server", iv);
            }
        });

        env.add(new Agent("student") {
            @Override
            public void task() throws Exception {
                final byte[] bytes = receive("david");
                final byte[] iv = receive("david");
                print(" IN: %s", hex(bytes));
                final String message1 = "12345678912345";

                final Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aes.init(Cipher.ENCRYPT_MODE, key1);
                final byte[] ct = aes.doFinal(message1.getBytes(StandardCharsets.UTF_8));
                final byte[] iv1 = aes.getIV();
                int emailLEN = ct.length;

                for (byte b : ct) {
                    System.out.println(Integer.toBinaryString(b & 255 | 256).substring(1));
                }

                final Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                enc.init(Cipher.DECRYPT_MODE, key1, new IvParameterSpec(iv1));
                final byte[] pt = enc.doFinal(ct);
                final String message = new String(pt, StandardCharsets.UTF_8);



                print(message);

                print(String.valueOf(emailLEN));

                byte[] emailofprof= Arrays.copyOfRange(bytes, 0, emailLEN);

                byte[] messageofprof = Arrays.copyOfRange(bytes, emailLEN, bytes.length);
                int messageofprofLEN = messageofprof.length;


                byte[] fakemessage = new byte[emailLEN+messageofprofLEN];


                System.arraycopy(ct, 0, fakemessage, 0, emailLEN);
                System.arraycopy(messageofprof, 0, fakemessage, emailLEN, messageofprofLEN);


                
                



                // As the person-in-the-middle, modify the ciphertext
                // so that the FMTP server will send the email to you
                // (Needless to say, you are not allowed to use the key
                // that is being used by david and server.)

                print("OUT: %s", hex(fakemessage));
                send("server", fakemessage);
                send("server", iv);
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                final byte[] ct = receive("david");
                final byte[] iv = receive("david");
                final Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aes.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                final byte[] pt = aes.doFinal(ct);
                final String message = new String(pt, StandardCharsets.UTF_8);

                print("got: '%s' (%s)", message, hex(ct));
            }
        });

        env.mitm("david", "server", "student");
        env.start();
    }
}
