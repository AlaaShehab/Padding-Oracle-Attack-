public class PaddingOracleAttackSimulation {

    private static class Sender {
        private byte[] secretKey;
        private String secretMessage = "Top secret!";

        public Sender(byte[] secretKey) {
            this.secretKey = secretKey;
        }

        // This will return both iv and ciphertext
        public byte[] encrypt() {
            return AESDemo.encrypt(secretKey, secretMessage);
        }
    }

    private static class Receiver {
        private byte[] secretKey;

        public Receiver(byte[] secretKey) {
            this.secretKey = secretKey;
        }

        // Padding Oracle (Notice the return type)
        public boolean isDecryptionSuccessful(byte[] ciphertext) {
            return AESDemo.decrypt(secretKey, ciphertext) != null;
        }
    }

    public static class Adversary {

        // This is where you are going to develop the attack
        // Assume you cannot access the key.
        // You shall not add any methods to the Receiver class.
        // You only have access to the receiver's "isDecryptionSuccessful" only.
        public String extractSecretMessage(Receiver receiver, byte[] ciphertext) {

            byte[] iv = AESDemo.extractIV(ciphertext);
            byte[] ciphertextBlocks = AESDemo.extractCiphertextBlocks(ciphertext);
            boolean result = receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(iv, ciphertextBlocks));
            System.out.println(result); // This is true initially, as the ciphertext was not altered in any way.

            // Get the padding.
            int padding = 0;
            for (int i = 0; i < iv.length; i++) {
                iv[i] = 5;
                result = receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(iv, ciphertextBlocks));
                if (!result) {
                    padding = iv.length - i;
                    break;
                }
            }
            iv = AESDemo.extractIV(ciphertext);
            String encryptedText = "";
            while (iv.length - padding > 0) {
                // Increase the padding by 01
                for (int i = iv.length - 1; i >= iv.length - padding; i--) {
                    iv[i] = (byte) (iv[i] ^ padding ^ (padding + 1));
                }
                padding++;
                int current = iv.length - padding;
                // Get the current byte of data
                for (int i = 0; i <= 255; i++) {
                    iv[current] = (byte) (i);
                    result = receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(iv, ciphertextBlocks));
                    if (result) {
                        encryptedText = (char)(padding ^ iv[current] ^ ciphertext[current]) + encryptedText;
                        break;
                    }
                }
            }
            return encryptedText;
        }
    }

    public static void main(String[] args) {

        byte[] secretKey = AESDemo.keyGen();
        Sender sender = new Sender(secretKey);
        Receiver receiver = new Receiver(secretKey);

        // The adversary does not have the key
        Adversary adversary = new Adversary();

        // Now, let's get some valid encryption from the sender
        byte[] ciphertext = sender.encrypt();

        // The adversary  got the encrypted message from the network.
        // The adversary's goal is to extract the message without knowing the key.
        String message = adversary.extractSecretMessage(receiver, ciphertext);

        System.out.println("Extracted message = " + message);
    }
}