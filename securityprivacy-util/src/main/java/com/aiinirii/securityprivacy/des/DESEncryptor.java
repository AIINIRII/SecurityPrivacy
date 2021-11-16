package com.aiinirii.securityprivacy.des;

import com.aiinirii.securityprivacy.Encryptor;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class DESEncryptor implements Encryptor {

    private final int[] INITIAL_PERMUTATION = new int[]{
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7,
    };

    private final int[] FINAL_PERMUTATION_REVERSE = new int[]{
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25,
    };

    private final int[] EXPANSION_FUNCTION = new int[]{
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1,
    };

    private final int[] PERMUTATION = new int[]{
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25,
    };

    private final int[] PERMUTED_CHOICE_ONE_LEFT = new int[]{
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
    };

    private final int[] PERMUTED_CHOICE_ONE_RIGHT = new int[]{
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4,
    };

    private final int[] PERMUTED_CHOICE_ONE = new int[]{
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4,
    };

    private final int[] PERMUTED_CHOICE_TWO = new int[]{
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32,
    };

    private final int[][][] S_MATRIX = new int[][][]{
            new int[][]{
                    new int[]{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    new int[]{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    new int[]{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    new int[]{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
            },
            new int[][]{
                    new int[]{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    new int[]{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    new int[]{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    new int[]{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
            },
            new int[][]{
                    new int[]{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    new int[]{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    new int[]{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    new int[]{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
            },
            new int[][]{
                    new int[]{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    new int[]{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    new int[]{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    new int[]{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
            },
            new int[][]{
                    new int[]{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    new int[]{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    new int[]{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    new int[]{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
            },
            new int[][]{
                    new int[]{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    new int[]{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    new int[]{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    new int[]{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
            },
            new int[][]{
                    new int[]{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    new int[]{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    new int[]{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    new int[]{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
            },
            new int[][]{
                    new int[]{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    new int[]{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    new int[]{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    new int[]{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
            }
    };

    private final int[] BITS_ROTATION_TABLE = new int[]{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,};

    private static long permute(int[] table, int blockLength, long block) {
        long res = 0;
        for (int b : table) {
            int srcPos = blockLength - b;
            res = (res << 1) | (block >> srcPos & 0x01);
        }
        return res;
    }

    @Override
    public String encryptMessage(String message, String key, Charset charset) throws Exception {
        byte[] messageBytes = message.getBytes(charset);
        return new String(Base64.getEncoder().encode(encryptBytes(messageBytes, key)));
    }

    @Override
    public byte[] encryptBytes(byte[] bytes, String key) throws Exception {
        // convert key into long value
        long keyLong = convertStringKeyIntoLong(key);
        List<Long> keyList = generateSubKeys(keyLong);

        // initialize the result bytes array
        byte[] res = new byte[bytes.length];

        // encrypt every blocks
        for (int i = 0; i < bytes.length; i += 8) {
            long messageBlock = convertBytesToLong(bytes, i);
            long encryptedBits = encryptBlock(messageBlock, keyList);
            convertLongToBytes(res, i, encryptedBits);
        }
        return res;
    }

    @Override
    public String decryptMessage(String message, String key, Charset charset) throws Exception {
        byte[] messageBeforeBase64 = Base64.getDecoder().decode(message.getBytes());
        return new String(decryptBytes(messageBeforeBase64, key), charset);
    }

    @Override
    public byte[] decryptBytes(byte[] bytes, String key) throws Exception {
        // convert key into long value
        long keyLong = convertStringKeyIntoLong(key);
        List<Long> keyList = generateSubKeys(keyLong);

        // initialize the result bytes array
        byte[] res = new byte[bytes.length];

        // encrypt every blocks
        for (int i = 0; i < bytes.length; i += 8) {
            long messageBlock = convertBytesToLong(bytes, i);
            long encryptedBits = decryptBlock(messageBlock, keyList);
            convertLongToBytes(res, i, encryptedBits);
        }
        return res;
    }

    /**
     * encrypt every block
     *
     * @param messageBlock 64bits message block
     * @param keyList      generated key list
     * @return encrypted message
     */
    protected long encryptBlock(long messageBlock, List<Long> keyList) {
        // 1. Initial Permutation
        long mT = initialPermutation(messageBlock);
        // 2. Generate Sub-keys
        // already generated outside the function
        // 3. Iteration process
        long iterationOutputs = iterationProcess(mT, keyList, true);
        // 4. Reverse Permutation
        return reversePermutation(iterationOutputs);
    }

    /**
     * decrypt every block
     *
     * @param messageBlock 64bits message block
     * @param keyList      generated key list
     * @return decrypted message
     */
    protected long decryptBlock(long messageBlock, List<Long> keyList) {
        // 1. Initial Permutation
        long mT = initialPermutation(messageBlock);
        // 2. Generate Sub-keys
        // already generated outside the function
        // 3. Iteration process
        long iterationOutputs = iterationProcess(mT, keyList, false);
        // 4. Reverse Permutation
        return reversePermutation(iterationOutputs);
    }

    /**
     * have 16 iterations with mT
     *
     * @param mT      transformed message block
     * @param keyList the generated sub-keys
     * @return iteration process's output
     */
    protected long iterationProcess(long mT, List<Long> keyList, boolean isEncrypt) {
        // split into two parts
        long leftMT = (mT >> 32) & 0xFFFFFFFFL;
        long rightMT = mT & 0xFFFFFFFFL;

        if (isEncrypt) {
            // 16 iterations
            for (int i = 0; i < 16; i++) {
                // f function
                long fOutput = fFunction(keyList, rightMT, i);

                long temp = rightMT;
                rightMT = leftMT ^ fOutput;
                leftMT = temp;
            }
        } else {
            // 16 iterations
            for (int i = 15; i >= 0; i--) {
                // f function
                long fOutput = fFunction(keyList, rightMT, i);

                long temp = rightMT;
                rightMT = leftMT ^ fOutput;
                leftMT = temp;
            }
        }

        return rightMT << 32 | leftMT;
    }

    protected long convertStringKeyIntoLong(String key) throws Exception {
        long keyLong = 0;
        if (key.length() <= 8) {
            long key64Long = convertBytesToLong(key.getBytes(), 0);
            for (int i = 0; i < 64; i += 8) {
                keyLong = (keyLong << 8) | ((key64Long >> (64 - i - 8)) & 0x7F);
            }
        } else {
            throw new Exception("Key's length should not longer than 8");
        }
        return keyLong;
    }

    /**
     * convert bytes to long
     *
     * @param bytes  src
     * @param offset offset of array
     * @return the long value
     */
    private long convertBytesToLong(byte[] bytes, int offset) {
        long l = 0;
        for (int i = 0; i < 8; i++) {
            byte value;
            if ((offset + i) < bytes.length) {
                value = bytes[offset + i];
            } else {
                value = 0;
            }
            l = l << 8 | (value & 0xFFL);
        }
        return l;
    }

    /**
     * convert long to bytes
     *
     * @param bytes  target bytes' array
     * @param offset offset of the array
     * @param l      the long value
     */
    private void convertLongToBytes(byte[] bytes, int offset, long l) {
        for (int i = 7; i > -1; i--) {
            if ((offset + i) < bytes.length) {
                bytes[offset + i] = (byte) (l & 0xFF);
                l = l >> 8;
            } else {
                break;
            }
        }
    }

    private long reversePermutation(long iterationOutputs) {
        return permute(FINAL_PERMUTATION_REVERSE, 64, iterationOutputs);
    }

    private long fFunction(List<Long> keyList, long rightMT, int i) {
        // expand the right part
        long expandPermutationRes = expandPermutation(rightMT);

        // use xor generate s box's input
        long sInput = expandPermutationRes ^ keyList.get(i);

        // substitute box
        long sOutput = substituteBox(sInput);

        // permutation substitution
        return permutationAfterSBox(sOutput);
    }

    private long permutationAfterSBox(long sOutput) {
        return permute(PERMUTATION, 32, sOutput);
    }

    /**
     * substitute box is implemented here
     *
     * @param sInput 48 input bytes
     * @return 32 output bytes
     */
    protected long substituteBox(long sInput) {
        long sOutput = 0;
        for (int i = 0; i < 48; i += 6) {
            long sBlockInput = (sInput >> (48 - i - 6)) & 0x0000003F;
            int boxIndex = i / 6;
            int sRow = (int) ((sBlockInput >> 5 << 1) | (sBlockInput & 1));
            int sCol = (int) ((sBlockInput >> 1) & 0x0000000F);
            int sBlockOutput = S_MATRIX[boxIndex][sRow][sCol];
            sOutput = (sOutput << 4) | sBlockOutput;
        }
        return sOutput;
    }

    private long expandPermutation(long rightMT) {
        return permute(EXPANSION_FUNCTION, 32, rightMT);
    }

    protected List<Long> generateSubKeys(long key) {
        List<Long> keyList = new ArrayList<>(16);

        // generate left and right keys
        long permutedKey = keyPermutedChoiceOne(key);
        long leftKey = permutedKey >> 28;
        long rightKey = permutedKey & 0x0FFFFFFF;
        for (int genKeyIndex = 0; genKeyIndex < 16; genKeyIndex++) {
            // rotate key
            int rotateValue = BITS_ROTATION_TABLE[genKeyIndex];
            leftKey = rotateKey(leftKey, rotateValue);
            rightKey = rotateKey(rightKey, rotateValue);

            long keyAfterRotation = (leftKey & 0xFFFFFFFFL) << 28 | (rightKey & 0xFFFFFFFFL);
            long genKey = keyPermutationChoiceTwo(keyAfterRotation);

            keyList.add(genKey);
        }
        return keyList;
    }

    private long keyPermutationChoiceTwo(long keyAfterRotation) {
        return permute(PERMUTED_CHOICE_TWO, 56, keyAfterRotation);
    }

    protected long rotateKey(long key, int rotateValue) {
        return ((key << rotateValue) & 0x0FFFFFFF) | (key >> (28 - rotateValue));
    }

    protected long initialPermutation(long messageBlock) {
        return permute(INITIAL_PERMUTATION, 64, messageBlock);
    }

    protected long keyPermutedChoiceOne(long key) {
        return permute(PERMUTED_CHOICE_ONE, 64, key);
    }

}
