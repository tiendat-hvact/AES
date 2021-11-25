/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package project_aes;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import project_aes.controller.AES_Controller;

/**
 *
 * @author ADMIN
 */
public class Project_AES {

    /**
     * @param args the command line arguments
     */
    //Hiển thị một dãy gồm 4 số hexa, mỗi số đủ 2 byte => tổng là 8 byte
    public static void showHexaNumber(int w) {
        int byteAtI;
        for (int i = 1; i <= 8; i++) {
            byteAtI = (w >> 32 - i * 4) & 0xF;
            System.out.printf("%x", byteAtI);
        }
    }

    //==============================================================================================================================
    // GIẢI THUẬT SINH KHÓA
    // Bước 1: Rotword - Quay trái 1 byte (8 bit)
    public static int rotword(int w) {
        int byte1 = (w >> 24) & 0xFF;
        int byte234 = w & 0xFFFFFF;
        int rot = (byte234 << 8) | byte1;
        return rot;
    }

    // Bước 2: subBytes - Đổi giá trị byte tương ứng thành giá trị trong bảng Sbox
    public static int subBytesInKey(int w) {
        int sBox[] = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        };
        int i, byteAtI, subByteAtI;
        int result = 0;
        for (i = 1; i <= 4; i++) {
            byteAtI = (w >> (32 - i * 8)) & 0xFF;
            subByteAtI = sBox[byteAtI];
            result = (result << 8) | subByteAtI;
        }
        return result;
    }

    // Bước 3: Rcon - Tính giá trị Rcon thứ i
    public static int xorRcon(int w, int i) {
        int rcon[] = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
            0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39
        };
        int byte1 = (w >> 24) & 0xFF;
        int byte234 = w & 0xFFFFFF;
        int resultXor = (byte1 ^ rcon[i]) & 0xFF;
        int result = (resultXor << 24) | byte234;
        return result;
    }

    // Thiết kế vòng lặp trong sinh khóa
    //Rotword -> SubBytes -> Rcon
    public static int loopKeyExpansion(int w, int i) {
        int rot = rotword(w);
        int sub = subBytesInKey(rot);
        int result = xorRcon(sub, i);
        return result;
    }

    // Hàm sinh khóa
    public static int[] keyExpansion(int[] key) {
        int[] w = new int[44];
        w[0] = key[0];
        w[1] = key[1];
        w[2] = key[2];
        w[3] = key[3];
        int i;
        for (i = 4; i < 44; i++) {
            if (i % 4 == 0) {
                w[i] = loopKeyExpansion(w[i - 1], i / 4) ^ w[i - 4];
            } else {
                w[i] = w[i - 1] ^ w[i - 4];
            }
        }
        return w;
    }

    //==============================================================================================================================
    // MÃ HÓA
    // Bước 1: AddRoundKey
    public static int[] addRoundKey(int[] state, int[] key) {
        int[] result = new int[4];
        result[0] = state[0] ^ key[0];
        result[1] = state[1] ^ key[1];
        result[2] = state[2] ^ key[2];
        result[3] = state[3] ^ key[3];
        return result;
    }

    // Bước 2: SubBytes
    public static int[] subBytes(int[] state) {
        int i;
        int[] result = new int[4];
        for (i = 0; i < 4; i++) {
            result[i] = subBytesInKey(state[i]);
        }
        return result;
    }

    // Bước 3: ShiftRow
    public static int[] shiftrow(int[] state) {
        int i;
        int[] result = new int[4];
        for (i = 0; i < 4; i++) {
            int byte1 = state[i] & 0xFF000000;
            int byte2 = state[(i + 1) % 4] & 0xFF0000;
            int byte3 = state[(i + 2) % 4] & 0xFF00;
            int byte4 = state[(i + 3) % 4] & 0xFF;
            result[i] = byte1 | byte2 | byte3 | byte4;
        }
        return result;
    }

    // Bước 4: MixCollumn
    // Hàm nhân 2 với byte
    public static int nhan2(int w) {
        int result = w << 1;
        if (result > 256) {
            result = result ^ 0x11b;
        }
        return result & 0xFF;
    }

    // Hàm nhân 3 với byte
    public static int nhan3(int w) {
        int result = w ^ nhan2(w);
        return result & 0xFF;
    }

    // Hàm nhân dùng cho từng cột
    public static int multipleCollumn(int w) {
        int byte1 = (w >> 24) & 0xFF;
        int byte2 = (w >> 16) & 0xFF;
        int byte3 = (w >> 8) & 0xFF;
        int byte4 = w & 0xFF;

        int result1 = nhan2(byte1) ^ nhan3(byte2) ^ byte3 ^ byte4;
        int result2 = byte1 ^ nhan2(byte2) ^ nhan3(byte3) ^ byte4;
        int result3 = byte1 ^ byte2 ^ nhan2(byte3) ^ nhan3(byte4);
        int result4 = nhan3(byte1) ^ byte2 ^ byte3 ^ nhan2(byte4);

        return (result1 << 24) | (result2 << 16) | (result3 << 8) | result4;
    }

    // Hàm mixCollumn cho ra kết quả cuối cùng là 4 cột
    public static int[] mixCollumn(int[] state) {
        int i;
        int[] result = new int[4];
        for (i = 0; i < 4; i++) {
            result[i] = multipleCollumn(state[i]);
        }
        for (i = 0; i < 4; i++) {
            System.out.println(Integer.toHexString(result[i]));
        }
        return result;
    }

    public static void showMatrix(int[] w) {
        for (int i = 0; i < 4; i++) {
            showHexaNumber(w[i]);
            System.out.println("");
        }
    }

    public static int[] getKey(int[] key, int i) {
        int j;
        int[] w = keyExpansion(key);
        int[] result = new int[4];
        for (j = 0; j < 4; j++) {
            result[j] = w[i * 4 + j];
        }
        return result;
    }

    public static int[] EncrptionAES(int[] state, int[] key) {
        // Vòng đầu tiên
        state = addRoundKey(state, getKey(key, 0));
        System.out.println("Vòng 0");
        showMatrix(state);
        // Vòng thứ 1 đến thứ 9
        int i;
        for (i = 1; i <= 9; i++) {
            state = subBytes(state);
            state = shiftrow(state);
            state = mixCollumn(state);
            state = addRoundKey(state, getKey(key, i));
            System.out.println("Vòng " + i);
            showMatrix(state);
        }
        // Vòng thứ 10
        state = subBytes(state);
        state = shiftrow(state);
        state = addRoundKey(state, getKey(key, 10));
        System.out.println("Vòng 10");
        showMatrix(state);
        return state;
    }

    public static void main(String[] args) {
        //key
        int w0 = 0x2b7e1516;
        int w1 = 0x28aed2a6;
        int w2 = 0xabf71588;
        int w3 = 0x09cf4f3c;
        int key[] = {w0, w1, w2, w3};

        //input
        int[] state = new int[4];
        state[0] = 0x3243f6a8;
        state[1] = 0x885a308d;
        state[2] = 0x313198a2;
        state[3] = 0xe0370734;

        EncrptionAES(state, key);
    }

}
