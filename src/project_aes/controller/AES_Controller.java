/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package project_aes.controller;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author ADMIN
 */
public class AES_Controller {

    //Số cột chứa một trạng thái trong AES
    private int Nb = 4;
    // Số vòng lặp trong AES Cipher
    private int Nr = 10;
    // Số khóa vòng vào từng vòng mã hóa và giải mã
    private int Nk = 4;

    // Mảng lưu trữ đầu vào
    private int[] input;

    // Độ dài chuỗi đầu vào
    private int inputLength;

    // Kết quả đầu ra
    private String output;

    // Mảng lưu trữ các kết quả biến đổi bên trong
    private int[] state = new int[4];

    // Khóa đầu vào cho chương trình
    private int[] key = new int[32];

    //Hiển thị dãy số Hexa
    public String showHexaNumber(int w) {
        int i, byteAtI;
        String result = "";
        for (i = 1; i <= 8; i++) {
            byteAtI = (w >> 32 - i * 4) & 0xF;
            result += Integer.toHexString(byteAtI);
            if (i % 2 == 0) {
                result += " ";
            }
        }
        return result;
    }

    //====================================================================================================================================================================
    // KIỂM TRA, BIẾN ĐỔI CÁC THAM SỐ ĐẦU VÀO VÀ KẾT QUẢ ĐẦU RA 
    // Biến đổi chuỗi số Hexa đầu vào thành một mảng hexa
    public int[] formatToHexaMatrix(String hexaString) throws UnsupportedEncodingException {
        int resultLength = hexaString.length() / 8;
        int[] result = new int[resultLength];
        int byte1, byte2, byte3, byte4;
        for (int i = 0; i < resultLength; i++) {
            byte1 = Integer.valueOf(hexaString.substring(i * 8, i * 8 + 2), 16);
            byte2 = Integer.valueOf(hexaString.substring(i * 8 + 2, i * 8 + 4), 16);
            byte3 = Integer.valueOf(hexaString.substring(i * 8 + 4, i * 8 + 6), 16);
            byte4 = Integer.valueOf(hexaString.substring(i * 8 + 6, i * 8 + 8), 16);
            result[i] = (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4;
        }
        return result;
    }

    // Biến đổi chuỗi đầu vào thành mảng Input
    public void formatInput(String input, String typeInput) throws UnsupportedEncodingException {
        this.input = new int[99999999];
        String hexaString = "";
        boolean flag = false;
        if (typeInput.equals("UTF-8")) {
            while (!flag) {
                byte[] myBytes = input.getBytes("UTF-8");
                hexaString = DatatypeConverter.printHexBinary(myBytes);
                if (hexaString.length() % 32 != 0) {
                    input += " ";
                } else {
                    flag = true;
                }
            }
        } else if (typeInput.equals("Hexa")) {
            this.inputLength = input.length();
            while (!flag) {
                hexaString = input.replaceAll(" ", "");
                if (hexaString.length() % 32 != 0) {
                    input += 0;
                } else {
                    flag = true;
                }
            }
        }
        this.input = formatToHexaMatrix(hexaString);
    }

    // Kiểm tra độ dài khóa
    public boolean checkKeyLength(String key, String type) {
        if (type.equals("128 bits") && (key.length() == 16)) {
            Nk = 4;
            Nr = 10;
        } else if (type.equals("192 bits") && (key.length() == 24)) {
            Nk = 6;
            Nr = 12;
        } else if (type.equals("256 bits") && (key.length() == 32)) {
            Nk = 8;
            Nr = 14;
        } else {
            return false;
        }
        return true;
    }

    // Biến đổi khóa thành mảng
    public void formatkey(String key) throws UnsupportedEncodingException {
        byte[] myBytes = key.getBytes("UTF-8");
        String hexaString = DatatypeConverter.printHexBinary(myBytes);
        this.key = formatToHexaMatrix(hexaString);
    }

    // Lấy ra mảng byte trong chuỗi hexa
    private static byte[] fromHex(String hex) {
        byte[] binary = new byte[hex.length() / 2];
        for (int i = 0; i < binary.length; i++) {
            binary[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return binary;
    }

    // Biến đổi chuỗi đầu ra
    public String formatOutput(String typeOutput, Boolean decrption) throws UnsupportedEncodingException {
        if (typeOutput.equals("UTF-8")) {
            this.output = this.output.replaceAll(" ", "");
            byte[] bytes = fromHex(this.output);
            this.output = new String(bytes, StandardCharsets.UTF_8);
            if (decrption) {
                this.output = this.output.trim();
            }
        } else if (decrption && typeOutput.equals("Hexa")) {
            this.output = this.output.substring(0, this.inputLength);
        }
        return this.output;
    }

    //====================================================================================================================================================================
    // GIẢI THUẬT SINH KHÓA
    // Bước 1: Rotword - Quay trái 1 byte (8 bit)
    public int rotword(int w) {
        int byte1 = (w >> 24) & 0xFF;
        int byte234 = w & 0xFFFFFF;
        int rot = (byte234 << 8) | byte1;
        return rot;
    }

    // Bước 2: subBytes - Đổi giá trị byte tương ứng thành giá trị trong bảng Sbox
    public int subWord(int w) {
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
        for (i = 1; i <= Nb; i++) {
            byteAtI = (w >> (32 - i * 8)) & 0xFF;
            subByteAtI = sBox[byteAtI];
            result = (result << 8) | subByteAtI;
        }
        return result;
    }

    // Bước 3: Rcon - Tính giá trị Rcon thứ i
    public int xorRcon(int w, int i) {
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

    // Hàm sinh khóa
    public int[] keyExpansion(int[] key) {
        int i;
        int temp = 0;
        int[] w = new int[Nb * (Nr + 1)];

        for (i = 0; i < Nk; i++) {
            w[i] = key[i];
        }

        for (i = Nk; i < Nb * (Nr + 1); i++) {
            temp = w[i - 1];
            if (i % Nk == 0) {
                temp = rotword(temp);
                temp = subWord(temp);
                temp = xorRcon(temp, i / Nk);
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }
            w[i] = w[i - Nk] ^ temp;
        }
        return w;
    }

    //====================================================================================================================================================================
    // MÃ HÓA
    // Bước 1: AddRoundKey
    public int[] addRoundKey(int[] state, int[] key) {
        int[] result = new int[4];
        result[0] = state[0] ^ key[0];
        result[1] = state[1] ^ key[1];
        result[2] = state[2] ^ key[2];
        result[3] = state[3] ^ key[3];
        return result;
    }

    // Bước 2: SubBytes
    public int[] subBytes(int[] state) {
        int i;
        int[] result = new int[4];
        for (i = 0; i < 4; i++) {
            result[i] = subWord(state[i]);
        }
        return result;
    }

    // Bước 3: ShiftRow
    public int[] shiftrow(int[] state) {
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
    public int nhan2(int w) {
        int result = w << 1;
        if (result >= 256) {
            result = result ^ 0x11b;
        }
        return result & 0xFF;
    }

    // Hàm nhân 3 với byte
    public int nhan3(int w) {
        int result = w ^ nhan2(w);
        return result & 0xFF;
    }

    // Hàm nhân dùng cho từng cột
    public int multipleCollumn(int w) {
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
    public int[] mixCollumn(int[] state) {
        int i;
        int[] result = new int[4];
        for (i = 0; i < 4; i++) {
            result[i] = multipleCollumn(state[i]);
        }
        return result;
    }

    public void showMatrix(int[] w) {
        for (int i = 0; i < w.length; i++) {
            System.out.println(showHexaNumber(w[i]));
        }
    }

    public int[] getKey(int[] key, int i) {
        int j;
        int[] w = keyExpansion(key);
        int[] result = new int[4];
        for (j = 0; j < 4; j++) {
            result[j] = w[i * 4 + j];
        }
        return result;
    }

    public String encrptionAES() throws UnsupportedEncodingException {
        int i, j;
        this.output = "";

//        System.out.println("====== MÃ HÓA ======");
        for (i = 0; i < input.length; i += 4) {
            state[0] = input[i];
            state[1] = input[i + 1];
            state[2] = input[i + 2];
            state[3] = input[i + 3];

//            System.out.println("");
//            System.out.println("Input:");
//            showMatrix(state);

//            System.out.println("");
//            System.out.println("Key:");
//            showMatrix(getKey(key, 0));

            state = addRoundKey(state, getKey(key, 0));

//            System.out.println("");
//            System.out.println("Vòng 1:");
//            showMatrix(state);

            for (j = 1; j <= Nr - 1; j++) {
                state = subBytes(state);

//                System.out.println("");
//                System.out.println("SubBytes:");
//                showMatrix(state);

                state = shiftrow(state);

//                System.out.println("");
//                System.out.println("Shiftrow:");
//                showMatrix(state);

                state = mixCollumn(state);

//                System.out.println("");
//                System.out.println("MixCollumn:");
//                showMatrix(state);

//                System.out.println("");
//                System.out.println("Key:");
//                showMatrix(getKey(key, j));

                state = addRoundKey(state, getKey(key, j));

//                System.out.println("");
//                System.out.println("Vòng " + (j + 1));
//                showMatrix(state);

            }

            state = subBytes(state);

//            System.out.println("");
//            System.out.println("SubBytes");
//            showMatrix(state);

            state = shiftrow(state);

//            System.out.println("");
//            System.out.println("Shiftrow:");
//            showMatrix(state);

            state = addRoundKey(state, getKey(key, Nr));

//            System.out.println("");
//            System.out.println("Output:");
//            showMatrix(state);

            for (j = 0; j < 4; j++) {
                this.output += showHexaNumber(state[j]);
            }
        }

        return output.toUpperCase();
    }

    //====================================================================================================================================================================
    // GIẢI MÃ
    // Bước 1: Invert ShiftRow
    public int[] invertShiftrow(int[] state) {
        int i;
        int[] result = new int[4];
        for (i = 0; i < 4; i++) {
            int byte1 = state[i] & 0xFF000000;
            int byte2 = state[(i + 3) % 4] & 0xFF0000;
            int byte3 = state[(i + 2) % 4] & 0xFF00;
            int byte4 = state[(i + 1) % 4] & 0xFF;
            result[i] = byte1 | byte2 | byte3 | byte4;
        }
        return result;
    }

    // Bước 2: Invert SubBytes
    public int invertSubWord(int w) {
        int invSbox[] = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };
        int i, byteAtI, subByteAtI;
        int result = 0;
        for (i = 1; i <= Nb; i++) {
            byteAtI = (w >> (32 - i * 8)) & 0xFF;
            subByteAtI = invSbox[byteAtI];
            result = (result << 8) | subByteAtI;
        }
        return result;
    }

    public int[] invertSubBytes(int[] state) {
        int i;
        int[] result = new int[4];
        for (i = 0; i < 4; i++) {
            result[i] = invertSubWord(state[i]);
        }
        return result;
    }

    public int nhan9(int w) {
        int result = (w << 3) ^ w;
        if (result > (256 << 2)) {
            result = result ^ (0x11b << 2);
        }
        if (result > (256 << 1)) {
            result = result ^ (0x11b << 1);
        }
        if (result > 256) {
            result = result ^ 0x11b;
        }
        return result & 0xFF;
    }

    public int nhanB(int w) {
        int result = (w << 3) ^ (w << 1) ^ w;
        if (result > (256 << 2)) {
            result = result ^ (0x11b << 2);
        }
        if (result > (256 << 1)) {
            result = result ^ (0x11b << 1);
        }
        if (result > 256) {
            result = result ^ 0x11b;
        }
        return result & 0xFF;
    }

    public int nhanD(int w) {
        int result = (w << 3) ^ (w << 2) ^ w;
        if (result >= (256 << 2)) {
            result = result ^ (0x11b << 2);
        }
        if (result >= (256 << 1)) {
            result = result ^ (0x11b << 1);
        }
        if (result >= 256) {
            result = result ^ 0x11b;
        }
        return result & 0xFF;
    }

    public int nhanE(int w) {
        int result = (w << 3) ^ (w << 2) ^ (w << 1);
        if (result >= (256 << 2)) {
            result = result ^ (0x11b << 2);
        }
        if (result >= (256 << 1)) {
            result = result ^ (0x11b << 1);
        }
        if (result >= 256) {
            result = result ^ 0x11b;
        }
        return result & 0xFF;
    }

    public int invertMultipleCollumn(int w) {
        int byte1 = (w >> 24) & 0xFF;
        int byte2 = (w >> 16) & 0xFF;
        int byte3 = (w >> 8) & 0xFF;
        int byte4 = w & 0xFF;

        int result1 = nhanE(byte1) ^ nhanB(byte2) ^ nhanD(byte3) ^ nhan9(byte4);
        int result2 = nhan9(byte1) ^ nhanE(byte2) ^ nhanB(byte3) ^ nhanD(byte4);
        int result3 = nhanD(byte1) ^ nhan9(byte2) ^ nhanE(byte3) ^ nhanB(byte4);
        int result4 = nhanB(byte1) ^ nhanD(byte2) ^ nhan9(byte3) ^ nhanE(byte4);

        return (result1 << 24) | (result2 << 16) | (result3 << 8) | result4;
    }

    public int[] invertMixCollumn(int[] state) {
        int i;
        int[] result = new int[4];
        for (i = 0; i < 4; i++) {
            result[i] = invertMultipleCollumn(state[i]);
        }
        return result;
    }

    public int[] invertGetKey(int[] key, int i) {
        int j;
        int[] w = keyExpansion(key);
        int[] result = new int[4];
        for (j = 0; j < 4; j++) {
            result[j] = w[w.length - (4 * (i + 1)) + j];
        }
        return result;
    }

    public String decryptionAES() {
        int i, j;
        this.output = "";
        
//        System.out.println("====== GIẢI MÃ ======");
        for (i = 0; i < input.length; i += 4) {
            state[0] = input[i];
            state[1] = input[i + 1];
            state[2] = input[i + 2];
            state[3] = input[i + 3];

//            System.out.println("");
//            System.out.println("Input:");
//            showMatrix(state);

//            System.out.println("");
//            System.out.println("Key:");
//            showMatrix(invertGetKey(key, 0));

            state = addRoundKey(state, invertGetKey(key, 0));

            System.out.println("");
            System.out.println("Vòng 1:");
            showMatrix(state);

            for (j = 1; j <= Nr - 1; j++) {
                state = invertShiftrow(state);

//                System.out.println("");
//                System.out.println("InvertShiftrow:");
//                showMatrix(state);

                state = invertSubBytes(state);

//                System.out.println("");
//                System.out.println("InvertSubBytes:");
//                showMatrix(state);

//                System.out.println("");
//                System.out.println("Key:");
//                showMatrix(invertGetKey(key, j));

                state = addRoundKey(state, invertGetKey(key, j));

//                System.out.println("");
//                System.out.println("AddRoundKey");
//                showMatrix(state);

                state = invertMixCollumn(state);

//                System.out.println("");
//                System.out.println("Vòng " + (j + 1));
//                showMatrix(state);

            }
            state = invertShiftrow(state);

//            System.out.println("");
//            System.out.println("InvertShiftrow:");
//            showMatrix(state);

            state = invertSubBytes(state);

//            System.out.println("");
//            System.out.println("InvertSubBytes:");
//            showMatrix(state);

            state = addRoundKey(state, invertGetKey(key, Nr));

//            System.out.println("");
//            System.out.println("Output:");
//            showMatrix(state);

            for (j = 0; j < 4; j++) {
                this.output += showHexaNumber(state[j]);
            }
        }
        return output.toUpperCase();
    }
}
