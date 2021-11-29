/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package project_aes;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import project_aes.controller.AES_Controller;

/**
 *
 * @author ADMIN
 */
public class Project_AES {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnsupportedEncodingException {
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
        
        AES_Controller controller = new AES_Controller();
        int[] EncrptionAES = controller.EncrptionAES(state, key);
        controller.decryptionAES(EncrptionAES, key);
//        String input = "Phạm Văn Tài";
//        controller.formatInput(input);
//        String key = "12345678912345678912345678912345";
//        controller.checkKeyLength(key);
//        controller.formatkey(key);
//        System.out.println(controller.encrptionAES());

    }

}
