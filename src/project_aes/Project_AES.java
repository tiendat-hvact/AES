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
        AES_Controller controller = new AES_Controller();
        String input = "Nguyễn Tiến";
        controller.formatInput(input);
        String key = "0123456789101112";
        controller.checkKeyLength(key);
        controller.formatkey(key);
        controller.EncrptionAES();
    }

}
