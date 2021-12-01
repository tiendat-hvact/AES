/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package project_aes.view;

import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import project_aes.controller.AES_Controller;

/**
 *
 * @author ADMIN
 */
public class AES_Form extends javax.swing.JFrame {

    /**
     * Creates new form AES_Form
     */
    private final AES_Controller aesc;

    public AES_Form() {
        initComponents();
        this.aesc = new AES_Controller();
        this.setTitle("AES Encryption");
        this.setLocationRelativeTo(null);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel2 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jScrollPane3 = new javax.swing.JScrollPane();
        jTextArea3 = new javax.swing.JTextArea();
        jLabel1 = new javax.swing.JLabel();
        keyTxt = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        encrytedTxtArea = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        decrytedTxtArea = new javax.swing.JTextArea();
        decrytedBtn = new javax.swing.JButton();
        encrytedBtn = new javax.swing.JButton();
        keyTypeCbx = new javax.swing.JComboBox<>();
        decTypeCbx = new javax.swing.JComboBox<>();
        encTypeCbx = new javax.swing.JComboBox<>();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();

        jLabel2.setText("jLabel2");

        jLabel5.setText("Encrypted text");

        jTextArea3.setColumns(20);
        jTextArea3.setRows(5);
        jScrollPane3.setViewportView(jTextArea3);

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setText("Key");

        encrytedTxtArea.setColumns(20);
        encrytedTxtArea.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
        encrytedTxtArea.setLineWrap(true);
        encrytedTxtArea.setRows(5);
        encrytedTxtArea.setCursor(new java.awt.Cursor(java.awt.Cursor.TEXT_CURSOR));
        jScrollPane1.setViewportView(encrytedTxtArea);

        decrytedTxtArea.setColumns(20);
        decrytedTxtArea.setFont(new java.awt.Font("Tahoma", 0, 16)); // NOI18N
        decrytedTxtArea.setLineWrap(true);
        decrytedTxtArea.setRows(5);
        jScrollPane2.setViewportView(decrytedTxtArea);

        decrytedBtn.setAlignmentY(0.0F);
        decrytedBtn.setLabel("Decrypted");
        decrytedBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decrytedBtnActionPerformed(evt);
            }
        });

        encrytedBtn.setText("Encrypted");
        encrytedBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encrytedBtnActionPerformed(evt);
            }
        });

        keyTypeCbx.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "128 bits", "192 bits", "256 bits" }));

        decTypeCbx.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Hexa", "UTF-8" }));

        encTypeCbx.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "UTF-8", "Hexa" }));

        jLabel3.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        jLabel3.setText("MÃ HÓA AES - ADVANCED ENCRYPTION STANDARD");

        jLabel4.setText("Yêu cầu cần nhập đúng độ dài khóa ứng với từng loại khóa:");

        jLabel6.setText("Khóa 128 bits - 16 ký tự");

        jLabel7.setText("Khóa 192 bits - 24 ký tự");

        jLabel8.setText("Khóa 256 bits - 32 ký tự");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(50, 50, 50)
                        .addComponent(jLabel3))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(30, 30, 30)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel8)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel1)
                                .addGap(18, 18, 18)
                                .addComponent(keyTxt, javax.swing.GroupLayout.PREFERRED_SIZE, 362, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(keyTypeCbx, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                .addGroup(layout.createSequentialGroup()
                                    .addComponent(jLabel6)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(jLabel7))
                                .addComponent(jLabel4))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(encTypeCbx, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addComponent(encrytedBtn))
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                    .addComponent(decTypeCbx, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addGap(18, 18, 18)
                                    .addComponent(decrytedBtn))
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 514, Short.MAX_VALUE)
                                .addComponent(jScrollPane2)))))
                .addContainerGap(30, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(30, 30, 30)
                .addComponent(jLabel3)
                .addGap(30, 30, 30)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel6)
                    .addComponent(jLabel7))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel8)
                .addGap(30, 30, 30)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(keyTxt, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(keyTypeCbx, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(29, 29, 29)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(encTypeCbx, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(encrytedBtn))
                .addGap(0, 0, 0)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(30, 30, 30)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(decrytedBtn)
                    .addComponent(decTypeCbx, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(0, 0, 0)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(30, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void encrytedBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encrytedBtnActionPerformed
        if (this.aesc.checkKeyLength(keyTxt.getText(), keyTypeCbx.getSelectedItem().toString())) {
            try {
                this.aesc.formatkey(keyTxt.getText());
                this.aesc.formatInput(encrytedTxtArea.getText(), encTypeCbx.getSelectedItem().toString());
                this.aesc.encrptionAES();
                String formatOutput = this.aesc.formatOutput(decTypeCbx.getSelectedItem().toString(), false);
                decrytedTxtArea.setText(formatOutput.toUpperCase());
            } catch (UnsupportedEncodingException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Cảnh báo !", JOptionPane.WARNING_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Độ dài khóa nhập vào không hợp lệ", "Cảnh báo !", JOptionPane.WARNING_MESSAGE);
        }
    }//GEN-LAST:event_encrytedBtnActionPerformed

    private void decrytedBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decrytedBtnActionPerformed
        if (this.aesc.checkKeyLength(keyTxt.getText(), keyTypeCbx.getSelectedItem().toString())) {
            try {
                this.aesc.formatkey(keyTxt.getText());
                this.aesc.formatInput(decrytedTxtArea.getText(), decTypeCbx.getSelectedItem().toString());
                this.aesc.decryptionAES();
                String formatOutput = this.aesc.formatOutput(encTypeCbx.getSelectedItem().toString(), true);
                encrytedTxtArea.setText(formatOutput);
            } catch (UnsupportedEncodingException ex) {
                JOptionPane.showMessageDialog(this, ex.getMessage(), "Cảnh báo !", JOptionPane.WARNING_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Độ dài khóa nhập vào không hợp lệ", "Cảnh báo !", JOptionPane.WARNING_MESSAGE);
        }
    }//GEN-LAST:event_decrytedBtnActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main() {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(AES_Form.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(AES_Form.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(AES_Form.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(AES_Form.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(() -> {
            new AES_Form().setVisible(true);
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox<String> decTypeCbx;
    private javax.swing.JButton decrytedBtn;
    private javax.swing.JTextArea decrytedTxtArea;
    private javax.swing.JComboBox<String> encTypeCbx;
    private javax.swing.JButton encrytedBtn;
    private javax.swing.JTextArea encrytedTxtArea;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JTextArea jTextArea3;
    private javax.swing.JTextField keyTxt;
    private javax.swing.JComboBox<String> keyTypeCbx;
    // End of variables declaration//GEN-END:variables
}
