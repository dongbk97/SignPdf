/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.pdfbox.example.demo.digitalsignature;

import com.pdfbox.example.demo.SignIt;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 *
 * @author Kareem
 */
public class DigitalSignature {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        File file = new File("C:\\Users\\dongnv1\\Desktop\\DigitalSignatureUsingPDFBOX\\test.pdf");
        
        SignIt sign = new SignIt(file);
    }
    
}
