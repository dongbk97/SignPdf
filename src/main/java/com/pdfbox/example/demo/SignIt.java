package com.pdfbox.example.demo;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.*;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Karim Omaya
 */
public class SignIt extends CreateSignatureBase{
    
    public File outFile = null;
    public boolean isSigned = false;
    
    
    /*
        Take the file to began the signing cycle 
    */
    public SignIt(File file) {
        try {
            File inFile = file;
            PDDocument doc = new PDDocument();
            PDPage page = new PDPage();
            doc.addPage(page);
            // C:\Users\dongnv1\Desktop\DigitalSignatureUsingPDFBOX\test.pdf
            doc.save("C:\\Users\\dongnv1\\Desktop\\DigitalSignatureUsingPDFBOX\\signed.pdf");
            doc.close();
            outFile = new File("C:\\Users\\dongnv1\\Desktop\\DigitalSignatureUsingPDFBOX\\signed.pdf");
            signDetached(inFile, outFile);
            this.isSigned = true;
            
        } catch (IOException ex) {
            Logger.getLogger(SignIt.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /*
    
        convert the token file into PDDocument
    
    */
    public void signDetached(File inFile, File outFile) throws IOException {
        if (inFile == null || !inFile.exists()) {
            throw new FileNotFoundException("Document for signing does not exist");
        }

        FileOutputStream fos = new FileOutputStream(outFile);

        PDDocument doc = PDDocument.load(inFile);
        signDetached(doc, fos);
        doc.close();
    }
    
    
    
    
    public void signDetached(PDDocument document, OutputStream output) throws IOException {
        
        int accessPermissions = getMDPPermission(document);
        System.out.println(accessPermissions);
        if (accessPermissions == 1) {
            throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
        }     

        // create signature dictionary
        PDSignature signature = new PDSignature();
        
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter for handling certificate
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED); 
        signature.setName("CBE User");
        signature.setLocation("Central Bank Of Egypt");
        signature.setReason("For Protecting CBE data");

        // the signing date, needed for valid signature
        signature.setSignDate(Calendar.getInstance());

        //  certify 
        if (accessPermissions == 0)
        {
            setMDPPermission(document, signature, 2);
        }        

        
        System.out.println("Sign externally...");
        document.addSignature(signature);
        ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(output);
        // invoke external signature service
        byte[] cmsSignature = sign(externalSigning.getContent());
        // set signature bytes received from the service
        externalSigning.setSignature(cmsSignature);
        
        
    }
}
