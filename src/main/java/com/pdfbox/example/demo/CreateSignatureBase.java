
package com.pdfbox.example.demo;

import com.pdfbox.example.demo.digitalsignature.ReadKey;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class CreateSignatureBase implements SignatureInterface
{
    private PrivateKey privateKey;
    protected Certificate certificate;
    private Certificate[] certificateChain;

    public void loadCertificate() {
        try {
            // Đường dẫn đến tệp .crt
            String filePath = "cert.crt";

            // Load tệp .crt vào InputStream
            InputStream inputStream = new FileInputStream(filePath);

            // Tạo đối tượng CertificateFactory
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            // Đọc chứng chỉ từ InputStream
           certificate = certificateFactory.generateCertificate(inputStream);


            inputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public CreateSignatureBase() {
        try {
            KeyStore keystore = KeyStore.getInstance("Windows-MY");
            keystore.load(null, null);
            
            
            PrivateKey oPrivateKey = null;
            for (Enumeration oEnum = keystore.aliases(); oEnum.hasMoreElements();) {                   
                String sAlias = (String) oEnum.nextElement();
                
                oPrivateKey = (PrivateKey) keystore.getKey(sAlias,null);
                Certificate[] certChain = keystore.getCertificateChain(sAlias);
                if (certChain == null){
                    continue;
                }
		 // if no keys continue ..
		if(oPrivateKey == null) continue;
                
                setPrivateKey(oPrivateKey);
                setCertificateChain(certChain);
                 loadCertificate();

		System.out.println("Found a private key with Alias name:"+sAlias);
                break;
			 
            }
        } catch (KeyStoreException ex) {
            Logger.getLogger(CreateSignatureBase.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CreateSignatureBase.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CreateSignatureBase.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(CreateSignatureBase.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(CreateSignatureBase.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public CreateSignatureBase(KeyStore keystore, char[] pin)  throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException {
        Enumeration<String> aliases = keystore.aliases();
        String alias;
        Certificate cert = null;
        while (aliases.hasMoreElements()) {
            alias = aliases.nextElement();
            setPrivateKey((PrivateKey) keystore.getKey(alias, pin));
            Certificate[] certChain = keystore.getCertificateChain(alias);
            if (certChain == null) {
                continue;
            }
            setCertificateChain(certChain);
            cert = keystore.getCertificate(alias);
            setCertificate(cert);
            if (cert instanceof X509Certificate){
                // avoid expired certificate
                ((X509Certificate) cert).checkValidity();
            }
            break;
        }

        if (cert == null) {
            throw new IOException("Could not find certificate");
        }
    }

    public final void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public final void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public final void setCertificateChain(final Certificate[] certificateChain) {
        
        this.certificateChain = certificateChain;
    }


    public static X509Certificate generateCertificate(KeyPair keyPair) throws Exception {
        // Thời gian hiện tại
        Date startDate = new Date();

        // Thời gian hết hạn (1 năm sau)
        Date endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);

        // Số serial number, có thể tăng lên cho mỗi chứng chỉ mới
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        // Subject DN (Distinguished Name) của chứng chỉ
        X509Principal subjectDN = new X509Principal("CN=Example");

        // Tạo đối tượng X509V3CertificateGenerator
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        // Thiết lập các thuộc tính của chứng chỉ
        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(subjectDN);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(endDate);
        certGen.setSubjectDN(subjectDN);
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        // Tạo chứng chỉ
        return certGen.generate(keyPair.getPrivate());
    }
    @Override
    public byte[] sign(InputStream content) throws IOException {
        try {
            loadCertificate();
            RSAPrivateKey rsaPrivateKey = ReadKey.readPKCS8PrivateKey(new File("cert.key"));
            privateKey = rsaPrivateKey;
//            RSAPublicKey rsaPublicKey = ReadKey.readX509PublicKey(new File("public_key.pem"));
            List<Certificate> certList = new ArrayList<>();
//            certList.addAll(Arrays.asList(certificateChain));
//            certList.add(certificate);
//            Store certs = new JcaCertStore(certList);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(certificate.getEncoded()));
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1WithRSA").build(privateKey);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, new X509CertificateHolder(cert)));
//            gen.addCertificates(certs);
            CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
            CMSSignedData signedData = gen.generate(msg, false);
            
            return signedData.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        } catch (CMSException e) {
            throw new IOException(e);
        } catch (OperatorCreationException e) {
            throw new IOException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    
    

    

    public int getMDPPermission(PDDocument doc) {
        COSBase base = doc.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.PERMS);
        if (base instanceof COSDictionary)
        {
            COSDictionary permsDict = (COSDictionary) base;
            base = permsDict.getDictionaryObject(COSName.DOCMDP);
            if (base instanceof COSDictionary)
            {
                COSDictionary signatureDict = (COSDictionary) base;
                base = signatureDict.getDictionaryObject("Reference");
                if (base instanceof COSArray)
                {
                    COSArray refArray = (COSArray) base;
                    for (int i = 0; i < refArray.size(); ++i)
                    {
                        base = refArray.getObject(i);
                        if (base instanceof COSDictionary)
                        {
                            COSDictionary sigRefDict = (COSDictionary) base;
                            if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject("TransformMethod")))
                            {
                                base = sigRefDict.getDictionaryObject("TransformParams");
                                if (base instanceof COSDictionary)
                                {
                                    COSDictionary transformDict = (COSDictionary) base;
                                    int accessPermissions = transformDict.getInt(COSName.P, 2);
                                    if (accessPermissions < 1 || accessPermissions > 3)
                                    {
                                        accessPermissions = 2;
                                    }
                                    return accessPermissions;
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }

    public void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions) {
        COSDictionary sigDict = signature.getCOSObject();

        COSDictionary transformParameters = new COSDictionary();
        transformParameters.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
        transformParameters.setInt(COSName.P, accessPermissions);
        transformParameters.setName(COSName.V, "1.2");
        transformParameters.setNeedToBeUpdated(true);

        COSDictionary referenceDict = new COSDictionary();
        referenceDict.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
        referenceDict.setItem("TransformMethod", COSName.getPDFName("DocMDP"));
        referenceDict.setItem("DigestMethod", COSName.getPDFName("SHA1"));
        referenceDict.setItem("TransformParams", transformParameters);
        referenceDict.setNeedToBeUpdated(true);

        COSArray referenceArray = new COSArray();
        referenceArray.add(referenceDict);
        sigDict.setItem("Reference", referenceArray);
        referenceArray.setNeedToBeUpdated(true);

        COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
        COSDictionary permsDict = new COSDictionary();
        catalogDict.setItem(COSName.PERMS, permsDict);
        permsDict.setItem(COSName.DOCMDP, signature);
        catalogDict.setNeedToBeUpdated(true);
        permsDict.setNeedToBeUpdated(true);
    }
}
