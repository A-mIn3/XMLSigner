# XMLSigner
    The program uses the JAVA XML SIGNATURE API to sign and verify xml signatures . 
    For now it only supports envelopped signatures with x509 certificates and performs content 
    validation without certificate path verification.
    
    A JAVA KeyStore is being used to store  trusted certificates.This KeyStore however does not support importing 
    previously generated keys .
    This is the purpose of the importKey source file which is a good tool to help import your own keys . 
