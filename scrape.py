#!/usr/bin/env python

import M2Crypto,sys,os

PRINT_ERROR = False

def yankCRL(arg,dirname,names):
    for fileName in os.listdir(dirname):
        target = dirname + "/" + fileName
        try:
            fp = open(target,"rb")
        except:
            if PRINT_ERROR:
                print "Error: Could not open file %s - skipping" % target
            continue
        
        certificateString = fp.read()
        try:
            cert = M2Crypto.X509.load_cert_string(certificateString,format=M2Crypto.X509.FORMAT_PEM)
        except:
            try:
                cert = M2Crypto.X509.load_cert_string(certificateString,format=M2Crypto.X509.FORMAT_DER)
            except:
                if PRINT_ERROR:
                    print "Error: File %s cannot be loaded in PEM or DER format" % target
                    fp.close()
                    continue

        try:
            crlExt = cert.get_ext("crlDistributionPoints")
        except LookupError:
            fp.close()
            continue
        
        crl = crlExt.get_value().strip()
        serial = cert.get_serial_number()
#      print target + "," + str(serial) + "," + crl.split("URI:")[1]
        entries = crl.split("\n")
        for e in entries:
            if "URI" in e:
                print target + "," + str(serial) + "," + e[6:]
        
        fp.close()
        
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage ./scrape.py /FolderWithCertificates"
        exit(0)
    
    os.path.walk(sys.argv[1],yankCRL,None) 