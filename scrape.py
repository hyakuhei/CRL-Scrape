#!/usr/bin/env python

import M2Crypto,sys,os,urllib2,time
from subprocess import call
from time import gmtime


PRINT_ERROR = False

def file_exists(filepath):
    try:
        fp = open(filepath,'r')
        fp.close()
        return True
    except:
        return False


def fetch(url):
    exists = False
    if 'http' not in url:
      #  print "Don't know how to fetch %s" % url
        return None
    try:
        fd = open(url.split('/')[-1],'r')
        exists = True
        fd.close()
        return os.path.abspath(fd.name)
    except:
        #File don't exist son!
        pass
    
    response = urllib2.urlopen(url)
    try:
        crl = open(url.split('/')[-1],'wb')
        crl.write(response.read())
        crl.close()
    except:
        return None

    return os.path.abspath(crl.name)

def der2pem_crl(filepath):
    if file_exists("%s.pem" % filepath):
        #PEM file already exists
        return "%s.pem" % filepath
    call(("openssl crl -in %s -inform DER -out %s.pem -outform PEM" % (filepath,filepath)).split())
    return "%s.pem" % filepath

def crl_expires(filepath,target=""):       
    try:
        crl = M2Crypto.X509.load_crl(filepath)
    except M2Crypto.X509.X509Error as e:
        try:
            crl = M2Crypto.X509.load_crl(der2pem_crl(filepath))
        except M2Crypto.X509.X509Error as e:
            raise Exception('Tried to load as PEM and DER but failed')

    nextStr = [x for x in crl.as_text().split("\n") if 'Next' in x][0].strip()
    nu = " ".join(nextStr.split()) #make fields spaced by a single space, always
    nuTime = time.strptime(nu, "Next Update: %b %d %H:%M:%S %Y %Z")
    now = gmtime()

    if now > nuTime:
        print '%s has a CRL %s that expired on %s' % (target.split("/")[-1],filepath.split("/")[-1],nu.split('te: ')[1])
    #else:
     #   print 'CRL %s has not expired' % filepath

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
        except:
            continue
        
        crl = crlExt.get_value().strip()
        serial = cert.get_serial_number()
#      print target + "," + str(serial) + "," + crl.split("URI:")[1]
        entries = crl.split("\n")
        for e in entries:
            if "URI" in e:
                #print target + "," + str(serial) + "," + e[6:]
                filepath = fetch(e[6:])
                if filepath == None:
                    continue
                if filepath not in arg:
                    arg.append(filepath)
                    crl_expires(filepath,target)
        
        fp.close()
        
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage ./scrape.py /FolderWithCertificates"
        exit(0)
    
    CRLS = []
    os.path.walk(sys.argv[1],yankCRL,CRLS) 
