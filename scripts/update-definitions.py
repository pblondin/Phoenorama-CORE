#!/usr/bin/python

import urllib2
import shutil
import urlparse
import os
import sys
import time
import zipfile


from progressbar import *

# NVD/CVE XML Feed with CVSS and CPE mappings (version 2.0)
nvd_data	  =  "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml"

# Open Vulnerability and Assessment Language (version 5.10)
oval_data_zip = "http://oval.mitre.org/rep-data/5.10/org.mitre.oval/oval.xml.zip"
oval_checksum = "904dbac19e693fed372cce2c19e9b732"

def download(url, fileName=None):
    def getFileName(url,openUrl):
        if 'Content-Disposition' in openUrl.info():
            # If the response has Content-Disposition, try to get filename from it
            cd = dict(map(
                lambda x: x.strip().split('=') if '=' in x else (x.strip(),''),
                openUrl.info().split(';')))
            if 'filename' in cd:
                filename = cd['filename'].strip("\"'")
                if filename: return filename
        # if no filename was found above, parse it out of the final URL.
        return os.path.basename(urlparse.urlsplit(openUrl.url)[2])
    
    #TODO: Fix max length if header is not available.
    def getTotalBytes(openUrl):
        if 'Content-Length' in openUrl.info():
            # If the response has content-length, try to get size from it
            return openUrl.info()['Content-Length']
    
    req = urllib2.urlopen(url)
    
    try:
        bytesSoFar = 0
        totalBytes = getTotalBytes(req)
        fileName = fileName or getFileName(url,req)
        
        widgets = [fileName + ': ', Percentage(), ' ', Bar(),
                    ' ', ETA(), ' ', FileTransferSpeed()]
        pbar = ProgressBar(widgets=widgets, maxval=int(totalBytes)).start()
        
        with open(fileName, 'wb') as f:
            while True:
                readBytes = req.read(8192)
                bytesSoFar += len(readBytes)
                
                if not readBytes:
                    pbar.finish()
                    break
                
                f.write(readBytes)
                pbar.update(bytesSoFar)
    finally:
        f.close()
        req.close()
        return fileName
    
def unzip(zipFile, path=None):
    zipFile = zipfile.ZipFile(zipFile, 'r')
    for member in zipFile.namelist():
        fileName = os.path.basename(member)
        if not fileName:
            continue
        source = zipFile.open(member)
        target = file(fileName, "wb")
        shutil.copyfileobj(source, target)
        source.close()
        target.close()
    zipFile.close()

def main():
    download(nvd_data)
    unzip(download(oval_data_zip))

if __name__ == "__main__":
    main()

