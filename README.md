# Domain SSL Certificate SAN Enumerator - DCSE
Enumerates a domains SSL certificate for Subject Alternate Names (subdomains).
# Requirements
```
python 3.9
pip 20.3.4
```
# Get DCSE
Download the repository change to the relevant directory and give the file execute permissions
```
git clone https://github.com/Rodney-O-C-Melby/domain-certificate-san-enumerator.git  
cd domain-certificate-san-enumerator
sudo pip install -r requirements.txt
```  
  
# Use DCSE
sudo or root is required to make a new network connection, Python version 3.6 - 3.9 Required
```
sudo python dcse.py  
sudo python dcse.py zonetransfer.me
sudo python dcse.py -n 1.1.1.1 zonetransfer.me
sudo python dcse.py -v  
sudo python dcse.py -h
