DCSE - Domain SSL Certificate SAN Enumerator
==================================
<p float="left">
  <img src="https://img.shields.io/pypi/pyversions/Django" alt="Supported Python versions" />
  <img src="https://img.shields.io/cpan/l/Config-Augeas?color=orange" alt="License: GPL-2.1" />
</p>

DCSE is a subdomain enumerator, looking up the public SSL domain certificate, Subject Alternate Names (SAN) and returning the subdomains. Written in Python.

https://github.com/Rodney-O-C-Melby/domain-certificate-san-enumerator/

Requirements
============
In order to work correctly, DCSE needs :

+ Python 3.x where x is >= (3.6, 3.7, 3.8, 3.9, 3.10) ( https://www.python.org/ )
+ pip 20.3.4 ( https://pypi.org/project/pip/ )

Install
=================
Download the repository change to the relevant directory and give the file execute permissions.
```
git clone https://github.com/Rodney-O-C-Melby/domain-certificate-san-enumerator.git  
cd domain-certificate-san-enumerator
sudo pip install -r requirements.txt
```  

Usage
=================
sudo or root is required to make a new network connection, Python versions 3.6 - 3.9 Required.
```
sudo python dcse.py  
sudo python dcse.py zonetransfer.me
sudo python dcse.py -n 1.1.1.1 zonetransfer.me
sudo python dcse.py -v  
sudo python dcse.py -h
```

How it works
============

DCSE works as a subdomain enumerator by checking the targets 
SSL certificate for associated subdomains declared at the 
time of the SSL certificate creation.

General features
================

+ Can use custom DNS (-n) for the lookup to query for interal or exteral Domain Name Systems (DNS).
+ Version and help/usage.

Where to get help
=================

In the prompt, just type the following command to get the basic usage :

    python dcse.py -h

If you find a bug, fill a issue : https://github.com/Rodney-O-C-Melby/domain-certificate-san-enumerator/issues

How to help the DCSE project
==============================

You can :

+ Support the project by making a donation ( https://app.galabid.com/dcse )
+ Send bugfixes, and patches.
+ Talk about dcse around you.

Licensing
=========

DCSE is released under the GNU General Public License version 2.1 (the GPL).
  Source code is available on <a href="https://github.com/Rodney-O-C-Melby/domain-certificate-san-enumerator/" alt="Github">Github</a>.

Created by Rodney O. C. Melby.

Disclaimer
==========

DCSE is cybersecurity software. It performs a scan of the provided targets public SSL certificate.

Usage of DCSE is not illegal without prior consent of its owner because the SSL certificate is public information. It is the end user's responsibility to obey all applicable local laws.

Developers and people involved in the DCSE project assume no liability and are not responsible for any misuse or damage caused by this program.
