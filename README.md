# porkbun-dynamic-dns-bash

This is a minimalist dynamic DNS client written in Bash based upon the Porkbun Python client at https://github.com/porkbundomains/porkbun-dynamic-dns-python. The command line parameters of the original program have been extended so that it is easier to integrate the script into other Bash scripts.

Before using the script make sure that you have the jq and curl packages installed on your system.

```
sudo apt install jq curl
```

#Usage

```
porkbun-ddns.sh /path/to/config.json example.com
```
        Creates an A record 'example.com' that points to the external IP address as determined by the Porkbun API.

```
porkbun-ddns.sh example.com www -s < /path/to/config.json
```
        Creates an A record 'www.example.com' that points to the IP address as determined by the Porkbun API. The configuration is read from the STDIN.

```
porkbun-ddns.sh /path/to/config.json example.com '*' -i 10.0.0.1
```
        Creates an A record '*.example.com' that points to the IP address 10.0.0.1.

#Remarks

For further information on how this script can be used please check the manual of the orginial Python app at https://github.com/porkbundomains/porkbun-dynamic-dns-python.
This script has been tested only on Ubuntu 22.04 so it might not work on other systems.
After successfully executing the script it might take several minutes before the changes take effect.
Despite the fact that the script has been tested and in use without any issues, be aware, that it may contain bugs that can mess up your DNS settings.