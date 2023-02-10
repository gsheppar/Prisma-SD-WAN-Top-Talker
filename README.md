# Prisma SD-WAN Top Talkers (Preview)
The purpose of this script is to get a lits of top talkers for a specific site for an hour

#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.7

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py

 1. ./top_talkers.py --name "Home-Office"
      - Will get the top talkers for Home-Office site for the the past hour

 2. ./top_talkers.py --name Home-Office --detailed
      - Will get the top talkers for Home-Office site for the the past hour using a more detailed collection

 3. ./top_talkers.py --name "Home-Office" --time "2023-02-10 17:00:00.0"
      - Will get the top talkers for Home-Office site for the from 02/10/2023, 16:00 to 02/10/2023, 17:00

### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
PrismaAccess2023