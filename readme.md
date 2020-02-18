# Domain-Wire-Up ### 

## Description 
Domain Wire Up is a quick script cobbled together to do the following:
### - Purchase a domain 
   - If domain is unavailable, search for it in Route53 and retrive the HostedZoneID.
   - Wait for the HostedZoneID of the purchased domain or searched domain to become available. 
### - Request a certificate for the domain.com and www subdomain. 
   - Write verifications records for the certificate to the HostedZoneID in Route53 retrieved above. 
   - Wait for the Certicate to be verified.
### - Create a Cloudfront Distribution 
   - Wire to Elastic Load Balancer
   - Attach Certificate
   ! Set Web Application Firewall
   - Wait for Distribution to be in the "Deployed" state. 
### - Write Recordsets to Route53 
### - Test Wiring
   - Wait for API Call to be successful

## Directions 
Domain Wire Up can be called from the command line: 
- pipenv run python domaincontrol.py <domain.com> <createdBy>
  - domain.com: Domain you wish to purchase. Records and Cert created for www.domain.com as well.
  - createdBy: All resources tagged with createdBy tag and value. 

