# 1 Make sure you fill out the contact information for your domain registration.
# pipenv run python domaincontrol.py <domain.com> <createdBy>

import boto3
import sys
import json
import time
import logging


# 2 Mind the regions. 
r53d    = boto3.client('route53domains', region_name='us-east-1')
r53     = boto3.client('route53', region_name='us-east-1')
acm     = boto3.client('acm', region_name='us-east-1')
cf      = boto3.client('cloudfront', region_name='us-east-1') 

cloudFrontTargetID = "ELB-my-first-load-balancer" #  your Target Load Balancer, etc here. 
cloudFrontTargetDomainName = "my-first-loadbalancer.us-west-2.elb.amazonaws.com" # DNS Name of the load balancer target



# Fill this out first
contactInfo = {
        "FirstName": "",
        "LastName": "",
        "ContactType": "",
        "OrganizationName": "",
        "AddressLine1": "",
        "AddressLine2": "",
        "City": "",
        "State": "",
        "CountryCode": "",
        "ZipCode": "",
        "PhoneNumber": "",
        "Email": ""
        }
createdBy = 'domain-control'

# Custom logging function
def setup_custom_logger(domain):
    formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    handler = logging.FileHandler(domain +'.txt', mode='w')
    handler.setFormatter(formatter)
    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)
    logger = logging.getLogger(domain)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.addHandler(screen_handler)
    return logger

# Purchase Domain 
def register_domain(domain): 
    checkResponse = r53d.check_domain_availability(DomainName=domain)
    logger.info('[Domain Registration] Domain: '+ checkResponse['Availability'])
    if checkResponse['Availability'] == 'AVAILABLE':
        registerResponse = r53d.register_domain(
            DomainName=domain,
            DurationInYears=1,
            AutoRenew=False,
            AdminContact=contactInfo,
            RegistrantContact=contactInfo,
            TechContact=contactInfo,
            PrivacyProtectAdminContact=True,
            PrivacyProtectRegistrantContact=True,
            PrivacyProtectTechContact=True        
        )
        logger.info('[Domain Registration] Domain Purchased')
        return "Purchased", registerResponse['OperationId']
    else:
        zoneId = 'None'
        zoneId = get_hosted_zone_id(domain)
        if zoneId != 'None':
            logger.info('[Domain Registration] Domain Found in Route53 Hosted Zones')
            return "Found", zoneId
        else:
            logger.error('[Domain Registration] Domain is not Available!')
            return "Failure", "Domain is not Available!" 

def domain_purchase_waiter(domain, createdBy, operationId):
    operationResponse = r53d.get_operation_detail(OperationId=operationId)
    while operationResponse['Status'] != 'SUCCESSFUL':
        logger.info('[Domain Registration] Domain Registration Status: ' + operationResponse['Status'])
        operationResponse = r53d.get_operation_detail(OperationId=operationId)
        if operationResponse['Status'] == 'ERROR' or operationResponse['Status'] == 'FAILED':
            logger.error('[Domain Registration] Domain Registration Status: ' + operationResponse['Status'])
            return "Failure", "Domain Registation " + operationResponse['Status']
        time.sleep(60)
    domainTagresponse = r53d.update_tags_for_domain(
        DomainName=domain,
        TagsToUpdate=[
            {
                'Key': 'createdBy',
                'Value': createdBy
            },
        ]
    )
    logger.error('[Domain Registration] Domain Registration Status: ' + operationResponse['Status'])
    return "Success", "Domain Registered Successfully"

def get_hosted_zone_id(domain):
    hostedZoneResponse = r53.list_hosted_zones(
        MaxItems='500',
    )

    for zones in hostedZoneResponse['HostedZones']:
        if zones['Name'] == domain +'.':
            zoneId = zones['Id'].replace("/hostedzone/","")
            return zoneId

# Create ACM Cert 
def create_certificate(domain, domainwww, createdBy):
    certificateResponse = acm.request_certificate(
        DomainName=domain,
        ValidationMethod='DNS',
        SubjectAlternativeNames=[
            domainwww,
        ],
        IdempotencyToken=domain.replace(".", ""),
        DomainValidationOptions=[
            {
                'DomainName': domain,
                'ValidationDomain': domain
            },
        ],
        Options={
            'CertificateTransparencyLoggingPreference': 'ENABLED'
        },
        Tags=[
            {
                'Key': 'createdBy',
                'Value': createdBy
            },
        ]
    )  
    
    time.sleep(5)
    describeCertificateResponse = acm.describe_certificate(CertificateArn=certificateResponse['CertificateArn'])

    for domains in describeCertificateResponse['Certificate']['DomainValidationOptions']: 
        create_cert_validation_record(domain, domains['ResourceRecord']['Name'], domains['ResourceRecord']['Value'])

    return "Success", certificateResponse['CertificateArn']

def create_cert_validation_record(domain, Name, Value):
    hostedZoneId = get_hosted_zone_id(domain)
    validationRecordResponse = r53.change_resource_record_sets(
        HostedZoneId=hostedZoneId,
        ChangeBatch={
            'Comment': 'ACM Certificate Validation Recordset',
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': Name,
                        'Type': 'CNAME',
                        
                        'TTL': 300,
                        'ResourceRecords': [
                            {
                                'Value': Value,
                            },
                        ],

                    }
                },
            ]
        }
    )
    logger.info('[Certificate Validation] '+ 'Record Created: ' + ' : ' + Name)

def certificate_validate_waiter(acmArn):
    allDomainsValidated = 'PENDING_VALIDATION'
    while allDomainsValidated == 'PENDING_VALIDATION':
        allDomainsValidated = 'SUCCESS'
        acmWaiterResponse = acm.describe_certificate(CertificateArn=acmArn)
        logger.info('[Certificate Validation] '+ 'Waiting to Validate Certificate...')
        time.sleep(60)
        for domains in acmWaiterResponse['Certificate']['DomainValidationOptions']:
            logger.info('[Certificate Validation] '+ 'Status: '+ domains['ValidationStatus'])
            if domains['ValidationStatus'] == 'PENDING_VALIDATION':
                allDomainsValidated = 'PENDING_VALIDATION'
            elif domains['ValidationStatus'] == 'FAILED':
                return 'Failed', 'DNS Certificate Validation Failed'
    return 'Success', 'DNS Certificate Validated Succeeded for both domains!'

def create_cloudfront_distro(domain, domainwww, acmArn, createdBy):
    try: 
        cloudFrontDistroresponse = cf.create_distribution_with_tags(
            DistributionConfigWithTags={
                'DistributionConfig': {
                    'CallerReference': domain,
                    'Aliases': {
                        'Quantity': 2,
                        'Items': [
                            domain,
                            domainwww
                        ]
                    },
                    'Origins': {
                        'Quantity': 1,
                        'Items': [
                            {
                                'Id': cloudFrontTargetID,
                                'DomainName': cloudFrontTargetDomainName,
                                'CustomOriginConfig': {
                                    'HTTPPort': 80,
                                    'HTTPSPort': 443,
                                    'OriginProtocolPolicy': 'http-only',
                                    'OriginSslProtocols': {
                                        'Quantity': 1,
                                        'Items': [
                                            'TLSv1',
                                        ]                                    
                                    },
                                'OriginReadTimeout': 30,
                                'OriginKeepaliveTimeout': 5
                                }
                            },
                        ]
                    },
                    'DefaultCacheBehavior': {
                        'TargetOriginId': cloudFrontTargetID,
                        'ForwardedValues': {
                            'QueryString': True,
                            'Cookies': {
                                'Forward': 'all',
                            },
                        },
                        'ViewerProtocolPolicy': 'redirect-to-https',
                        'MinTTL': 0,
                        'AllowedMethods': {
                            'Quantity': 7,
                            'Items': [
                                'GET',
                                'HEAD',
                                'POST',
                                'PUT',
                                'PATCH',
                                'OPTIONS',
                                'DELETE',
                            ],
                        },
                        'SmoothStreaming': False,
                        'DefaultTTL': 86400,
                        'MaxTTL': 31536000,
                        'Compress': False,
                        'TrustedSigners' : {
                            'Enabled' : False,
                            'Quantity': 0,
                        }
                    },
                    'Comment': 'Static Site HTTPS Forwarder',
                    'PriceClass': 'PriceClass_100',
                    'Enabled': True,
                    'ViewerCertificate': {
                        'CloudFrontDefaultCertificate': False,
                        'ACMCertificateArn': acmArn,
                        'SSLSupportMethod': 'sni-only',
                        'MinimumProtocolVersion': 'TLSv1.1_2016'
                    },
                    'HttpVersion': 'http1.1',
                    'IsIPV6Enabled': True,    
                },            
                'Tags': {
                    'Items': [
                        {
                            'Key': 'createdBy',
                            'Value': createdBy
                        },
                    ]
                }
            },
        )
    except cf.exceptions.DistributionAlreadyExists as e:
        logger.error('[Distribution Deployment] '+ str(e))
        distroID = str(e).replace("An error occurred (DistributionAlreadyExists) when calling the CreateDistributionWithTags operation: The caller reference that you are using to create a distribution is associated with another distribution. Already exists: ", "")
        logger.info('[Distribution Deployment] Attempting to continue setup with distribution: ' + distroID)
        return 'Success', distroID
    return 'Success', cloudFrontDistroresponse['Distribution']['Id']

def cloudfront_distro_waiter(id):
    cloudFrontDistroStatusresponse = cf.get_distribution(
        Id=id
    )
    while cloudFrontDistroStatusresponse['Distribution']['Status'] != 'Deployed':
        time.sleep(60)
        logger.info('[Distribution Deployment] Current Distribution Status: ' + cloudFrontDistroStatusresponse['Distribution']['Status'])
        cloudFrontDistroStatusresponse = cf.get_distribution(
            Id=id
        )
    return "Success", "Distribution Successfully Deployed!"

def create_dns_record_aliases(domain, domainwww, cloudfrontID):
    hostedZoneId = get_hosted_zone_id(domain)
    dnsName = cloudfrontID + '.cloudfront.net'
    wireupRecordResponse = r53.change_resource_record_sets(
        HostedZoneId=hostedZoneId,
        ChangeBatch={
            'Comment': 'ACM Certificate Validation Recordset',
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': domain,
                        'Type': 'A',
                        'AliasTarget': {
                            'HostedZoneId': 'Z2FDTNDATAQYW2',
                            'DNSName': dnsName,
                            'EvaluateTargetHealth': False
                        }
                    }
                },
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': domain,
                        'Type': 'AAAA',
                        'AliasTarget': {
                            'HostedZoneId': 'Z2FDTNDATAQYW2',
                            'DNSName': dnsName,
                            'EvaluateTargetHealth': False
                        }
                    }
                },
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': domainwww,
                        'Type': 'A',
                        'AliasTarget': {
                            'HostedZoneId': 'Z2FDTNDATAQYW2',
                            'DNSName': dnsName,
                            'EvaluateTargetHealth': False
                        }
                    }
                },
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': domainwww,
                        'Type': 'AAAA',
                        'AliasTarget': {
                            'HostedZoneId': 'Z2FDTNDATAQYW2',
                            'DNSName': dnsName,
                            'EvaluateTargetHealth': False

                        }
                    }
                }
            ]
        }
    )    
    return "Success", "Route53 Recordset Aliases Created!"






# Set basic script variables from command line.
domain = sys.argv[1]
domainwww = 'www.' + domain
createdBy = sys.argv[2]

# Setup logging
logger  = setup_custom_logger(domain)

# Purchase Domain and wait for registration to complete. 
domainStatus, responseId = register_domain(domain)
if domainStatus == 'Purchased':
    domain_purchase_waiter(domain, createdBy, responseId)
elif domainStatus == 'Found':
    logger.info('[Domain Registration] Success!')
else:
    sys.exit()

# Register certifcate and setup validation.
certStatus, acmArn = create_certificate(domain, domainwww, createdBy)
certWaiter, certMessage = certificate_validate_waiter(acmArn)
if certWaiter == 'Success':
    logger.info('[Certificate Registration] '+ certWaiter + ' : ' + acmArn)
else:
    logger.error('[Certificate Registration] '+ certWaiter + ' : ' +  certMessage)
    sys.exit()

# Create Cloudfront distribution and wait for setup.
distroStatus, distroId = create_cloudfront_distro(domain, domainwww, acmArn, createdBy)
logger.info('[Distribution Deployment] '+ distroStatus + ' : ' + distroId)
distroWaiter, distroWaiterMessage = cloudfront_distro_waiter(distroId)
logger.info('[Distribution Deployment] '+ distroWaiter + ' : ' + distroWaiterMessage)

# Create Route53 RecordSet Aliases
route53status, route53Message = create_dns_record_aliases(domain, domainwww, distroId)
logger.info('[Route53 Recordsets] '+ route53status + ' : ' + route53Message)


