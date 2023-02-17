## Copyright 2023 Agile Cloud Institute (AgileCloudInstitute.io) as described in LICENSE.txt distributed with this repository.

import random, string

def getAlphaNumericString(numDigits):
  return str(''.join(random.choices((string.ascii_letters).lower() + string.digits, k=numDigits)))

def randomCharacters(length):
   letters = string.ascii_lowercase
   return str(''.join(random.choice(letters) for i in range(length)))

def writeLinesToFile(linesArray, fileName):
  with open(fileName, mode='wt', encoding='utf-8') as myfile:
    myfile.write('\n'.join(linesArray))

def generateRandomConfig():
  configLines = []
  line = 'subscriptionId: Follow instructions in article entitled “Set up Azure Seed Credentials”'
  configLines.append(line)
  line = 'subscriptionName: Follow instructions in article entitled “Set up Azure Seed Credentials”'
  configLines.append(line)
  line = 'tenantId: Follow instructions in article entitled “Set up Azure Seed Credentials”'
  configLines.append(line)
  line = 'orgCfDemo: '+getAlphaNumericString(5)
  configLines.append(line)
  line = 'cfDemoStackName: '+randomCharacters(15)
  configLines.append(line)
  line = 'region: us-west-2'
  configLines.append(line)
  line = 'vpcCIDR: 10.0.0.0/16'
  configLines.append(line)
  line = 'stackName: '+randomCharacters(12)
  configLines.append(line)
  line = 'SSHLocation: 0.0.0.0/0'
  configLines.append(line)
  line = 'imageInstanceType: t2.small'
  configLines.append(line)
  line = 'sNetStackName: '+randomCharacters(17)
  configLines.append(line)
  line = 'imageName: '+randomCharacters(14)
  configLines.append(line)
  line = 'availZone: us-west-2a'
  configLines.append(line)
  line = 'orgTfPackerDemo: '+getAlphaNumericString(5)
  configLines.append(line)
  line = 'rgNameAdminTfBknd: '+getAlphaNumericString(5)
  configLines.append(line)
  line = 'rgNameAgentsTfBknd: '+getAlphaNumericString(5)
  configLines.append(line)
  line = 'resourceGroupRegion: eastus'
  configLines.append(line)
  line = 'rgNameAgentsFoundation: '+getAlphaNumericString(5)
  configLines.append(line)
  line = 'rgNameAgentsInstances: '+getAlphaNumericString(5)
  configLines.append(line)
  line = 'orgARM: '+getAlphaNumericString(6)
  configLines.append(line)
  line = 'rgArmDemoFoundation: '+getAlphaNumericString(5)
  configLines.append(line)
  line = 'rgArmDemoService: '+getAlphaNumericString(5)
  configLines.append(line)
  line = 'imageNameARM: '+randomCharacters(7)
  configLines.append(line)
  line = 'anotherVar: some-value'
  configLines.append(line)
  line = 'anotherVar2: another-value'
  configLines.append(line)
  line = 'scaleSetInstanceDeployNameARM: '+randomCharacters(10)
  configLines.append(line)
  line = 'networkName: name-of-vnet'
  configLines.append(line)
  line = 'sysName: name-of-system'
  configLines.append(line)
  line = 'orgCustom: '+getAlphaNumericString(5)
  configLines.append(line)
  line = 'imgNameCustom: custom-img'
  configLines.append(line)

  writeLinesToFile(configLines, 'config.yaml')

def generateKeysFile():
  keysLines = []
  line = "secretsType: master"
  keysLines.append(line)
  line = "clientName: <follow-instructions-below-to-get-value>"
  keysLines.append(line)
  line = "clientId: <follow-instructions-below-to-get-value>"
  keysLines.append(line)
  line = "clientSecret: <follow-instructions-below-to-get-value>"
  keysLines.append(line)
  line = "gitUsername: <follow-instructions-below-to-get-value>"
  keysLines.append(line)
  line = "gitPass: <follow-instructions-below-to-get-value>"
  keysLines.append(line)
  line = "KeyName: <follow-instructions-below-to-get-value>"
  keysLines.append(line)
  line = "AWSAccessKeyId: <follow-instructions-below-to-get-value>"
  keysLines.append(line)
  line = "AWSSecretKey: <follow-instructions-below-to-get-value>"
  keysLines.append(line)

  writeLinesToFile(keysLines, 'keys.yaml')

  
generateRandomConfig()
generateKeysFile()

