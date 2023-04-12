## Copyright 2023 Agile Cloud Institute (AgileCloudInstitute.io) as described in LICENSE.txt distributed with this repository.

# INSTRUCTIONS: 
# 1. Place this script in the directory that contains your keys.yaml and config.yaml that you will use for the demos.  
# 2. Open a command prompt and navigate to the directory that contains this file and your keys.yaml and your config.yaml . 
# 3. Type "python validateKeysAndConfig.py" in the command line to run this script. 
# 4. Examine the console printout to confirm whether or not your keys.yaml and config.yaml passed all the validation tests defined in this script. 

import yaml

ErrorCount = 0

configStatusDict = {
  "subscriptionId": "Missing",
  "subscriptionName": "Missing",
  "tenantId": "Missing",
  "orgCfDemo": "Missing",
  "cfDemoStackName": "Missing",
  "region": "Missing",
  "vpcCIDR": "Missing",
  "stackName": "Missing",
  "SSHLocation": "Missing",
  "imageInstanceType": "Missing",
  "sNetStackName": "Missing",
  "imageName": "Missing",
  "availZone": "Missing",
  "orgTfPackerDemo": "Missing",
  "rgNameAdminTfBknd": "Missing",
  "rgNameAgentsTfBknd": "Missing",
  "rgNameAdmin": "Missing",
  "resourceGroupRegion": "Missing",
  "rgNameAgentsFoundation": "Missing",
  "rgNameAgentsInstances": "Missing",
  "orgARM": "Missing",
  "rgArmDemoFoundation": "Missing",
  "rgArmDemoService": "Missing",
  "imageNameARM": "Missing",
  "anotherVar": "Missing",
  "anotherVar2": "Missing",
  "scaleSetInstanceDeployNameARM": "Missing",
  "networkName": "Missing",
  "sysName": "Missing",
  "orgCustom": "Missing",
  "imgNameCustom": "Missing"
}

keysStatusDict = {
  "secretsType": "Missing",
  "clientName": "Missing",
  "clientId": "Missing",
  "clientSecret": "Missing",
  "KeyName": "Missing",
  "AWSAccessKeyId": "Missing",
  "AWSSecretKey": "Missing"
}


def validateEachConfigField(key, value):
  global ErrorCount
  if key == "subscriptionId":
    if value.count("-") != 4:
      print("ERROR: Value for subscriptionId must contain exactly 4 dash symbols - but the value in your file contains ", str(value.count("-")), " dashes. Please fix your yaml file and rerun this validation script. ")
      ErrorCount += 1
    if len(value.split("-")) != 5:
      print("ERROR: Value for subscriptionId must have exactly five blocks of alphanumeric characters separated by dashes. ")
      ErrorCount += 1
    if len(value.split("-")[0]) != 8:
      print("ERROR: The number of characters before the first dash in the subscriptionId value must be exactly 8. ")
      ErrorCount += 1
    if len(value.split("-")[1]) != 4:
      print("ERROR: The number of characters between the first and second dashes in the subscriptionId value must be exactly 4. ")
      ErrorCount += 1
    if len(value.split("-")[2]) != 4:
      print("ERROR: The number of characters between the second and third dashes in the subscriptionId value must be exactly 4. ")
      ErrorCount += 1
    if len(value.split("-")[3]) != 4:
      print("ERROR: The number of characters between the third and fourth dashes in the subscriptionId value must be exactly 4. ")
      ErrorCount += 1
    if len(value.split("-")[4]) != 12:
      print("ERROR: The number of characters after the fourth dash in the subscriptionId value must be exactly 12. ")
      ErrorCount += 1
  elif key == "tenantId":
    if value.count("-") != 4:
      print("ERROR: Value for tenantId must contain exactly 4 dash symbols - but the value in your file contains ", str(value.count("-")), " dashes. Please fix your yaml file and rerun this validation script. ")
      ErrorCount += 1
    if len(value.split("-")) != 5:
      print("ERROR: Value for tenantId must have exactly five blocks of alphanumeric characters separated by dashes. ")
      ErrorCount += 1
    if len(value.split("-")[0]) != 8:
      print("ERROR: The number of characters before the first dash in the tenantId value must be exactly 8. ")
      ErrorCount += 1
    if len(value.split("-")[1]) != 4:
      print("ERROR: The number of characters between the first and second dashes in the tenantId value must be exactly 4. ")
      ErrorCount += 1
    if len(value.split("-")[2]) != 4:
      print("ERROR: The number of characters between the second and third dashes in the tenantId value must be exactly 4. ")
      ErrorCount += 1
    if len(value.split("-")[3]) != 4:
      print("ERROR: The number of characters between the third and fourth dashes in the tenantId value must be exactly 4. ")
      ErrorCount += 1
    if len(value.split("-")[4]) != 12:
      print("ERROR: The number of characters after the fourth dash in the tenantId value must be exactly 12. ")
      ErrorCount += 1
  elif key == "region":
    if value != "us-west-2":
      print("ERROR: For the demo, the value for region must be us-west-2")
      ErrorCount += 1
  elif key == "vpcCIDR":
    if value != "10.0.0.0/16":
      print("ERROR: For the demo, the value for vpcCIDR must be 10.0.0.0/16")
      ErrorCount += 1
  elif key == "SSHLocation":
    if value != "0.0.0.0/0":
      print("ERROR: For the demo, the value for SSHLocation must be 0.0.0.0/0")
      ErrorCount += 1
  elif key == "imageInstanceType":
    if value != "t2.small":
      print("ERROR: For the demo, the value for imageInstanceType must be t2.small")
      ErrorCount += 1
  elif key == "availZone":
    if value != "us-west-2a":
      print("ERROR: For the demo, the value for availZone must be us-west-2a")
      ErrorCount += 1
  elif (key == "orgCfDemo") or (key == "orgTfPackerDemo") or (key == "orgARM") or (key == "orgCustom"):
    if len(value) > 6:
      print("ERROR: For the demo, the value for ", key, " must not be longer than 5 or 6 characters.")
      ErrorCount += 1
  elif key == "resourceGroupRegion":
    if value != "eastus":
      print("ERROR: For the demo, the value for resourceGroupRegion must be eastus")
      ErrorCount += 1

def validateEachKeysField(key, value):
  global ErrorCount
  if key == "secretsType":
    if value != "master":
      print("ERROR: The value you gave for the secretsType key is not valid. The only valid value for the start of the demo is 'master', without the single quotes. ")
      ErrorCount += 1
  if key == "clientId":
    if value.count("-") != 4:
      print("ERROR: Value for clientId must contain exactly 4 dash symbols - but the value in your file contains ", str(value.count("-")), " dashes. Please fix your yaml file and rerun this validation script. ")
      ErrorCount += 1
    if len(value.split("-")) != 5:
      print("ERROR: Value for clientId must have exactly five blocks of alphanumeric characters separated by dashes. ")
      ErrorCount += 1
    if len(value.split("-")[0]) != 8:
      print("ERROR: The number of characters before the first dash in the clientId value must be exactly 8. ")
      ErrorCount += 1
    if len(value.split("-")[1]) != 4:
      print("ERROR: The number of characters between the first and second dashes in the clientId value must be exactly 4. ")
      ErrorCount += 1
    if len(value.split("-")[2]) != 4:
      print("ERROR: The number of characters between the second and third dashes in the clientId value must be exactly 4. ")
      ErrorCount += 1
    if len(value.split("-")[3]) != 4:
      print("ERROR: The number of characters between the third and fourth dashes in the clientId value must be exactly 4. ")
      ErrorCount += 1
    if len(value.split("-")[4]) != 12:
      print("ERROR: The number of characters after the fourth dash in the clientId value must be exactly 12. ")
      ErrorCount += 1
  elif key == "clientSecret":
    if len(value) != 40:
      print("ERROR: Value for clientSecret must contain exactly 40 characters, but the value in your file contains ", str(len(value)), " characters. Please fix your yaml file and rerun this validation script. ")
      ErrorCount += 1
  elif key == "AWSAccessKeyId":
    if len(value) != 20:
      print("ERROR: Value for AWSAccessKeyId must contain exactly 20 characters, but the value in your file contains ", str(len(value)), " characters. Please fix your yaml file and rerun this validation script. ")
      ErrorCount += 1
  elif key == "AWSSecretKey":
    if len(value) != 40:
      print("ERROR: Value for AWSSecretKey must contain exactly 40 characters, but the value in your file contains ", str(len(value)), " characters. Please fix your yaml file and rerun this validation script. ")
      ErrorCount += 1

def validateConfigYaml():
  global ErrorCount
  fileName = "config.yaml"
  missingFields = []
  with open(fileName, "r") as stream:
    try:
      fileContents = yaml.safe_load(stream)
      for thisKey in fileContents:
        #Validate the value of the field
        #Check for too many spaces
        if fileContents[thisKey].count(' ') != 0:
          print("ERROR: The value given for the key ", thisKey, " contains spaces, which is illegal. Remove the spaces and re-run the validation script. ")
          ErrorCount += 1
        #Check for empty value.
        if len(fileContents[thisKey]) == 0:
          print("ERROR: The value for field named ", thisKey, " has a length of 0. Please confirm that this field has been properly formatted, and then run this validation script again. ")
          ErrorCount += 1
        #Check for excessive length in value
        if len(fileContents[thisKey]) > 40:
          print("ERROR: The value for field named ", thisKey, " has a length greater than 40. The sample data values in the demo all have fewer than 40 characters, which means that you have too many characters for the value in this line. Please check the line in your yaml file, and then run this validation script again. ")
          ErrorCount += 1
        validateEachConfigField(thisKey, fileContents[thisKey])
        #Mark the item as present
        configStatusDict[thisKey] = "Found"
      for configItem in configStatusDict:
        if configStatusDict[configItem] == "Missing":
          missingFields.append(configItem)
      if len(missingFields) == 0:
        print("All required fields are present in ", fileName)
      else:
        print("Number of missing fields in ", fileName, " is: ", len(missingFields))
        ErrorCount += len(missingFields)
    except yaml.YAMLError as exc:
      print("ERROR: ", fileName, " does not contain valid yaml. ")
      ErrorCount += 1
      print(exc)

def validateKeysYaml():
  global ErrorCount
  fileName = "keys.yaml"
  missingFields = []
  with open(fileName, "r") as stream:
    try:
      fileContents = yaml.safe_load(stream)
      for thisKey in fileContents:
        #Validate the value of the field
        #Check for too many spaces
        if fileContents[thisKey].count(' ') != 0:
          print("ERROR: The value given for the key ", thisKey, " contains spaces, which is illegal. Remove the spaces and re-run the validation script. ")
          ErrorCount += 1
        #Check for empty value.
        if len(fileContents[thisKey]) == 0:
          print("ERROR: The value for field named ", thisKey, " has a length of 0. Please confirm that this field has been properly formatted, and then run this validation script again. ")
          ErrorCount += 1
        #Check for excessive length in value
        if len(fileContents[thisKey]) > 40:
          print("ERROR: The value for field named ", thisKey, " has a length greater than 40. The sample data values in the demo all have fewer than 40 characters, which means that you have too many characters for the value in this line. Please check the line in your yaml file, and then run this validation script again. ")
          ErrorCount += 1
        validateEachKeysField(thisKey, fileContents[thisKey])
        #Mark the item as present
        keysStatusDict[thisKey] = "Found"
      for configItem in keysStatusDict:
        if keysStatusDict[configItem] == "Missing":
          missingFields.append(configItem)
      if len(missingFields) == 0:
        print("All required fields are present in ", fileName)
      else:
        print("Number of missing fields in ", fileName, " is: ", len(missingFields))
        ErrorCount += len(missingFields)

    except yaml.YAMLError as exc:
      print("ERROR: ", fileName, " does not contain valid yaml. ")
      ErrorCount += 1
      print(exc)


validateConfigYaml()
print("Finished running validateConfigYaml(). ")
validateKeysYaml()
print("Finished running validateKeysYaml(). ")
print("ErrorCount is: ", str(ErrorCount))
