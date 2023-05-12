# coding: utf-8

## Copyright 2023 Agile Cloud Institute (AgileCloudInstitute.io) .  Rights restricted as described in LICENSE.txt distributed with this repository: https://github.com/AgileCloudInstitute/acm-demos-github

import sys
import subprocess
import re
import json
import random
import string
import yaml
import os

ErrorCount = 0
 
ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

def main(inputArgs): 
  if (sys.version_info >= (3, 5)):
    #This is a check to make sure Python 3 is used. This was tested on Python 3.10, but lower versions of Python 3 might work.
    pass
  else:
    print("ERROR: Python version is too low to run this program. Either upgrade to a higher version of Python 3 or call this program with 'python3 acmDemoSetup.py ...' if running 'python3 --version' on your machine returns a valid version of Python.  This was tested in Python 3.10, but might work with lower versions of Python 3.")
    print("sys.version_info is: ", str(sys.version_info))
    quit("")
  if len(inputArgs) == 1:
    malformedMessage()  
  elif len(inputArgs) == 2:
    if (inputArgs[1]=="validate-config-and-keys"):
      validateKeysYaml(inputArgs[1])
      validateConfigYaml(inputArgs[1])
    else:
      malformedMessage()
  else:
    print("Beginning to run command.")
    if (inputArgs[1] != "create") and (inputArgs[1] != "destroy"):
      malformedMessage()
    if (inputArgs[2]=="aws") or (inputArgs[2]=="awsfiles"):
      if inputArgs[3].count("=") == 1:
        key=inputArgs[3].split("=")[0]
        value=inputArgs[3].split("=")[1]
        if key != "userName":
          malformedMessage()
        else:
          validateInput(key, value)
          userName=value
      else:
        malformedMessage()
      if inputArgs[4].count("=") == 1: 
        inputArgs[4].count("=")
        key=inputArgs[4].split("=")[0]
        value=inputArgs[4].split("=")[1]
        if key != "groupName":
          malformedMessage()
        else:
          validateInput(key, value)
          groupName=value
      else:
        malformedMessage()
      if inputArgs[5].count("=") == 1:
        inputArgs[5].count("=")
        key=inputArgs[5].split("=")[0]
        value=inputArgs[5].split("=")[1]
        if key != "keyPairName":
          malformedMessage()
        else:
          validateInput(key, value)
          keyPairName=value
      else:
        malformedMessage()
      if inputArgs[1] == "create":
        createSequence(userName, groupName, keyPairName, inputArgs[2])
      elif inputArgs[1] == "destroy":
        if inputArgs[6].count("=") == 1:
          inputArgs[6].count("=")
          key=inputArgs[6].split("=")[0]
          value=inputArgs[6].split("=")[1]
          if key != "AWSAccessKeyId":
            malformedMessage()
          else:
            validateInput(key, value)
            AWSAccessKeyId=value
        else:
          malformedMessage()
        print("About to run delete sequence.")
        deleteSequence(userName, groupName, keyPairName, AWSAccessKeyId)
    elif (inputArgs[2]=="azure") or (inputArgs[2]=="azurefiles"):
      if inputArgs[1] == "create":
        if inputArgs[3].count("=") == 1:
          key=inputArgs[3].split("=")[0]
          value=inputArgs[3].split("=")[1]
          if key != "subscriptionId":
            malformedMessage()
          else:
            validateAzureInput(key, value)
            subscriptionId=value
        else:
          malformedMessage()
        if inputArgs[4].count("=") == 1: 
          inputArgs[4].count("=")
          key=inputArgs[4].split("=")[0]
          value=inputArgs[4].split("=")[1]
          if key != "subscriptionName":
            malformedMessage()
          else:
            validateAzureInput(key, value)
            subscriptionName=value
        else:
          malformedMessage()
        if inputArgs[5].count("=") == 1:
          inputArgs[5].count("=")
          key=inputArgs[5].split("=")[0]
          value=inputArgs[5].split("=")[1]
          if key != "tenantId":
            malformedMessage()
          else:
            validateAzureInput(key, value)
            tenantId=value
        else:
          malformedMessage()
        if inputArgs[6].count("=") == 1:
          inputArgs[6].count("=")
          key=inputArgs[6].split("=")[0]
          value=inputArgs[6].split("=")[1]
          if key != "appRegistrationName":
            malformedMessage()
          else:
            validateAzureInput(key, value)
            appRegistrationName=value
        else:
          malformedMessage()

        if inputArgs[7].count("=") == 1:
          inputArgs[7].count("=")
          key=inputArgs[7].split("=")[0]
          value=inputArgs[7].split("=")[1]
          if key != "clientSecretName":
            malformedMessage()
          else:
            validateAzureInput(key, value)
            clientSecretName=value
        else:
          malformedMessage()
        if inputArgs[8].count("=") == 1:
          inputArgs[8].count("=")
          key=inputArgs[8].split("=")[0]
          value=inputArgs[8].split("=")[1]
          if key != "clientSecretEndDate":
            malformedMessage()
          else:
            validateAzureInput(key, value)
            clientSecretEndDate=value
        else:
          malformedMessage()
        firstResults = createAzureSequence(subscriptionId, subscriptionName, tenantId, appRegistrationName, clientSecretName, clientSecretEndDate, inputArgs[2])
        print("")
        print("----------------------------------------------------------------------")
        print("")
        if inputArgs[2] == "azure":
          print("config.yaml file's values include:")
          print("subscriptionId: ", firstResults["subscriptionId"])
          print("subscriptionName: ", firstResults["subscriptionName"])
          print("tenantId: ", firstResults["tenantId"])
          print("")
          print("keys.yaml file's values include: ")
          print("clientName: ", firstResults["clientName"])
          print("clientId: ", firstResults["clientId"])
          print("clientSecret: ", firstResults["clientSecret"])
        elif inputArgs[2] == "azurefiles":
          print("config.yaml and keys.yaml should be created now in the current directory.")
        print("")

      elif inputArgs[1] == "destroy":
        if inputArgs[3].count("=") == 1:
          inputArgs[3].count("=")
          key=inputArgs[3].split("=")[0]
          value=inputArgs[3].split("=")[1]
          if key != "clientId":
            malformedMessage()
          else:
            validateAzureInput(key, value)
          appRegistrationId=value
        else:
          malformedMessage()
        print("About to start delete Azure credentials sequence. ")
        deleteAzureSequence(appRegistrationId)
    else:
      malformedMessage()
      quit()

#############################################################################################
##### CREATE SEQUENCE
#############################################################################################
def createSequence(userName, groupName, keyPairName, operation):
  #1. Create Group
  createGroupCommand='aws iam create-group --group-name '+groupName
  runShellCommand(createGroupCommand)
  #2. Assign PowerUserAccess policy to the new group
  attachPolicyCommand='aws iam attach-group-policy --policy-arn arn:aws:iam::aws:policy/PowerUserAccess --group-name '+ groupName
  runShellCommand(attachPolicyCommand)
  #3. Create user and assign to the new group
  createUserCommand='aws iam create-user --user-name '+userName
  runShellCommand(createUserCommand)
  addUserToGroupCommand='aws iam add-user-to-group --user-name '+userName+' --group-name '+groupName 
  runShellCommand(addUserToGroupCommand)
  #4. Add Programmatic access for user
  createAccessKeyCommand='aws iam create-access-key --user-name '+userName
  data = getShellJsonResponse(createAccessKeyCommand)
  data=json.loads(data)
  AWSAccessKeyId=data["AccessKey"]["AccessKeyId"]
  SecretAccessKey=data["AccessKey"]["SecretAccessKey"]
  #5. Create key pair, setting rsa and pem
  createKeyPairCommand='aws ec2 create-key-pair --key-name '+keyPairName+' --key-type rsa --key-format pem'
  runShellCommand(createKeyPairCommand)
  if operation == "awsfiles":
    #6. Store AWS keys in dict
    resultsDict = {}
    resultsDict["KeyName"] = keyPairName
    resultsDict["AWSAccessKeyId"] = AWSAccessKeyId
    resultsDict["AWSSecretKey"] = SecretAccessKey
    #7. Create keys.yaml and config.yaml by calling functions
    generateKeysFile(resultsDict)
    generateRandomConfig(resultsDict)
###########################
    validateConfigYaml(operation)
    print("Finished running validateConfigYaml(). ")
    validateKeysYaml(operation)
    print("Finished running validateKeysYaml(). ")
    print("ErrorCount is: ", str(ErrorCount))
###########################
  elif operation == "aws":
    print("")
    print("Copy the following three key/value pairs to your keys.yaml to replace the placeholders:")
    print("")
    print("KeyName:",keyPairName)
    print("AWSAccessKeyId:",AWSAccessKeyId)
    print("AWSSecretKey:",SecretAccessKey)
    print("")


##############################################################################################
##### DELETE SEQUENCE
##############################################################################################
def deleteSequence(userName, groupName, keyPairName, AWSAccessKeyId):
  print("About to delete access key. ")
  deleteAccessKeyCommand='aws iam delete-access-key --access-key-id '+AWSAccessKeyId+' --user-name '+userName
  runShellCommand(deleteAccessKeyCommand)
  print("Deleted access key with ID ", AWSAccessKeyId)
  removeUserFromGroupCommand='aws iam remove-user-from-group --user-name '+userName+' --group-name '+groupName
  runShellCommand(removeUserFromGroupCommand)
  print("Removed user ",userName," from group ", groupName)
  deleteUserCommand='aws iam delete-user --user-name '+userName
  runShellCommand(deleteUserCommand)
  print("Deleted user named ", userName)
  detachPolicyCommand='aws iam detach-group-policy --group-name '+groupName+' --policy-arn arn:aws:iam::aws:policy/PowerUserAccess'
  runShellCommand(detachPolicyCommand)
  print("Detached the PowerUserAccess policy from group named ", groupName)
  deleteGroupCommand='aws iam delete-group --group-name '+groupName
  runShellCommand(deleteGroupCommand)
  print("Deleted group named ", groupName)
  deleteKeyPairName='aws ec2 delete-key-pair --key-name '+keyPairName
  runShellCommand(deleteKeyPairName)
  print("Deleted key pair named ", keyPairName)
  print("Completed delete process.")

def malformedMessage():
  print("")
  print("You entered an invalid CLI command.  The CLI commands that we test with have the following syntax: ")
  print("")
  print("python acmDemoSetup.py create azurefiles subscriptionId=valid-subscription-id-guid subscriptionName=validSubscriptionName tenantId=valid-active-directory-tenant-id appRegistrationName=ValidAppRegistrationName clientSecretName=ValidClientSecretName clientSecretEndDate=2024-12-31")
  print("")
  print("python3 acmDemoSetup.py create aws userName=validUserName groupName=validGroupName keyPairName=validKeyPairname")
  print("")
  print("python acmDemoSetup.py destroy azure clientId=valid-client-id-created-fordemo")
  print("")
  print("python3 acmDemoSetup.py destroy aws userName=validUserName groupName=validGroupName keyPairName=validKeyPairname AWSAccessKeyId=ValidAWSAccessKeyIdThatWasCreatedByCreateCommand")
  print("")
  print("python acmDemoSetup.py validate-config-and-keys")
  print("")
  print("Please examine the command that you entered to see how it deviates from these examples.  ")
  print("")
  print("Also please note that Python 3 is required.  Type 'python --version' and 'python3 --version' in your terminal to determine whether you must begin each of the above commands with either 'python3' or 'python' .  The reason we use 'python3' in some of the examples is that the AWS Cloud Shell requires 'python3' to be stated explicitly to avoid invocation of Python 2, while the Azure Cloud Shell maps the 'python' command to Python 3. ")
  quit()

def validateInput(key, value):
  if len(value) > 40:
    print("The value ", value, " is longer than 40 characters.")
    malformedMessage()
  elif key == "AWSAccessKeyId":
    if len(value) != 20:
      print("The value for AWSAccessKeyId must be 20 characters.")
      malformedMessage()
  else:
    pass

################################################################################################
### Start of Azure section
################################################################################################

#############################################################################################
##### CREATE SEQUENCE
#############################################################################################
def createAzureSequence(subscriptionId, subscriptionName, tenantId, appRegistrationName, clientSecretName, clientSecretEndDate, operation):
  #1. Create App Registration
  createAppRegistrationCommand = "az ad app create --display-name "+ appRegistrationName +" --query appId --output tsv"
  clientId = runCreateAppRegistrationCommand(createAppRegistrationCommand)
  if (len(clientId.replace(" ", "")) == 36) and (clientId.count("-")==4):
    print("clientId is: ", clientId)
  else: 
    print("clientId is: ", clientId)
    quit("ERROR: Malformed clientId returned for app registration.")
  showAppRegistrationCommand="az ad app show --id "+clientId
  print("About to show app registration. ")
  appJson=getShellJsonResponse(showAppRegistrationCommand)
  appJson=json.loads(appJson)
  objectId = appJson["id"]
  print("objectId is: ", objectId)
  if (len(objectId.replace(" ", "")) == 36) and (objectId.count("-")==4):
    pass
  else:
    quit("ERROR: Malformed objectId returned for app registration.")
  #2. Create Client Secret
  createClientSecretCommand="az ad app credential reset --id "+clientId+" --append --display-name "+clientSecretName+" --end-date "+clientSecretEndDate+" --query password --output tsv"
  print("createClientSecretCommand is: ", createClientSecretCommand)
  clientSecret=runCreateSecretCommand(createClientSecretCommand)
  #print("clientSecret is: ", clientSecret)

  #3. Create a service principal for the app registration so you can add subscription roles to it after
  ###Create an AAD service principal
  createServicePrincipalCommand="az ad sp create --id "+clientId+" --query id --output tsv"
  print("createServicePrincipalCommand is: ", createServicePrincipalCommand)
  spid=runCreateServicePrincipalCommand(createServicePrincipalCommand)
  print("spid is: ", spid)
  print("Sleeping 45 seconds so that the service principal can propagate in the Azure network before we try to assign subscription roles to it. ")
  import time
  time.sleep(45)

  #4. Add subscription owner role to service principal
  templateName='subscriptionScopeRole.json'
  roleDefinitionIdOwner = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
  roleNameOwner = "Owner"
  addSubscriptionOwnerCommand='az deployment sub create --location WestUS --template-file '+templateName+' --parameters principalId='+spid+' roleDefinitionId='+roleDefinitionIdOwner
  assignSubscriptionRole(addSubscriptionOwnerCommand)
  print('About to confirm that Subscription Owner role has been assigned.')
  roleResult = confirmSubscriptionRole(clientId,roleNameOwner)
  if roleResult:
    print('Confirmed that Subscription Owner role has been assigned.')
  else:
    print('ERROR: Subscription Owner role was NOT assigned.  You must manually assign the role in the GUI at portal.azure.com in order to prevent permissions errors when running the demos. ')
  print("Done adding subscription owner role. ")
   
  ##5. Add subscription contributor role to service principal
  #roleDefinitionIdContributor = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
  #addSubscriptionContributorCommand='az deployment sub create --location WestUS --template-file '+templateName+' --parameters principalId='+spid+' roleDefinitionId='+roleDefinitionIdContributor
  #assignSubscriptionRole(addSubscriptionContributorCommand)
  #print("Done adding subscription contributor role. ")
 
  #6. Assign AD Global Administrator
  roleTemplateIdGlobalAdmin='62e90394-69f5-4237-9190-012177145e10'
  assignAdRole(roleTemplateIdGlobalAdmin, spid)
  print("Done adding global admin role.")
  roleTemplateIdAppAdmin='9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
  assignAdRole(roleTemplateIdAppAdmin, spid)
  print("Done adding application admin role.")
  resultsDict = {}
  resultsDict["subscriptionId"] = subscriptionId
  resultsDict["subscriptionName"] = subscriptionName
  resultsDict["tenantId"] = tenantId
  resultsDict["clientName"] = appRegistrationName
  resultsDict["clientId"] = clientId
  resultsDict["clientSecret"] = clientSecret

  if operation == "azurefiles":
###########################
    #7. Create keys.yaml and config.yaml by calling functions
    generateKeysFile(resultsDict)
    generateRandomConfig(resultsDict)
    validateConfigYaml(operation)
    print("Finished running validateConfigYaml(). ")
    validateKeysYaml(operation)
    print("Finished running validateKeysYaml(). ")
    print("ErrorCount is: ", str(ErrorCount))
###########################
  return resultsDict

##############################################################################################
##### DELETE SEQUENCE
##############################################################################################
def deleteAzureSequence(appRegistrationId):
  print("About to delete app registration. This will cascade-delete dependent credentials. ")
  deleteAppRegistrationCommand = "az ad app delete --id "+appRegistrationId
  print("deleteAppRegistrationCommand is: ", deleteAppRegistrationCommand)
  #runShellCommand(deleteAppRegistrationCommand)
  resp=runDeleteAppRegistrationShellCommand(deleteAppRegistrationCommand)
  print(str(resp))
  print("Finished deleting app registration. ")
  quit("Finished Delete sequence.")


def assignAdRole(roleId, spId): 
  URI="https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId="+roleId+"/members/$ref" 
  BODY=  {"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/"+spId}
  assignGlobalAdminCommand='az rest --method POST --uri '+URI+' --header Content-Type=application/json --body "'+str(BODY)+'"'
  runShellCommand(assignGlobalAdminCommand)

def removeAdRole(roleTemplateId, spId): 
  #1. Retrieve role assignments for user by first retrieving assignments for directory and then filtering for the service principal id
  URI="https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments"#?\$filter=principalId%20eq%20'$"+spId+"'"
  retrieveRoleAssignmentsCommand="az rest --method GET --uri "+URI+" --header Content-Type=application/json"
  roleAssignments=getShellJsonResponse(retrieveRoleAssignmentsCommand)
  # Transform json input to python objects
  input_dict = json.loads(roleAssignments)
  # Filter python objects with list comprehensions
  print("+++++++++++++++++++++++++++++++++++++++++++")
  output_dict = [x for x in input_dict['value'] if (x['principalId'] == spId) and (x['roleDefinitionId'] == roleTemplateId)]
  if len(output_dict)==0:
    print("There are no assignments of role ", roleTemplateId, " for service principal with object id ", spId)
  elif len(output_dict)==1:
    roleAssignmentId=output_dict[0]['id']
    print("roleAssignmentId is: ", roleAssignmentId)
    URI="https://graph.microsoft.com/v1.0/directoryRoles/"+roleAssignmentId+"/members/"+spId+"/$ref"
    deleteRoleAssignmentCommand="az rest --method DELETE --uri "+URI+" --header Content-Type=application/json"
    runShellCommand(deleteRoleAssignmentCommand)
  else:
    print("len(output_dict) is: ", len(output_dict))
    quit("ERROR: Malformed data. More than one role assignment for the same role and the same service principal found in tenant.  ")

#@public
def runShellCommand(commandToRun):
    proc = subprocess.Popen( commandToRun,cwd=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    while True:
      line = proc.stdout.readline()
      if line:
        thetext=line.decode('utf-8').rstrip('\r|\n')
        decodedline=ansi_escape.sub('', thetext)
        logString = decodedline
#        print("shell", logString)
      else:
        break

#@public
def runDeleteAppRegistrationShellCommand(commandToRun, counter=0):
    process = subprocess.run(commandToRun, shell=True, stdout=subprocess.PIPE, text=True)
    data = process.stdout
    err = process.stderr

    if process.returncode == 0:
      return data
    else:
      logString = "Response data string is: " + data
      print(logString)
      logString = "Error: " + str(err)
      print(logString)
      logString = "Error: Return Code is: " + str(process.returncode)
      print(logString)
      logString = "ERROR: "+str(err)+".  Halting the program so that you can debug the cause of the problem."
      print(logString)
      sys.exit(1)


#@public
def runCreateAppRegistrationCommand(commandToRun):
    proc = subprocess.Popen( commandToRun,cwd=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    while True:
      line = proc.stdout.readline()
      if line:
        thetext=line.decode('utf-8').rstrip('\r|\n')
        decodedline=ansi_escape.sub('', thetext)
        if "WARNING:" in decodedline:
          print(decodedline)
        elif (len(decodedline.replace(" ", "")) == 36) and (decodedline.count("-")==4):
          return decodedline
        else:
          print(decodedline)
      else:
        quit("ERROR: Failed to create app registration. Halting program so you can identify the root cause of this error and prevent downstream errors.")

#@public
def runCreateSecretCommand(commandToRun):
    proc = subprocess.Popen(commandToRun,cwd=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    while True:
      line = proc.stdout.readline()
      if line:
        thetext=line.decode('utf-8').rstrip('\r|\n')
        decodedline=ansi_escape.sub('', thetext)
        if "The output includes credentials" in decodedline:
          print(decodedline)
        elif (len(decodedline.replace(" ", "")) == 40):
          return decodedline
        else:
          print(decodedline)
      else:
        quit("ERROR: Failed to create app registration. Halting program so you can identify the root cause of this error and prevent downstream errors.")

#@public
def runCreateServicePrincipalCommand(commandToRun):
  proc = subprocess.Popen( commandToRun,cwd=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
  while True:
    line = proc.stdout.readline()
    if line:
      thetext=line.decode('utf-8').rstrip('\r|\n')
      decodedline=ansi_escape.sub('', thetext)
      if "WARNING:" in decodedline:
        print(decodedline)
      elif (len(decodedline.replace(" ", "")) == 36) and (decodedline.count("-")==4):
        return decodedline
      else:
        print(decodedline)
    else:
      quit("ERROR: Failed to create service principal. Halting program so you can identify the root cause of this error and prevent downstream errors.")


#@public
def getShellJsonResponse(cmd,counter=0):
    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
    data = process.stdout
    err = process.stderr

    if process.returncode == 0:
      return data
    else:
      logString = "data string is: " + data
      print(logString)
      print("--------------------------------------------------------")
      logString = "err is: " + str(err)
      print(logString)
      print("========================================================")
      logString = "process.returncode is: " + str(process.returncode)
      print(logString)
      print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

      if counter < 16:
        counter +=1
        logString = "Sleeping 30 seconds before running the command a second time in case a latency problem caused the attempt to fail. "
        print(logString)
        logString = "Attempt "+str(counter)+ " out of 15. "
        print(logString)
        import time
        time.sleep(30)
        data = getShellJsonResponse(cmd,counter)
        return data 
      else: 
        logString = "Error: " + str(err)
        print(logString)
        logString = "Error: Return Code is: " + str(process.returncode)
        print(logString)
        logString = "ERROR: Failed to return Json response.  Halting the program so that you can debug the cause of the problem."
        print(logString)
        sys.exit(1)

#@public
def assignSubscriptionRole(cmd,counter=0):
    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
    data = process.stdout
    err = process.stderr

    if process.returncode == 0:
      return data
    else:
      logString = "data string is: " + data
      print(logString)
      print("--------------------------------------------------------")
      logString = "err is: " + str(err)
      print(logString)
      print("========================================================")
      logString = "process.returncode is: " + str(process.returncode)
      print(logString)
      print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

      if counter < 3:
        counter +=1
        logString = "Sleeping 30 seconds before running the command a second time in case a latency problem caused the attempt to fail. "
        print(logString)
        logString = "Attempt "+str(counter)+ " out of 15. "
        print(logString)
        import time
        time.sleep(30)
        data = assignSubscriptionRole(cmd,counter)
        return data 
      else: 
        logString = "Warning: " + str(err)
        print(logString)
        logString = "Warning: Return Code is: " + str(process.returncode)
        print(logString)
        logString = "Warning: Failed to return success message from role assignment. Continuing program flow in case there is a latency problem. Make sure to confirm in the portal that the role has been assigned."
        print(logString)
        #sys.exit(1)

#@public
def confirmSubscriptionRole(clientId,roleName,counter=1):
    cmd='az role assignment list --assignee '+clientId
    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
    data = process.stdout
    err = process.stderr
    data = json.loads(data)

    if process.returncode == 0:
      for roleRecord in data:
        print("roleRecord is: ",roleRecord)
        for roleItem in roleRecord:
          if roleItem == "roleDefinitionName":
#            print("Match! roleItem is: ", roleItem)
#            print('Match! roleRecord["roleDefinitionName"] is: ', roleRecord["roleDefinitionName"])
            if roleRecord["roleDefinitionName"] == "Owner":
              print("Confirmed that Subscription ", roleName, " role was assigned to clientId ", clientId)
              return True
      print("Did not find Subscription ",roleName," role for clientId ", clientId," . Going to sleep for 30 seconds and then try again in case network latency is causing the problem. ")
      time.sleep(30)
      counter+=1
      if counter < 4:
        print("About to start attempt ",counter," out of 3.")
        confirmSubscriptionRole(clientId, roleName, counter)
      else:
        print("ERROR: Failed to confirm assignment of Subscription ", roleName, " role for user with clientId ", clientId," . You must manually assign the subscription ", roleName, " role in the GUI at portal.azure.com in order to prevent errors when running the demos.  ")
        return False
    else:
      logString = "data string is: " + str(data)
      print(logString)
      print("--------------------------------------------------------")
      logString = "err is: " + str(err)
      print(logString)
      print("========================================================")
      logString = "process.returncode is: " + str(process.returncode)
      print(logString)
      print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

      if counter < 3:
        counter +=1
        logString = "Sleeping 30 seconds before running the command a second time in case a latency problem caused the attempt to fail. "
        print(logString)
        logString = "Attempt "+str(counter)+ " out of 15. "
        print(logString)
        import time
        time.sleep(30)
        myResult = confirmSubscriptionRole(clientId,roleName,counter)
        return myResult
      else: 
        logString = "Warning: " + str(err)
        print(logString)
        logString = "Warning: Return Code is: " + str(process.returncode)
        print(logString)
        logString = "Warning: Failed to return confirmation of the role assignment. Continuing program flow in case there is a latency problem. Make sure to confirm in the portal that the role has been assigned."
        print(logString)
        return False
        #sys.exit(1)

def validateAzureInput(key, value):
  if len(value) > 40:
    print("The value ", value, " for ",key," is longer than 40 characters.")
    malformedMessage()
  elif (key == "subscriptionId") or (key == "tenantId") or (key == "appRegistrationId"):
    if value.count("-")!=4:
      print("The value for ",key," must contain 5 blocks separated by dashes - .")
      malformedMessage()
    if value.count("-")==4:
      if len(value.split("-")[0]) != 8:
        print("The first block of characters in ",key," must be 8 characters long.")
      if len(value.split("-")[1]) != 4:
        print("The second block of characters in ",key," must be 4 characters long.")
      if len(value.split("-")[2]) != 4:
        print("The third block of characters in ",key," must be 4 characters long.")
      if len(value.split("-")[3]) != 4:
        print("The fourth block of characters in ",key," must be 4 characters long.")
      if len(value.split("-")[4]) != 12:
        print("The fifth block of characters in ",key," must be 12 characters long.")
    if len(value) != 36:
      print("The value for ",key," must be 36 characters.")
      malformedMessage()
  elif (key == "clientSecretEndDate"):
    if value.count("-") != 2:
      print("The value for clientSecertEndDate must contain three blocks of numbers separated by dashes - ")
      malformedMessage()
      if len(value.split("-")[0]) != 4:
        print("The first block of characters in ",key," must be 4 numeric characters long.")
      if len(value.split("-")[1]) != 2:
        print("The second block of characters in ",key," must be 2 numeric characters long.")
      if len(value.split("-")[2]) != 2:
        print("The third block of characters in ",key," must be 2 numeric characters long.")
      if not value.split("-")[0].isdigit():
        print("The first block of characters in ",key," must be a 4 digit integer.")
      if not value.split("-")[1].isdigit():
        print("The second block of characters in ",key," must be a 2 digit integer.")
      if not value.split("-")[2].isdigit():
        print("The third block of characters in ",key," must be a 2 digit integer.")
  else:
    pass

################################################################################################
### End of Azure section
################################################################################################

################################################################################################
### keys.yaml and config.yaml writer section below
################################################################################################

def getAlphaNumericString(numDigits):
  return str(''.join(random.choices((string.ascii_letters).lower() + string.digits, k=numDigits)))

def randomCharacters(length):
   letters = string.ascii_lowercase
   return str(''.join(random.choice(letters) for i in range(length)))

def writeLinesToFile(linesArray, fileName):
  with open(fileName, mode='wt', encoding='utf-8') as myfile:
    myfile.write('\n'.join(linesArray))

def generateRandomConfig(configDict):  
  configLines = []

  if "subscriptionId" in configDict:
    line = 'subscriptionId: '+configDict["subscriptionId"]
  else:
    line = 'subscriptionId: <Follow-instructions-in-article-entitled-Set-up-Seed-Credentials>'
  configLines.append(line)

  if "subscriptionName" in configDict:
    line = 'subscriptionName: '+configDict["subscriptionName"]
  else:
    line = 'subscriptionName: <Follow-instructions-in-article-entitled-Set-up-Seed-Credentials>'
  configLines.append(line)

  if "tenantId" in configDict:
    line = 'tenantId: '+configDict["tenantId"]
  else:
    line = 'tenantId: <Follow-instructions-in-article-entitled-Set-up-Seed-Credentials>'
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
  line = 'rgNameAdmin: '+getAlphaNumericString(5)
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

def generateKeysFile(keysDict):
  keysLines = []

  line = "secretsType: master"
  keysLines.append(line)

  if 'clientName' in keysDict:
    line = "clientName: "+keysDict["clientName"]
  else:
    line = "clientName: <follow-instructions-below-to-get-value>"
  keysLines.append(line)

  if 'clientId' in keysDict:
    line = "clientId: "+keysDict["clientId"]
  else:
    line = "clientId: <follow-instructions-below-to-get-value>"
  keysLines.append(line)

  if 'clientSecret' in keysDict:
    line = "clientSecret: "+keysDict["clientSecret"]
  else:
    line = "clientSecret: <follow-instructions-below-to-get-value>"
  keysLines.append(line)

  if 'KeyName' in keysDict:
    line = "KeyName: "+keysDict["KeyName"]
  else:
    line = "KeyName: <follow-instructions-below-to-get-value>"
  keysLines.append(line)

  if 'AWSAccessKeyId' in keysDict:
    line = "AWSAccessKeyId: "+keysDict["AWSAccessKeyId"]
  else:
    line = "AWSAccessKeyId: <follow-instructions-below-to-get-value>"
  keysLines.append(line)

  if 'AWSSecretKey' in keysDict:
    line = "AWSSecretKey: "+keysDict["AWSSecretKey"]
  else:
    line = "AWSSecretKey: <follow-instructions-below-to-get-value>"
  keysLines.append(line)

  writeLinesToFile(keysLines, 'keys.yaml')

#################################################################################################
### Start of validation section
#################################################################################################
  
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


def validateEachConfigField(key, value, operation):
  global ErrorCount
  valueFoundOrMissing = "Found"
  if value == None:
    #print("ERROR: No value is given for the key ", key)
    #ErrorCount += 1
    pass
  else:
    if key == "subscriptionName":
      if (operation == "awsfiles") or (operation == "validate-config-and-keys"):
        if "Follow-instructions-in-article" in value:
          valueFoundOrMissing = "Missing"
    if key == "subscriptionId":
      if (operation == "awsfiles"):
        if "Follow-instructions-in-article" in value:
          valueFoundOrMissing = "Missing"
      else:
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
      if (operation == "awsfiles"):
        if "Follow-instructions-in-article" in value:
          valueFoundOrMissing = "Missing"
      else:
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
    return valueFoundOrMissing

def validateEachKeysField(key, value):
  global ErrorCount
  if value == None:
    quit("Empty")
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

def validateConfigYaml(operation):
  if not os.path.isfile("config.yaml"):
    quit("ERROR: config.yaml does not exist in the current directory.  Halting the program so you can identify the source of the problem. ")
  #print(" ")
  #print("operation is: ", operation)
  #print(" ")
  global ErrorCount
  fileName = "config.yaml"
  missingFields = []
  missingValues = []
  with open(fileName, "r", encoding='utf-8') as stream:
    try:
      fileContents = yaml.safe_load(stream)
      for thisKey in fileContents:
        #Validate the value of the field
        #Check for empty field
        if fileContents[thisKey] == None:
          print("ERROR: No value is given for the key ", thisKey)
          missingValues.append(thisKey)
          ErrorCount += 1
        elif (operation=="awsfiles") and ((thisKey=="subscriptionId") or (thisKey=="subscriptionName") or (thisKey=="tenantId")) and ("Follow-instructions" in fileContents[thisKey]):
          #skipping because this case is handled elsewhere in the logic.
          pass
        else:
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
        valFoundOrMissing = validateEachConfigField(thisKey, fileContents[thisKey], operation)
        if valFoundOrMissing == "Missing":
          missingValues.append(thisKey)
        #Mark the item as present
        configStatusDict[thisKey] = "Found"
      for configItem in configStatusDict:
        if configStatusDict[configItem] == "Missing":
          print("ERROR: Field named ", configItem, " in config.yaml has a missing value. ")
          missingFields.append(configItem)
      if len(missingFields) == 0:
        print("All required fields are present in ", fileName)
      else:
        print("Number of missing fields in ", fileName, " is: ", len(missingFields))
        ErrorCount += len(missingFields)
      if len(missingValues) != 0:
        if operation == "awsfiles":
          print(" ")
          print("The following config.yaml fields are missing values.  The Azure demos will not work unless you put valid values for the following fields into your config.yaml: ")
          for missingVal in missingValues:
            printStr = str(str(missingVal).replace(" ","")+":").replace(" ","")
            print(printStr)
          print(" ")
        if operation == "validate-config-and-keys":
          print(" ")
          print("The following config.yaml fields are missing values.  The demos will not work unless you put valid values for the following fields into your config.yaml: ")
          for missingVal in missingValues:
            printStr = str(str(missingVal).replace(" ","")+":").replace(" ","")
            print(printStr)
          print(" ")

      else:
        print("All of the fields in config.yaml have values.")
    except yaml.YAMLError as exc:
      print("ERROR: ", fileName, " does not contain valid yaml. ")
      ErrorCount += 1
      print(exc)
  print("ErrorCount is: ", str(ErrorCount))

def validateKeysYaml(operation):
  if not os.path.isfile("keys.yaml"):
    quit("ERROR: keys.yaml does not exist in the current directory.  Halting the program so you can identify the source of the problem. ")
#  if operation == "validate-config-and-keys":
#    print("Inside validateKeysYaml()")
  global ErrorCount
  fileName = "keys.yaml"
  missingFields = []
  missingValues = []
  with open(fileName, "r", encoding='utf-8') as stream:
    try:
      fileContents = yaml.safe_load(stream)
      for thisKey in fileContents:
        if (operation=="awsfiles") and ((thisKey=="clientName") or (thisKey=="clientId") or (thisKey=="clientSecret")) and ("follow-instructions" in fileContents[thisKey]):
          missingValues.append(thisKey)
          #Mark the item as present because the key is present and only the value is missing.
          keysStatusDict[thisKey] = "Found"
        elif (operation == "azurefiles") and ((thisKey=="KeyName") or (thisKey=="AWSAccessKeyId") or (thisKey=="AWSSecretKey")) and ("follow-instructions" in fileContents[thisKey]):
          missingValues.append(thisKey)
          #Mark the item as present because the key is present and only the value is missing.
          keysStatusDict[thisKey] = "Found"
        else:
          #Validate the value of the field
          if fileContents[thisKey] == None:
            print("ERROR: No value was present for the key ", thisKey)
            missingValues.append(thisKey)
            keysStatusDict[thisKey] = "Found"
            ErrorCount += 1
          else:
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
#
      for configItem in keysStatusDict:
        if keysStatusDict[configItem] == "Missing":
          print("ERROR: Field named ", configItem, " in keys.yaml has a missing value. ")
          missingFields.append(configItem)
      if len(missingFields) == 0:
        print("All required fields are present in ", fileName)
      else:
        print("Number of missing fields in ", fileName, " is: ", len(missingFields))
        ErrorCount += len(missingFields)
      if len(missingValues) != 0:
        if operation == "awsfiles":
          print(" ")
          print("The following keys.yaml fields are missing values.  The Azure demos will not work unless you put valid values for the following fields into your keys.yaml: ")
          for missingVal in missingValues:
            print(missingVal,":")
          print(" ")
        if operation == "azurefiles":
          print(" ")
          print("The following keys.yaml fields are missing values.  The AWS demos will not work unless you put valid values for the following fields into your keys.yaml: ")
          for missingVal in missingValues:
            print(missingVal,":")
          print(" ")
      else:
        print("All of the fields in keys.yaml have values.")

    except yaml.YAMLError as exc:
      print("ERROR: ", fileName, " does not contain valid yaml. ")
      ErrorCount += 1
      print(exc)

#################################################################################################
### End of validation section
#################################################################################################

main(sys.argv)
