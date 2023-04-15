# coding: utf-8

## Copyright 2023 Agile Cloud Institute (AgileCloudInstitute.io) as described in LICENSE.txt distributed with this repository.

###############################################################################################################
### Instructions
###############################################################################################################

# PREREQUISITE: Run configFilesGenerator.py in your devbox to create keys.yaml and config.yaml.  You will be pasting the results of these instructions into that keys.yaml to replace the default dummy values for 3 fields given below. 

# 1. Log in to the AWS GUI console as root, or as a high enough user to create PowerUsers and perform other high-authority actions.
# 2. Set the region to us-west-2 for the demo. (Later, after you successfully complete the demo, you can expiriment with other regions)
# 3. Search for "CloudShell" in the AWS services, and navigate to open a cloudshell terminal
# 4. Type "aws --version" in the cloudshell terminal.  This is tested in version 2.11. If you later encounter problems, note the version. and please report back to us.
# 5. Download this script into your cloudshell by typing the following into the terminal:
#    wget https://github.com/AgileCloudInstitute/acm-demos-github/blob/main/manageAWSKeys.py?raw=true -O manageAWSKeys.py
# 6. Confirm that the file has been successfully downloaded by typing "ls -al" and looking for the file name in the results.
# 7. Run the following command to create IAM resources including keys:

#    python manageAWSKeys.py create userName=ACMUser_abc groupName=SuperUserACM_abc keyPairName=ACMKeyPair_abc

#    Note that the values for userName, groupName, and keyPairName can be any valid values. But start with these because they work, assuming you do not already have resources with the same names created in your account.

# 8. Examine the IAM resources in your account through the GUI console to confirm that a user and group were created with the given names, and that the PowerUser role was attached to the group.
# 9. Examine the EC2 key pairs in your account through the GUI console to confirm that a key pair was created with the given name.
# 10. Examine the cloudshell terminal output to confirm there were no errors reported, and that the keys were printed to the terminal.
# 11. Note that you can comment out the printing of the keys for security reasons later. This is just a demo. You can delete these keys as soon as you successfully run the demo using the delete commands given below.
# 12. Copy the following three lines of yaml after "THE THREE LINES TO ADD TO keys.yaml FOR AWS ARE:" at the end of the terminal output and paste them into the keys.yaml that was created when you ran configFilesGenerator.py

#     KeyName: actual-value-redacted
#     AWSAccessKeyId: actual-value-redacted
#     AWSSecretKey: actual-value-redacted

#     Note that the 3 preceding lines will have actual secrets that you will need to copy into keys.yaml
#     Also note that you will be replacing the empty/default lines that were written for keyName, AWSAccessKeyId, and AWSSecretKey when you ran configFilesGenerator.py

# 13. Save a backup copy of the keys.yaml someplace safe, so you have access to it to delete the resources later.

# REPEAT STEPS 1 THROUGH 13 ABOVE A SECOND TIME TO POPULATE THE SECOND keys.yaml FILE DESCRIBED IN THE GETTING STARTED FOR ENGINEERS DOCUMENTATION.
# FOR THE SECOND RUN THROUGH OF THE ABOVE STEPS, REPLACE THE VALUES OF THE INPUT PARAMETERS WITH DIFFERENT VALUES TO AVOID ERRORS RELATED TO PREEXISTING RESOURCES WITH THE SAME NAMES.
# FOR EXAMPLE, THE FOLLOWING COMMAND WORKS IF YOU DO NOT HAVE PREEXISTING RESOURCES WITH THE SAME NAMES:

#    python manageAWSKeys.py create userName=ACMUser_xyz groupName=SuperUserACM_xyz keyPairName=ACMKeyPair_xyz

# AFTER BOTH keys.yaml HAVE BEEN CREATED, CONTINUE WITH THE GETTING STARTED FOR ENGINEERS TUTORIAL.

# LATER, WHEN YOU HAVE SUCCESSFULLY RUN THE DEMOS, YOU CAN DELETE THE RESOURCES CREATED BY THIS PROGRAM AND REPLACE THEM WITH NEW RESOURCES FOR SECURITY REASONS.
# THE DESTROY COMMANDS CORRESPONDING WITH THE COMMANDS WE GAVE ABOVE ARE:  

# python manageAWSKeys.py destroy userName=ACMUser_abc groupName=SuperUserACM_abc keyPairName=ACMKeyPair_abc accessKeyID=ValidAccessKeyIdThatWasCreatedByCreateCommand
# python manageAWSKeys.py destroy userName=ACMUser_xyz groupName=SuperUserACM_xyz keyPairName=ACMKeyPair_xyz accessKeyID=ValidAccessKeyIdThatWasCreatedByCreateCommand

# Note the value you give for ValidAccessKeyIdThatWasCreatedByCreateCommand will be the value that you saved in the backedup copy of each of the keys.yaml files you created when following the above instructions. 

import sys
import subprocess
import re
import json

ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

def main(inputArgs): 
  if len(inputArgs) == 1:
    malformedMessage()  
  else:
    if inputArgs[2].count("=") == 1:
      key=inputArgs[2].split("=")[0]
      value=inputArgs[2].split("=")[1]
      if key != "userName":
        malformedMessage()
      else:
        validateInput(key, value)
        userName=value
    else:
      malformedMessage()
    if inputArgs[3].count("=") == 1: 
      inputArgs[3].count("=")
      key=inputArgs[3].split("=")[0]
      value=inputArgs[3].split("=")[1]
      if key != "groupName":
        malformedMessage()
      else:
        validateInput(key, value)
        groupName=value
    else:
      malformedMessage()
    if inputArgs[4].count("=") == 1:
      inputArgs[4].count("=")
      key=inputArgs[4].split("=")[0]
      value=inputArgs[4].split("=")[1]
      if key != "keyPairName":
        malformedMessage()
      else:
        validateInput(key, value)
        keyPairName=value
    else:
      malformedMessage()
    if inputArgs[1] == "create":
      createSequence(userName, groupName, keyPairName)
    elif inputArgs[1] == "destroy":
      if inputArgs[5].count("=") == 1:
        inputArgs[5].count("=")
        key=inputArgs[5].split("=")[0]
        value=inputArgs[5].split("=")[1]
        if key != "accessKeyID":
          malformedMessage()
        else:
          validateInput(key, value)
          accessKeyID=value
      else:
        malformedMessage()
      deleteSequence(userName, groupName, keyPairName, accessKeyID)

#############################################################################################
##### CREATE SEQUENCE
#############################################################################################
def createSequence(userName, groupName, keyPairName):
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
  AccessKeyId=data["AccessKey"]["AccessKeyId"]
  SecretAccessKey=data["AccessKey"]["SecretAccessKey"]
  #5. Create key pair, setting rsa and pem
  createKeyPairCommand='aws ec2 create-key-pair --key-name '+keyPairName+' --key-type rsa --key-format pem'
  runShellCommand(createKeyPairCommand)

  keyNameLine='KeyName: '+keyPairName
  accessKeyIdLine='AWSAccessKeyId: '+AccessKeyId
  secretAccessKeyLine='AWSSecretKey: '+SecretAccessKey
  print("THE THREE LINES TO ADD TO keys.yaml FOR AWS ARE:")
  print(keyNameLine)
  print(accessKeyIdLine)
  print(secretAccessKeyLine)

##############################################################################################
##### DELETE SEQUENCE
##############################################################################################
def deleteSequence(userName, groupName, keyPairName, accessKeyID):
  deleteAccessKeyCommand='aws iam delete-access-key --access-key-id '+accessKeyID+' --user-name '+userName
  runShellCommand(deleteAccessKeyCommand)
  removeUserFromGroupCommand='aws iam remove-user-from-group --user-name '+userName+' --group-name '+groupName
  runShellCommand(removeUserFromGroupCommand)
  deleteUserCommand='aws iam delete-user --user-name '+userName
  runShellCommand(deleteUserCommand)
  detachPolicyCommand='aws iam detach-group-policy --group-name '+groupName+' --policy-arn arn:aws:iam::aws:policy/PowerUserAccess'
  runShellCommand(detachPolicyCommand)
  deleteGroupCommand='aws iam delete-group --group-name '+groupName
  runShellCommand(deleteGroupCommand)
  deleteKeyPairName='aws ec2 delete-key-pair --key-name '+keyPairName
  runShellCommand(deleteKeyPairName)

#@public
def runShellCommand(commandToRun):
    proc = subprocess.Popen( commandToRun,cwd=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    while True:
      line = proc.stdout.readline()
      if line:
        thetext=line.decode('utf-8').rstrip('\r|\n')
        decodedline=ansi_escape.sub('', thetext)
        logString = decodedline
        print("shell", logString)
      else:
        break

#@public
def getShellJsonResponse(cmd,counter=0):
    process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
    data = process.stdout
    err = process.stderr
    logString = "data string is: " + data
    print(logString)
    logString = "err is: " + str(err)
    print(logString)
    logString = "process.returncode is: " + str(process.returncode)
    print(logString)

    if process.returncode == 0:
      return data
    else:
      if counter < 16:
        logString = "Sleeping 30 seconds before running the command a second time in case a latency problem caused the attempt to fail. "
        print(logString)
        logString = "Attempt "+str(counter)+ " out of 15. "
        print(logString)
        import time
        time.sleep(30)
        counter +=1
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

def malformedMessage():
  print("You must add arguments to run this script. Examples include: ")
  print("python manageAWSKeys.py create userName=validUserName groupName=validGroupName keyPairName=validKeyPairname")
  print("python manageAWSKeys.py destroy userName=validUserName groupName=validGroupName keyPairName=validKeyPairname accessKeyID=ValidAccessKeyIdThatWasCreatedByCreateCommand")
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

main(sys.argv)
