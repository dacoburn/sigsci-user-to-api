# encoding = utf-8
import time
from datetime import datetime, timedelta
import json
import calendar
import requests
import os
import argparse
from timeit import default_timer as timer

start = timer()

parser = argparse.ArgumentParser()
parser = argparse.ArgumentParser(description="Example script to expire events " +
                                 "from Signal Sciences")
parser.add_argument("--config", type=str,
                    help="Specify the file with the configuration options")

parser.add_argument("--api", type=str,
                    help="Can be 'True' or 'False', will either enable API" +
                    " mode or disable it for the user(s).")

parser.add_argument("--user", type=str,
                    help="Specify the user you would like to convert. " +
                    "It is either this option OR --userFile")

parser.add_argument("--userFile", type=str,
                    help="Specify the file with list of users, one per" +
                    " line, that you would like to convert.")

opts = parser.parse_args()

# Initial setup

if "config" in opts and (opts.config is not None):
    confFile = open(opts.config, "r")
    confJson = json.load(confFile)
else:
    confJson = ""



# Logfile for the script
logFile = "sigsci-user-to-api.log"

try:
    os.remove(logFile)
except OSError as e:
    # print("Failed to remove %s with: %s" % (logFile,e.strerror))
    pass


# Simple logout function for saving log file
def logOut(msg):
    log = open(logFile, 'a')
    data = "%s: %s" % (datetime.now(), msg)
    log.write(data)
    log.write("\n")
    log.close
    #print(msg)


if "api" in opts and (opts.api is not None and opts.api == "True"):
    apiEnable = True
    logOut("API Mode Enabled")
elif "api" in opts and (opts.api is not None and opts.api == "False"):
    apiEnable = False
    logOut("API Mode Disabled")
else:
    print("Unrecognized option for api has to be \"True\" or \"False\"")
    logOut("Unrecognized option for api has to be \"True\" or \"False\"")
    exit(1)


singleUser = None
userFile = None
userList = []

if "user" in opts and (opts.user is not None):
    singleUser = opts.user
    logOut("Single User Mode")
elif ("userFile" in opts and opts.userFile is not None):
    userFile = opts.userFile
    with open(userFile, "r") as ins:
        for line in ins:
            userList.append(line.rstrip())
    logOut("Multi User Mode from File")
else:
    print("Please use --user or --userFile but not both")
    logOut("Please use --user or --userFile but not both")

# This is requried and is used for all API requests.
if "email" in confJson and confJson["email"] is not None:
    email = confJson["email"]
else:
    email = os.environ.get('SIGSCI_EMAIL')
    if email is None or email == "":
        logOut("email must be specified in conf file")
        exit()

if "corp_name" in confJson and confJson["corp_name"] is not None:
    corp_name = confJson["corp_name"]
else:
    corp_name = os.environ.get('SIGSCI_CORP')
    if corp_name is None or corp_name == "":
        logOut("corp_name must be specified in conf file")
        exit()

if "password" in confJson and confJson["password"] is not None:
    password = confJson["password"]
else:
    password = os.environ.get('SIGSCI_PASSWORD')

if "apitoken" in confJson and confJson["apitoken"] is not None:
    apitoken = confJson["apitoken"]
else:
    apitoken = os.environ.get('SIGSCI_TOKEN')
    if (apitoken is None or apitoken == "") and \
            (password is None or password == ""):
        logOut("apitoken or password must be specified in conf file")
        exit()

# Dashboard URL
api_host = 'https://dashboard.signalsciences.net'

logOut("email: %s" % email)
logOut("corp: %s" % corp_name)
if apitoken is not None:
    logOut("Using API TOKEN")
else:
    logOut("Using Password Auth")

pythonRequestsVersion = requests.__version__
userAgentVersion = "1.0.0"
userAgentString = "SigSci-Expire-Events/%s (PythonRequests %s)" \
    % (userAgentVersion, pythonRequestsVersion)


# Handy function for pretty printing JSON
def prettyJson(data):
    return(json.dumps(data, indent=4, separators=(',', ': ')))


# Definition for error handling on the response code
def checkResponse(code, responseText, curSite=None,
                  from_time=None, until_time=None):
    site_name = curSite
    if code == 400:
        if "Rate limit exceeded" in responseText:
            return("rate-limit")
        else:
            logOut("Bad API Request (ResponseCode: %s)" % (code))
            logOut("ResponseError: %s" % responseText)
            logOut('from: %s' % from_time)
            logOut('until: %s' % until_time)
            logOut('email: %s' % email)
            logOut('Corp: %s' % corp_name)
            logOut('SiteName: %s' % site_name)
            return("bad-request")
    elif code == 500:
        logOut(
            "Caused an Internal Server error (ResponseCode: %s)" % (code))
        logOut("ResponseError: %s" % responseText)
        logOut('from: %s' % from_time)
        logOut('until: %s' % until_time)
        logOut('email: %s' % email)
        logOut('Corp: %s' % corp_name)
        logOut('SiteName: %s' % site_name)
        return("internal-error")
    elif code == 401:
        logOut(
            "Unauthorized, likely bad credentials or site configuration," +
            " or lack of permissions (ResponseCode: %s)" % (code))
        logOut("ResponseError: %s" % responseText)
        logOut('email: %s' % email)
        logOut('Corp: %s' % corp_name)
        logOut('SiteName: %s' % site_name)
        return("unauthorized")
    elif code >= 400 and code <= 599 and code != 400 \
            and code != 500 and code != 401:
        logOut("ResponseError: %s" % responseText)
        logOut('from: %s' % from_time)
        logOut('until: %s' % until_time)
        logOut('email: %s' % email)
        logOut('Corp: %s' % corp_name)
        logOut('SiteName: %s' % site_name)
        return("other-error")
    else:
        return("success")


# If Password auth, perform Auth
def sigsciAuth():
    logOut("Authenticating to SigSci API")
    # Authenticate
    authUrl = api_host + '/api/v0/auth'
    authHeader = {
        "User-Agent": userAgentString
    }
    auth = requests.post(
        authUrl,
        data={"email": email, "password": password},
        headers=authHeader
    )

    authCode = auth.status_code
    authError = auth.text

    authResult = checkResponse(authCode, authError)
    if authResult is None or authResult != "success":
        logOut("API Auth Failed")
        logOut(authResult)
        exit()
    elif authResult is not None and authResult == "rate-limit":
        logOut("SigSci Rate Limit hit")
        logOut("Retrying in 10 seconds")
        time.sleep(10)
        sigsciAuth()
    else:
        parsed_response = auth.json()
        token = parsed_response['token']
        logOut("Authenticated")
        return(token)

# Actually call the Requests function
def getRequestData(url, headers, method="GET", payload=None):
    response_raw = requests.request(method, url, headers=headers, data=payload)
    responseCode = response_raw.status_code
    responseError = response_raw.text
    return(response_raw, responseCode, responseError)


def getUserDetails(userName, token, apiMode=None):
    writeStart = timer()
    logOut("-- Starting getUserDetails --")
    if apiMode == "apitoken":
        headers = {
            'Content-type': 'application/json',
            'x-api-user': email,
            'x-api-token': apitoken,
            'User-Agent': userAgentString
        }
    else:
        headers = {
            'Content-type': 'application/json',
            'Authorization': 'Bearer %s' % token,
            'User-Agent': userAgentString
        }

    url = api_host + ('/api/v0/corps/%s/users/%s?expand=member' % (corp_name, userName))

    responseResult, responseCode, ResponseError = \
        getRequestData(url, headers, method="GET")

    sigSciRequestCheck = \
        checkResponse(responseCode, ResponseError, curSite=None,
                      from_time=None, until_time=None)

    # print(ResponseError)
    # print(sigSciRequestCheck)
    # exit()
    if sigSciRequestCheck is None or sigSciRequestCheck != "success":
        logOut("Failed to get user data")
        logOut(sigSciRequestCheck)
        exit()
    elif sigSciRequestCheck is not None and \
            sigSciRequestCheck == "rate-limit":
        logOut("SigSci Rate Limit hit")
        logOut("Retrying in 10 seconds")
        time.sleep(10)
    else:
        response = json.loads(responseResult.text)

    urlMember = api_host + ('/api/v0/corps/%s/users/%s/memberships' % (corp_name, userName))

    responseResult, responseCode, ResponseError = \
        getRequestData(urlMember, headers, method="GET")

    sigSciRequestCheck = \
        checkResponse(responseCode, ResponseError, curSite=None,
                      from_time=None, until_time=None)

    if sigSciRequestCheck is None or sigSciRequestCheck != "success":
        logOut("Failed to get user data")
        logOut(sigSciRequestCheck)
        exit()
    elif sigSciRequestCheck is not None and \
            sigSciRequestCheck == "rate-limit":
        logOut("SigSci Rate Limit hit")
        logOut("Retrying in 10 seconds")
        time.sleep(10)
    else:
        responseMember = json.loads(responseResult.text)

    for memberInfo in responseMember["data"]:
        memberInfo["isSelected"] = True

    memberUri = response["memberships"]["uri"]
    response["memberships"] = responseMember
    #response["memberships"]["uri"] = memberUri
    # print(prettyJson(response))
    # exit()
    writeEnd = timer()
    writeTime = writeEnd - writeStart
    writeTimeResult = round(writeTime, 2)
    userInfoJson = response
    logOut("Total Event Output Time: %s seconds" % writeTimeResult)

    logOut("Got User details for %s" % userName)
    logOut("%s" % userInfoJson)
    logOut("-- Finished getUserDetails --")
    return(userInfoJson)

# Pull Event data from the API
def updateUser(userName, token, userInfo=None, apiMode=None):
    writeStart = timer()
    if apiMode == "apitoken":
        headers = {
            'Content-type': 'application/json',
            'x-api-user': email,
            'x-api-token': apitoken,
            'User-Agent': userAgentString
        }
    else:
        headers = {
            'Content-type': 'application/json',
            'Authorization': 'Bearer %s' % token,
            'User-Agent': userAgentString
        }

    url = api_host + ('/api/v0/corps/%s/users/%s' % (corp_name, userName))

    if apiMode:
        logOut("Updating user %s to be an API User" % userName)
    else:
        logOut("Updating user %s to not be an API User" % userName)


    userInfo["apiUser"] = apiEnable
    userDetailsJson = json.dumps(userInfo)

    responseResult, responseCode, ResponseError = \
        getRequestData(url, headers, method="PATCH", payload=userDetailsJson)

    sigSciRequestCheck = \
        checkResponse(responseCode, ResponseError, curSite=None,
                      from_time=None, until_time=None)

    if sigSciRequestCheck is None or sigSciRequestCheck != "success":
        logOut("Failed to update user")
        logOut(sigSciRequestCheck)
        exit()
    elif sigSciRequestCheck is not None and \
            sigSciRequestCheck == "rate-limit":
        logOut("SigSci Rate Limit hit")
        logOut("Retrying in 10 seconds")
        time.sleep(10)
    else:
        response = json.loads(responseResult.text)


    writeEnd = timer()
    writeTime = writeEnd - writeStart
    writeTimeResult = round(writeTime, 2)
    logOut("Total Event Output Time: %s seconds" % writeTimeResult)


if apitoken is not None and apitoken != "":
    authMode = "apitoken"
    logOut("AuthMode: API Token")
else:
    authMode = "password"
    logOut("AuthMode: Password")
    sigsciToken = sigsciAuth()

if singleUser is not None:
    if authMode == "apitoken":
        userResult = getUserDetails(userName=singleUser, token=apitoken,
                                        apiMode="apitoken")
        updateUser(userName=singleUser,
                     token=apitoken, apiMode="apitoken", userInfo=userResult)
    else:
        userResult = getUserDetails(userName=singleUser, token=sigsciToken)
        updateUser(userName=singleUser, token=sigsciToken, userInfo=userResult)
    print("Updated user: %s" % singleUser)
    logOut("Updated user: %s" % singleUser)
else:
    for curUser in userList:   
        if authMode == "apitoken":
            userResult = getUserDetails(userName=curUser, token=apitoken,
                                            apiMode="apitoken")
            updateUser(userName=curUser, token=apitoken,
                        apiMode="apitoken", userInfo=userResult)
        else:
            userResult = getUserDetails(userName=curUser, token=sigsciToken)
            updateUser(userName=curUser,
                         token=sigsciToken, userInfo=userResult)
        print("Updated user: %s" % curUser)
        logOut("Updated user: %s" % curUser)

    logOut("Finished updating users")

end = timer()
totalTime = end - start
timeResult = round(totalTime, 2)
logOut("Total Script Time: %s seconds" % timeResult)
