# /bin/python
import sys
import os
import re
import time
import json
import signal
import boto3
import requests
import urllib2
import logger
import subprocess
import base64

# region files
PROFILE = {}
LOCAL_FOLDER = "/tmp/protego_demo/"
LAMBDA_KEY_FILE = LOCAL_FOLDER + ".lkeys"
PROFILE_FILE = LOCAL_FOLDER + ".profile"
# endregion


# region profile/bundle methods
def updateProfile(p):
    global PROFILE
    PROFILE = p
    return PROFILE


def getProfile():
    return PROFILE


def updateProfileAttr(a, v):
    global PROFILE
    PROFILE[a] = v
    return PROFILE
# endregion


def signal_handler(sig, frame):
    logger.flush()
    logger.bye()
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)


def ApiCall(url, method, data, head):
    requests.packages.urllib3.disable_warnings()
    if url is None or not url.startswith("http"):
        logger.error("invalid URL")
        yn = logger.input("Change URL? [y/N] > ")
        if yn == 'y' or yn == "Y":
            url = logger.input("Enter endpoint URL > ")
            updateProfileAttr("endpoint", url)
            with open(LOCAL_FOLDER + ".endpoint", "w+") as f:
                f.write(url)
        else:
            return

    res = None
    if head is not None:
        if "content-type" in head or "Content-Type" in head:
            headers = head
        else:
            head = json.dumps(head)
            headers = '{"content-type": "application/json", ' + head[1:]
            headers = json.loads(headers)
    else:
        headers = {'content-type': 'application/json'}

    logger.debug("Sending requests to: " + url)
    if method == "POST":
        data = data
        logger.debug("Request Payload: " + str(data))
        try:
            if getProfile()["proxy"] is not None:
                proxies = { 'http': "http://" + getProfile()["proxy"], 'https': "http://" + getProfile()["proxy"] }
                res = requests.post(url, data=data, headers=headers, proxies=proxies, verify=False)
            else:
                res = requests.post(url, data=data, headers=headers)

        except urllib2.HTTPError as e:
            logger.debug("RESPONSE: " + str(e))
            return '{"status": "err"}'

        except ValueError as e:
            if str(e).startswith("Invalid header value"):
                logger.error("Invalid session. Please, re-authenticate")
                updateProfileAttr("isAuth", False)
                updateProfileAttr("session", None)
                logger.pressAnyKey()
                return '{"status": "err"}'

    else:
        proxies = None
        if getProfile()["proxy"] is not None:
            # req.add_header('Host', '127.0.0.1')
            proxies = {'http': "http://" + getProfile()["proxy"], 'https': "http://" + getProfile()["proxy"]}
        try:
            res = requests.get(url, headers=headers, proxies=proxies, verify=False)

        except urllib2.HTTPError as e:
            logger.debug ("RESPONSE: " + str(e))
            return '{"status": "err"}'

        except ValueError as e:
            if str(e).startswith("Invalid header value"):
                logger.error("Invalid session. Please, re-authenticate")
                updateProfileAttr("isAuth", False)
                updateProfileAttr("session", None)
                logger.pressAnyKey()
                return '{"status": "err"}'
    if len(res.content) > 64000:
        logger.debug("Response is too big")
    else:
        logger.debug("RESPONSE: " + res.content.encode('utf-8').strip())

    return res.content


# region AWS-CLI
def run_aws_cmd(service, action, cmd, output=None):
    if output is None:
        output = "table"

    if cmd is None:
        cmd = ""
    cli = "aws {} {} {} --region={}".format(service, action, cmd, getProfile()["region"])
    logger.debug("running command: " + cli)
    os.system(cli + " --output {} > {}{}".format(output, LOCAL_FOLDER, ".awsoutput"))
# endregion




