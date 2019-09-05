# region imports
import sys
import pkg_resources
dependencies = open("requirements.txt").readlines()
try:
    pkg_resources.require(dependencies)
except Exception as e:
    sys.exit("missing requirements: {}".format(str(e)))

from lib.utils import *
from lib import xploiter as Xploiter
from lib import logger as logger

from termcolor import colored
import inquirer
import os
import argparse
import json
# endregion


def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--profile", required=False, default=None, help="Attackers AWS profile name (as appears in ~/.aws/credentials")
    parser.add_argument("-r", "--region", required=False, default="us-east-1", help="The region in deployed the DVSA on (defualt is `us-east-1`")
    parser.add_argument("-e", "--endpoint", required=False, default=None, help="The endpoint (API Gateway) for the lambda with XXE Vulnerability")
    parser.add_argument("-a", "--account", required=False, default=None, help="The AWS Account ID on which DVSA is installed")
    parser.add_argument("-x", "--proxy", required=False, default=None, help="[HOST]:[PORT]")
    parser.add_argument("-v", "--verbose", required=False, action="store_true", help="Print additional information to stdout")
    parser.add_argument("-d", "--attack", required=False, default="None", help="Run attack directly. Use: [xxe, injection]")
    args = parser.parse_args()

    return {
        "attack": args.attack,
        "profile": args.profile,
        "endpoint": args.endpoint,
        "account": args.account,
        "region": args.region,
        "proxy": args.proxy,
        "verbose": args.verbose
    }


def showInitManu():
    profile = getProfile()
    exploit = ""
    while exploit.find("[!]") == -1:
        choices = [
                ' [01] XXE',
                ' [02] Injection',
                colored(' [!] Quit', 'yellow')
        ]

        question = [
            inquirer.List('exploit',
                          message="Choose an exploit",
                          choices=choices
            )
        ]

        try:
            return inquirer.prompt(question)["exploit"]
        except:
            signal_handler(None, None)


def exploit_navigator(exploit):
        try:
            x = exploit[exploit.find("[")+1:exploit.find("]")]
        except:
            return

        if x=="01":
            Xploiter.xploit_xxe()

        elif x=="02":
            Xploiter.xploit_injection()

        # quit
        elif x.find("!") > -1:
            logger.flush()
            logger.bye()
            sys.exit(0)

        else:
            return


def main():
    # update arguments to memory
    args = getArguments()
    print args

    if not os.path.exists(LOCAL_FOLDER):
        os.makedirs(LOCAL_FOLDER)
    elif args['endpoint'] is None and os.path.isfile(LOCAL_FOLDER + ".endpoint"):
        with open(LOCAL_FOLDER + ".endpoint") as f:
            args['endpoint'] = f.read()
    else:
        pass
    updateProfile(args)

    if "attack" in getProfile() and getProfile()["attack"] is not None:
        if getProfile()["attack"] == "xxe":
            Xploiter.xploit_xxe()
        elif getProfile()["attack"] == "injection":
            Xploiter.xploit_injection()
        else:
            pass

    # run menu in loop until exit
    exploit = None
    while exploit is None or exploit.find("[!]") == -1:
        logger.flush()
        logger.logo()
        exploit = showInitManu()
        logger.liner()
        exploit_navigator(exploit)

    # quit
    if exploit.find("[!]") > -1:
        logger.flush()
        logger.bye()
        sys.exit(0)

    else:
        print("What did you do ?!")
        sys.exit(1)


if __name__ == "__main__":
    main()
