# -*- coding: utf-8 -*-
# /bin/python
import os
from termcolor import colored
import utils


# region logger
def debug(txt):
    if utils.getProfile()["verbose"]:
        print(colored("> " + txt + "\n", "grey", None))


def alert(txt):
    print(colored(txt + "\n", "yellow", None))


def input(txt):
    return raw_input(colored(txt, "magenta", None))


def info(txt):
    print(colored("> " + txt + "\n", "cyan", None))


def error(txt):
    print(colored("> " + txt + "\n", "red", None))
# endregion


# region prints
def flush():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def pressAnyKey():
    raw_input(colored("\n--- Press any key to continue ---\n", "blue", None))


def liner():
    print(colored("---------------------------------------------\n", "blue", None))


def pwned():
    print(colored("[** Pwned **]", "white", "on_green"))


def logo():
    demo = ('''
██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗  ██████╗     ██╗ ██╗      ██████╗ ███████╗███╗   ███╗ ██████╗ 
██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝ ██╔═══██╗    ╚██╗╚██╗     ██╔══██╗██╔════╝████╗ ████║██╔═══██╗
██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║  ███╗██║   ██║     ╚██╗╚██╗    ██║  ██║█████╗  ██╔████╔██║██║   ██║
██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║   ██║██║   ██║     ██╔╝██╔╝    ██║  ██║██╔══╝  ██║╚██╔╝██║██║   ██║
██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╔╝╚██████╔╝    ██╔╝██╔╝     ██████╔╝███████╗██║ ╚═╝ ██║╚██████╔╝
╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝     ╚═╝ ╚═╝      ╚═════╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝ 
''')
    print(demo)


def bye():
    bye = ('''
██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗  ██████╗       ██╗ ██╗ ██╗    ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝ ██╔═══██╗     ██╔╝██╔╝██╔╝    ██╔══██╗╚██╗ ██╔╝██╔════╝
██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║  ███╗██║   ██║    ██╔╝██╔╝██╔╝     ██████╔╝ ╚████╔╝ █████╗  
██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║   ██║██║   ██║    ╚██╗╚██╗╚██╗     ██╔══██╗  ╚██╔╝  ██╔══╝  
██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╔╝╚██████╔╝     ╚██╗╚██╗╚██╗    ██████╔╝   ██║   ███████╗
╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝       ╚═╝ ╚═╝ ╚═╝    ╚═════╝    ╚═╝   ╚══════╝
                                                                                                          
''')
    print bye

# endregion
