#!/usr/bin/env python3
import os
import base64
import json
import getpass
import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

ALLOWED_DBMS = ["mysql", "postgres"]
CONFIGFILE = os.getenv("HOME") + "/.dbook.conf"
FORBIDDENNAMES = ["-a", "--add-bookmark", "-d", "--delete-bookmark", "--encrypt", "--decrpyt", "all", "*", "all", "list", "delete"]

def encrypt(key, source):
    key = bytes(key, "utf8")
    source = bytes(source, "utf8")
    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding
    data = IV + encryptor.encrypt(source)
    return base64.b64encode(data).decode("latin-1")


def decrypt(key, source):
    key = bytes(key, "utf8")
    source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()
    IV = source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])
    padding = data[-1]
    if data[-padding:] != bytes([padding]) * padding:
        return False
    return data[:-padding]


def firstRun():
    print("Welcome, you are running this program for the first time.")
    print("Do you want to encrypt your bookmark file? (y/n)")
    while True:
        ans = str(input(">>> ")).lower()
        if ans in ('y', 'n'):
            break
        else:
            print("Invalid input!\n")
    print()
    if ans == 'y':
        pwd = promptNewPassword()
        content = encrypt(pwd, "{}")
        writeConfigFile(CONFIGFILE, content, True)
    else:
        writeConfigFile(CONFIGFILE, "{}", False)
    print("Bookmark file created successfully")
    return


def promptNewPassword():
    while True:
        print("Enter the password with which you want to encrypt your bookmark file:")
        pwd1 = getpass.getpass(">>> ")
        print("and again...")
        pwd2 = getpass.getpass(">>> ")
        if pwd1 == pwd2:
            return pwd1
        print("Passwords don't match. Try again\n")


def readConfigFile(path):
    with open(path, 'r') as configfile:
        configfilecontent = configfile.readlines()
        if configfilecontent[0] == "!CRYPTED\n":
            crypted = True
            configfilecontent = configfilecontent[1:]
        else:
            crypted = False
        filecontent = str()
        for line in configfilecontent:
            filecontent += line
        configfile.close()
    return filecontent, crypted


def writeConfigFile(path, content, crypted):
    with open(path, 'w+') as configfile:
        if crypted:
            configfile.write("!CRYPTED\n" + content)
        else:
            configfile.write(content)
        configfile.close()
    return True


class Bookmark:
    _dbms = None
    _hostname = None
    _port = None
    _user = None
    _database = None
    _password = None

    def __init__(self, dbms=None, hostname=None, port=None, user=None, database=None, password=None):
        if dbms is not None:
            if type(dbms) is str:
                if dbms.lower() in ALLOWED_DBMS:
                    self._dbms = dbms.lower()
        if hostname is not None:
            if type(hostname) is str:
                self._hostname = str(hostname)
        if port is not None:
            try:
                port = int(port)
                if port >= 0 and port <= 65535:
                    self._port = port
            except ValueError:
                pass
        if user is not None:
            if type(user) is str:
                self._user = str(user)
        if database is not None:
            if type(database) is str:
                self._database = str(database)
        if password is not None:
            if type(database) is str:
                self._database = str(database)

    def setdbms(self, dbms):
        if type(dbms) is str:
            if dbms.lower() in ALLOWED_DBMS:
                self._dbms = dbms.lower()
                return True
            else:
                return False
        else:
            return False

    def sethostname(self, hostname):
        if type(hostname) is str:
            self._hostname = str(hostname)
            return True
        else:
            return False

    def setport(self, port=None):
        if port is None or port == "":
            if self._dbms is not None:
                if self._dbms == "mysql":
                    self._port = 3306
                    return True
                elif self._dbms == "postgres":
                    self._port = 5432
                    return True
                else:
                    return False
            else:
                return False

        try:
            port = int(port)
            if port >= 0 and port <= 65535:
                self._port = port
                return True
            else:
                return False
        except ValueError:
            return False

    def setuser(self, user):
        if type(user) is str:
            self._user = str(user)
            return True
        else:
            return False

    def setdatabase(self, database):
        if type(database) is str:
            self._database = str(database)
            return True
        else:
            return False

    def setpassword(self, password=None):
        if password is None:
            self._password = None
            return True
        elif password == "":
            self._password = None
            return True
        elif type(password) is str:
            self._password = str(password)
            return True
        else:
            return False

    def getdbms(self):
        if self._dbms is None:
            return False
        else:
            return self._dbms

    def gethostname(self):
        if self._hostname is None:
            return False
        else:
            return self._hostname

    def getport(self):
        if self._port is None:
            return False
        else:
            return self._port

    def getuser(self):
        if self._user is None:
            return False
        else:
            return self._user

    def getdatabase(self):
        if self._database is None:
            return False
        else:
            return self._database

    def getpassword(self):
        return self._password

    def checkValidity(self):
        if None in (self._dbms, self._hostname, self._port, self._user, self._database):
            return False
        else:
            return True

    def importJSON(self, jsondata):
        returnlist = list()
        returnlist.append(self.setdbms(jsondata["dbms"]))
        returnlist.append(self.sethostname(jsondata["hostname"]))
        returnlist.append(self.setport(jsondata["port"]))
        returnlist.append(self.setuser(jsondata["username"]))
        returnlist.append(self.setpassword(jsondata["password"]))
        returnlist.append(self.setdatabase(jsondata["database"]))
        if False in returnlist:
            return False
        else:
            return True

    def exportJSON(self):
        if self.checkValidity():
            return {"dbms":self.getdbms(), "hostname":self.gethostname(), "port":self.getport(), "username":self.getuser(), "password":self.getpassword(), "database":self.getdatabase()}
        else:
            return False


def promptBookmark():
    # prompt todo
    bookmark = Bookmark()
    print("Which DBMS do you use? (postgres/mysql)")
    while True:
        ans = str(input(">>> "))
        if bookmark.setdbms(ans) is True:
            break
        print("Invalid dbms!\n")
    print("On which host can I reach your DBMS?")
    while True:
        ans = str(input(">>> "))
        if bookmark.sethostname(ans) is True:
            break
        print("Invalid hostname!\n")
    print("On which port your DBMS is listening? (for default port leave empty)")
    while True:
        ans = str(input(">>> "))
        if bookmark.setport(ans) is True:
            break
        print("Invalid Port!\n")
    print("As which user do you want to login?")
    while True:
        ans = str(input(">>> "))
        if bookmark.setuser(ans) is True:
            break
        print("Invalid Username!\n")
    print("The password for user " + ans + " please")
    while True:
        ans = getpass.getpass(">>> ")
        if bookmark.setpassword(ans) is True:
            break
        print("Invalid Password!\n")
    print("To which database do you want to connect?")
    while True:
        ans = str(input(">>> "))
        if bookmark.setdatabase(ans) is True:
            break
        print("Invalid Database!\n")
    return bookmark


def getBookmarknametoAdd(config):
    print("How do you want to call your Bookmark?")
    while True:
        bookmarkname = str(input(">>> "))
        if bookmarkname.lower() not in config.keys() and bookmarkname.lower() not in FORBIDDENNAMES:
            return bookmarkname
        print("Bookmark already exists\n")


def getBookmarknametoDelete(config):
    print("Which bookmark do you want to delete?")
    while True:
        bookmarkname = str(input(">>> "))
        if bookmarkname in config.keys():
            return bookmarkname
        print("Bookmark doesn't exist\n")


def getBookmarknametoList(config):
    print("Which bookmark do you want to list?")
    while True:
        bookmarkname = str(input(">>> "))
        if bookmarkname in config.keys() or bookmarkname in ("all", "*"):
            return bookmarkname
        print("Bookmark doesn't exist\n")


def printBookmark(bookmark, bookmarkname):
    bookmark = bookmark.exportJSON()
    print(bookmarkname + ":")
    print("\tDBMS:     " + bookmark["dbms"])
    print("\tHostname: " + bookmark["hostname"])
    print("\tPort:     " + str(bookmark["port"]))
    print("\tUsername: " + bookmark["username"])
    print("\tPassword: ", end="")
    for i in range(len(bookmark["password"])):
        print("*", end="")
    print()
    print("\tDatabase:", bookmark["database"])


def dbconnect(bm):
    if bm.getdbms() == "postgres":
        if bm.getpassword() is None:
            returnstatus = os.system("pgcli postgres://" + bm.getuser() + "@" + bm.gethostname() + ":" + str(bm.getport())+ "/" + bm.getdatabase())
        else:
            returnstatus = os.system("pgcli postgres://" + bm.getuser() + ":" + bm.getpassword() +  "@" + bm.gethostname() + ":" + str(bm.getport())+ "/" + bm.getdatabase())
        if returnstatus is not 0:
            print("pgcli closed with error code: " + str(returnstatus))
            return False
        else:
            return True
    elif bm.getdbms() == "mysql": # better mysql support todo
        returnstatus = os.system("mycli -h " + bm.gethostname() + " -P " + str(bm.getport()) + " -u " + bm.getuser() + " -D " + bm.getdatabase())
        if returnstatus is not 0:
            print("mycli closed with error code: " + str(returnstatus))
            return False
        else:
            return True


def main():
    # check for first run
    if not os.path.exists(CONFIGFILE):
        firstRun()
        return 0

    # interpret cli args
    if len(sys.argv) > 1:

        # read config file and decrypt if needed
        config, crypted = readConfigFile(CONFIGFILE)
        if crypted:
            print("Your bookmark file is enrypted. Enter your passwort to decrypt it")
            pwd = getpass.getpass(">>> ")
            config = decrypt(pwd, config)
            if config is False:
                print("Wrong password, cannot decrypt your bookmark file")
                return 1
            try:
                config = json.loads(config)
            except json.decoder.JSONDecodeError:
                print("Wrong password, cannot decrypt your bookmark file")
                return 1
        else:
            try:
                config = json.loads(config)
            except json.decoder.JSONDecodeError:
                print("Invalid bookmark file")
                return 1

        # interpret bookmark file
        for bookmark in config.keys():
            temp = Bookmark()
            temp.importJSON(config[bookmark])
            config[bookmark] = temp

        # add bookmarks
        if sys.argv[1].lower() in ["-a", "--add-bookmark", "add", "create"]:
            if len(sys.argv) > 2:
                if sys.argv[2].lower() not in config.keys() and sys.argv[2].lower() not in FORBIDDENNAMES:
                    bookmarkname = sys.argv[2]
                else:
                    print("The specified bookmark already exists\n")
                    bookmarkname = getBookmarknametoAdd(config)
            else:
                bookmarkname = getBookmarknametoAdd(config)
            config[bookmarkname] = promptBookmark()
            print("Successfully added bookmark: " + bookmarkname)

        # delete bookmarks
        elif sys.argv[1].lower() in ["-d", "--delete-bookmark", "delete", "del", "rm"]:
            if len(sys.argv) > 2:
                if sys.argv[2] in config.keys():
                    bookmarkname = sys.argv[2]
                else:
                    print("The specified bookmark doesn't exist\n")
                    bookmarkname = getBookmarknametoDelete(config)
            else:
                bookmarkname = getBookmarknametoDelete(config)
            config.pop(bookmarkname, None)
            print("Successfully removed bookmark: " + bookmarkname)

        # list bookmarks
        elif sys.argv[1].lower() in ["-l", "--list-bookmark", "list", "ls"]:
            if len(sys.argv) > 2:
                if sys.argv[2].lower() in config.keys():
                    bookmarkname = sys.argv[2].lower()
                    printBookmark(config[bookmarkname], bookmarkname)
                elif sys.argv[2].lower() in ('all', '*'):
                    for bookmark in config.keys():
                        printBookmark(config[bookmark], bookmark)
                else:
                    print("The specified bookmark doesn't exist\n")
                    bookmarkname = getBookmarknametoList(config)
                    if bookmarkname.lower() in ('all', '*'):
                        for bookmark in config.keys():
                            printBookmark(config[bookmark], bookmark)
                    else:
                        printBookmark(config[bookmarkname], bookmarkname)
            else:
                for bookmark in config.keys():
                    print(bookmark)

        # encrypt bookmarkfile
        elif sys.argv[1] in ["--encrypt", "encrypt", "-e"]:
            if crypted:
                print("Bookmark file is already encrypted. Nothing todo")
                return 0
            crypted = True
            pwd = promptNewPassword()

        # decrypt bookmarkfile
        elif sys.argv[1] in ["--decrypt", "decrypt", "-u"]:
            if not crypted:
                print("Bookmark file is already decrypted. Nothing todo")
                return 0
            crypted = False

        # connect bookmark
        elif sys.argv[1].lower() in config:
            if dbconnect(config[sys.argv[1].lower()]):
                return 0
            else:
                return 1

        else:
            print("Unknown argument or bookmark not found")
            return 1
    else:
        dbconnect(promptBookmark())

    # reverse interpret bookmark file
    for bookmark in config.keys():
        temp = config[bookmark].exportJSON()
        config[bookmark] = temp

    # write config file
    config = json.dumps(config, indent=4)
    if crypted:
        content = encrypt(pwd, config)
        writeConfigFile(CONFIGFILE, content, True)
    else:
        writeConfigFile(CONFIGFILE, config, False)




if __name__ == "__main__":
    try:
        exitstatus = main()
        exit(exitstatus)
    except KeyboardInterrupt:
        exit(1)
    except EOFError:
        exit(1)
