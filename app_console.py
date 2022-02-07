'''
    There will be 2 passwords (double encryption)
    1st - encrypt/decrypt file data also used for login
    2nd - encrypt/decrypt for showing/editing the data on the file data
'''
import os

from sqlalchemy.exc import NoResultFound, InvalidRequestError
from db_handler import DBConnect
from encrypt import Encrypt
from cryptography.fernet import InvalidToken
from getpass import getpass

class VaultApp:
    def __init__(self):
        self.auth = False
        self.user_id = None
        self.user_salt = None # salt for encrypting the passwords for the apps
        self.db_connect = DBConnect()

    def display_title_bar(self):
        # Clears the terminal screen, and displays a title bar.
        os.system('cls')

        print("\t************************")
        print("\t*** Vaulting System  ***")
        print("\t************************")
        print("")
        print("")

    def auth_menu(self): 

        print("What would like to do?")

        options = ["Register", "Login", "Exit"]

        for idx, option in enumerate(options):
            print(f'{idx+1} - {option}')

        print("")
        return input(">> ")

    def register(self):
        self.display_title_bar()
        print("Username: ") 
        username = input(">> ")
        print("Password: ")
        password = getpass(">> ")
        print("Password confirmation: ")
        password2 = getpass(">> ")

        try:
            if (password != password2):
                raise ValueError

            self.db_connect.register(username, password)

        except ValueError:
            print("")
            print("Passwords don't match")
            input("")
            return None

    def login(self):
        self.display_title_bar()
        print("Username: ") 
        username = input(">> ")
        print("Password: ")
        password = getpass(">> ")

        try:
            res = self.db_connect.login(username, password)

            if not res:
                raise ValueError

            user_id, salt = res 

            # authenticate user 
            self.user_id  = user_id
            self.user_salt = salt
            self.auth = True

            return

        except ValueError:
            print("")
            print("username and password are wrong.")
            input("")

        except Exception as e:
            print(e) 
            input("")
        
        return None

    def authenticate(self):
        '''
            A little app to check user authentication
        '''
        while True:
            self.display_title_bar()
            choice = self.auth_menu()

            if choice == '1':
                self.register()
            elif choice == '2':
                self.login()
            elif choice == '3':
                return False

            if self.auth:
                break
            
        self.display_title_bar()
        print("You are authenticated.")
        print("Press enter to continue")
        input("")

    def add_app(self):
        '''
            Needed data is
            app, username, password
        '''
        content = {
            'app': '',
            'username': '',
            'secrets' : '',
            'user_id': None,
        }

        try:
            # Get all the data
            self.display_title_bar()

            print('App: ')
            content['app'] = input(">> ")
            print('Username: ')
            content['username'] = input(">> ")

            secrets = self.get_secrets()
            if secrets != None:
                content['secrets'] = secrets 

            print("Is all the info correct? y/n")
            ans = input(">> ")
            if ans.lower() == "n":
                print("Cancelled!")
                input("")
                return
            
            # update values to be saved to the database
            content['user_id'] = self.user_id

            res = self.db_connect.insert(content) # save to DB

            self.display_title_bar()
            if res:
                print("App added to vault.")
                print("Press enter to continue.")
                input("")
                return

            print("Something went wrong.")
            print("Press enter to continue.")
            input("")
        except Exception as error:
            print(error)
            input("")

    def show_apps(self):
        '''
            This will show a list of the apps and classified information
            But the passwords will not be decrypted
        '''
        try:

            res = self.db_connect.select(\
                cols = ['id', 'app', 'username', 'secrets'],  
                conds = {
                    'user_id' : self.user_id,
                },
            )

            # printing headers
            options = ["ID", "App", "Username", "Secrets"]
            for option in options:
                print( f'{option:15}', end="" )
            print("") 

            # printing passwords
            for row in res:
                app_id, app, username, secrets  = row
                print(f'{str(app_id):15}', end="")
                print(f'{str(app):15}{str(username) if username != None else "------":15}', end="")
                print(f'{"******":15}')

            print("")
            print("Press enter to continue.")
            input("")

        except NoResultFound:
            print("")
            print("No app was found with that name!")
            input("")
        except TypeError as error:
            print(error)
            input("")
        except KeyError as error:
            print(error)
            input("")
    
    def show_secret(self):
        '''
            This will decrypt the info requested and return it
            What it does:
                copy to clipboard - user can specify 1,2,3,4 (password, secrets..) 
                show on the console 
        '''
        try:
            self.display_title_bar()
            # which app
            print("App name:")
            app = input(">> ")

            # get second key to decrypt secrets
            print("Secret Password")
            password = getpass(">> ")

            # create a key
            key = Encrypt.get_hash(password, self.user_salt)

            # Query the database
            res = self.db_connect.select(cols=['app', 'username', 'secrets'], conds={
                'user_id': self.user_id, 
                'app': app
            } , many=False)

            # get secrets
            secrets = bytes(res[-1]) 
            secrets = Encrypt.decrypt(secrets, key) # decrypt
            secrets = secrets.decode("utf-8")
            secrets = secrets.split(",") # split the string


            self.display_title_bar()

            # printing headers
            options = ["App", "Username"]
            for val in range(len(secrets) + 2):
                if val == 0:
                    print( f'{options[0]:15}', end="" )
                elif val == 1:
                    print( f'{options[1]:15}', end="" )
                else:
                    show = f'Secret #{val-1}'
                    print(f'{show:15}', end="")
            
            print("\n", end="")
            # printing values
            print(f'{res[0]:15}', end="") # app name
            print(f'{res[1]:15}', end="") # username
            
            # printing secrets values
            for val in secrets:
                print(f'{val:15}', end="")

            print("")
            print("")
            print("Press enter to continue.")
            input("")
        
        except InvalidToken as error:
            print("")
            print("Invalid password!!")
            input("")
        
        except NoResultFound:
            print("")
            print("No app was found with that name!")
            input("")

        except TypeError as error:
            print(error)
            input("")
        except KeyError as error:
            print(error)
            input("")

    def get_secrets(self):
        '''
            Gets the secrets and returns the string 
            already encrypted
        '''

        secrets = []
        print("How many secrets/passwords: (max:4)")
        n = input(">> ")

        if n == "":
            return 

        n = int(n)

        if n > 4:
            print("")
            print("You can only pick 4 secrets.")
            input("")
            return

        print("") # space
        for i in range(n):
            print(f'Secret #{i+1}: ')
            s = getpass(">> ")
            secrets.append(s)

        ##
        # check secret password will be changed 
        # - meaning, confirm secret password before 
        #   changing it
        ##
        print("2nd Password for ecryption:")
        s = getpass(">> ")
        print("Password confirmation:")
        s1 = getpass(">> ")

        if s1 != s:
            print("Passwords don't match")
            input("")
            return

        # encrypt the secrets
        secrets = ",".join(secrets)

        # Encrypt secrets and add it to content array 
        key = Encrypt.get_hash(s, self.user_salt)
        secrets = Encrypt.encrypt(secrets.encode(), key)
        return secrets

    def edit_app(self):
        '''
            Completely overrides the data of the app
            or leave it be
        '''
        content = {
            'user_id': None,
        }

        try:
            # Get all the data
            self.display_title_bar()

            print("Enter a new value or press Enter to keep the same.")

            print("Old App Name: (for selection)")
            old_app = input(">> ")

            app_id = self.db_connect.select(
                cols=["id"],\
                conds={
                    'user_id': self.user_id, 
                    'app': old_app
                }, 
                many=False
            )

            print('App: ')
            app = input(">> ")
            
            print('Username: ')
            username = input(">> ")

            # get the secrets
            secrets = self.get_secrets()

            # check for changes
            if app_id != None:
                content['id'] = app_id[0]
            if app != "":
                content['app'] = app
            if username != "":
                content['username'] = username
            if secrets != None:
                content['secrets'] = secrets
            
            print("Is all the info correct? y/n")
            ans = input(">> ")
            if ans.lower() == "n":
                print("Cancelled!")
                input("")
                return

            # update values to be saved to the database
            content['user_id'] = self.user_id

            res = self.db_connect.update(content) # save to DB

            self.display_title_bar()
            if res:
                print("App updated.")
                print("Press enter to continue.")
                input("")
                return

            print("Something went wrong.")
            print("Press enter to continue.")
            input("")
        except NoResultFound:
            print("")
            print("No app was found with that name!")
            input("")
        except Exception as error:
            print(error)
            input("")
    
    def delete_app(self):
        content = {
            'user_id': None,
            'app_id' : None
        }

        try:
            # Get all the data
            self.display_title_bar()

            print("App Name: (for selection)")
            old_app = input(">> ")

            app_id = self.db_connect.select(
                cols=["id", 'app', 'username'],\
                conds={
                    'user_id': self.user_id, 
                    'app': old_app
                }, 
            )

            # Check how many
            if len(app_id) > 1:
                for app in app_id:
                    self.display_title_bar()
                    print("There seems to be more than one app registered\n with that name.")
                    print("")
                    print("Is this the app?")
                    print(f'App id {app[0]}, name {app[1]} with username -> {app[2]}')
                    ans = input("(y/n) >>  ")

                    if ans.lower() == 'y': 
                        content['id'] = app[0]
                        break
            else:
                content['id'] = app_id[0][0]
                        

            # check for changes
            if not content['id']:
                print("Operation cancelled.")
                print("Press enter to continue.")
                input("")
                return 

            # user id  
            content['user_id'] = self.user_id

            res = self.db_connect.delete(content) # save to DB

            self.display_title_bar()
            if res:
                print("App delete successfully.")
                print("Press enter to continue.")
                input("")
                return

            print("Something went wrong.")
            print("Press enter to continue.")
            input("")
        except Exception as error:
            print(error)
            input("")
    
    def main_menu(self):
        print("What would like to do?")

        options = ["Add App", "Show Apps", "Show Secret", \
            "Edit App", "Delete App", "Exit"]

        for idx, option in enumerate(options):
            print(f'{idx+1} - {option}')

        print("")
        return input(">> ")

    def run(self):
        # App main loop
        while True:
            self.display_title_bar()
            choice = self.main_menu()

            if choice == '1':
                self.add_app()
            elif choice == '2':
                self.show_apps()
            elif choice == '3':
                self.show_secret()
            elif choice == '4':
                self.edit_app()
            elif choice == '5':
                self.delete_app()
            elif choice == '6':
                break
            
    def main(self):
        '''
            Gives the user the option 
            to authenticate and run the program
            or to exit
        '''
        self.authenticate()

        if not self.auth:
            os.system("cls")
            return
        else:
            self.run()
            os.system("cls")


if __name__ == "__main__":
    VaultApp().main()