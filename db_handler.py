from configparser import ConfigParser

import sqlalchemy
from encrypt import Encrypt


# From sqlalchemy
from sqlalchemy import create_engine, \
    MetaData, Table, Column, \
    Integer, String, LargeBinary, Sequence, ForeignKey, \
    select, insert, update, delete, or_, and_ 

from sqlalchemy.exc import InvalidRequestError

class DBConnect:
    '''
        URL to create the engine 
            dialect+driver://username:password@host:port/database
    '''
    engine = None
    
    def __init__(self, config_file='./files/db.ini'):
        self.config_file = config_file
        db_url = self.config()
        DBConnect.engine = create_engine(db_url, future=True)
        self.get_tables()
    
    def get_tables(self):
        self.META_DATA = MetaData(bind=DBConnect.engine)

        # Tables definition
        ACCOUNT_TABLE = Table(
            "account", self.META_DATA,
            Column("id", Integer, primary_key=True),
            Column("username", String(255), unique=True, nullable=False),
            Column("hashed_pass", LargeBinary(), nullable=False),
            Column("access_salt", LargeBinary(), nullable=False),
            Column("login_salt", LargeBinary(), nullable=False)
        )

        VAULT_TABLE = Table(
            "vault", self.META_DATA,
            Column("id", Integer, primary_key=True),
            Column("user_id", Integer, ForeignKey("account.id"), nullable=False),
            Column("username", String(255), nullable=False),
            Column("app", String(255), nullable=False),
            Column("secrets", LargeBinary()),
        )

        self.META_DATA.create_all(DBConnect.engine, checkfirst=True)
        self.account = self.META_DATA.tables['account']
        self.vault = self.META_DATA.tables['vault']

    def config(self, section='postgresql'):
        '''
            Handles the configuration file 'filename.ini'
            Returns the config of a section in a dictionary

            Default for section is postgresql
        '''
        parser = ConfigParser() # create parser
        parser.read(self.config_file)

        # get section
        data = {}

        if parser.has_section(section):
            params = parser.items(section)
            for param in params:
                data[param[0]] = param[1]
        else:
            raise Exception(f'Section {section} not found in the file {self.config_file}.')
        

        # dialect+driver://username:password@host:port/database
        url = f'postgresql://{data["user"]}:{data["password"]}@{data["host"]}:{data["port"]}/{data["dbname"]}'
        return url
    
    def select(self, cols, conds, many=True ):
        '''
            cols -> select columns like ["id", "username"]
            conds -> these are the conditions/constraints to select
                the rows. this translates to a where condition connected
                with AND operators
                - the user_id must be specified here to select the apps
                    only for the user
        '''
        assert conds.get("user_id", None) != None, "The user id must be specified"

        if not cols:
            query = select(self.vault)\
                .where( and_( \
                    *[self.vault.c.get(key) == conds[key] for key in conds.keys() ]
                ) )
            
        else:
            query = select(Column(name) for name in cols)\
                .where( and_( \
                    *[self.vault.c.get(key) == conds[key] for key in conds.keys() ]
                ) )
        
        with DBConnect.engine.connect() as conn:
            res = conn.execute(query)

            if many:
                res = res.fetchall()
            else:
                res = res.fetchone()
            
            if not res:
                raise sqlalchemy.exc.NoResultFound

            return res

    def insert(self, content):
        '''
            INSERT INTO THE DATA TABLE

            Content acceptable
            app, username, password, secret1, secret2, secret3, user 
        '''
        if content.get("user_id", None) == None:
            return False

        query = insert(self.vault).values(content)

        with DBConnect.engine.connect() as conn:
            conn.execute(query)
            conn.commit()
        
        return True

    def update(self, content):
        '''
            Updates a row
        '''
        if content.get("user_id", None) == None:
            return False
        
        user_id = content.pop('user_id', None)
        app_id = content.pop("id", None)

        if user_id == None:
            raise InvalidRequestError("Invalid Request: User ID must be specified")
        elif app_id == None:
            raise InvalidRequestError("Invalid Request: App ID must be specified")

        query = update(self.vault).values(content).\
            where(and_(self.vault.c.user_id == user_id, self.vault.c.id == app_id))

        with DBConnect.engine.connect() as conn:
            conn.execute(query)
            conn.commit()
        
        return True

    def delete(self, content):
        '''
            To delete a row completly
            content must have
        '''
        if content.get("user_id", None) == None:
            return False
        
        user_id = content.pop('user_id', None)
        app_id = content.pop("id", None)

        if user_id == None:
            raise InvalidRequestError("Invalid Request: User ID must be specified")
        elif app_id == None:
            raise InvalidRequestError("Invalid Request: App ID must be specified")

        query = delete(self.vault).\
            where(and_(self.vault.c.user_id == user_id, self.vault.c.id == app_id))

        with DBConnect.engine.connect() as conn:
            conn.execute(query)
            conn.commit()
        
        return True




    def login(self, username, password):
        ''' 
            Checks the existence of the user and password 
            on account table.
        '''
        with DBConnect.engine.connect() as conn:
            # check if the user exists
            query = select(self.account.c.id, \
                        self.account.c.login_salt, \
                        self.account.c.access_salt, \
                        self.account.c.hashed_pass, \
                    )\
                    .where(self.account.c.username == username)

            res = conn.execute(query).fetchone()
            # does not exist
            if (not res):
                return None
            
            user_id, l_salt, a_salt, h_pass = res

            l_salt = bytes(l_salt) 
            a_salt = bytes(a_salt) 
            h_pass = bytes(h_pass)

            hashed = Encrypt.get_hash(password, l_salt)

            if (hashed != h_pass):
                return None
            
            return user_id, a_salt

    def register(self, username, password):
        ''' 
            Checks the existence of the user 
            if it does not exist it creates it
        '''
        with DBConnect.engine.connect() as conn:
            query = select(self.account) \
                    .where(self.account.c.username == username)
            
            res = conn.execute(query).fetchone()

            # the username is already in use
            if (res):
                return None
            
            h_pass, l_salt = Encrypt.gen_pass_key(password)
            a_salt = Encrypt.get_random_salt()

            query = self.account.insert().values({
                'username':username,
                'hashed_pass': h_pass,
                'login_salt': l_salt,
                'access_salt': a_salt
            })

            conn.execute(query)
            conn.commit()

        return True




if __name__ == "__main__":
    db = DBConnect()
    # ## KEY
    # key, salt = Encrypt.gen_pass_key("begin")

    # ## Encrypt and decrypt
    # string = "Test me".encode()
    # token = Encrypt.encrypt(string, key)
    # data = Encrypt.decrypt(token, key)

    ## INSERT TEST
    # res = db.insert(
    #     content = {
    #         'app': 'jounin',
    #         'username': 'ElderKamikaze',
    #         'password':bytes('hakunamatata', "utf-8"),
    #         'secret1': None,
    #         'secret2': None,
    #         'secret3': None,
    #         'user_id': 7
    #     }
    # )
    # print(res)

    ## LOGIN AND REGISTER TEST
    user, salt = db.login('naruto', 'hinata')
    print(db.select(cols=[], conds={'user_id' : user }, many=True))
    
    # print(db.register('minata', 'kushina'))
