# PasswordVaultConsole

Just a little app created with Python and SQL Alchemy, in order to learn a bit more about the Alchemy framework.

It is for saving passwords / secret answers for application that we use.

The encrypting of the secrets is done with the algorithm Scrypt.

For using the application it's needed 2 passwords. One for login in, and the other for encrypting/decrypting the secrets.
They are all concatenated in a string and encrypted together. This string is later saved to the database.
