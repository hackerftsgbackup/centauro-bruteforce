# centauro-bruteforce (read this file):
script for bruteforce centauro store

# created on:
11.01.2018

# next update:
12.01.2018

# warning:
version 1 of this script
this script is not fully updated
can have some bugs during executing

# python version:
2x

# some examples:
        python centauro.py -e test@gmail.com -p my_password
        python centauro.py -e test@gmail.com -P list_of_passwords.txt
        python centauro.py -E list_of_emails.txt -p my_password
        python centauro.py -E list_of_emails.txt -p list_of_passwords.txt
        python centauro.py -D my_database_of_emails_and_passwords.txt
       
# you can also use some aditional features:
        -s 0.5        | for sleep 500 milliseconds every account
        -a            | for show all informations of bruteforced account
        -d ;          | for change the delimiter of your database (this argument only work with -D argument)
        -o save.txt   | for select the output/save file of bruteforced account
