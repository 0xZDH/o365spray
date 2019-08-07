# o365spray

This is a basic username enumeration and password spraying tool aimed at Microsoft authentication. For educational purposes only.

Based on the research from grimhacker:<br>
https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/<br>
https://bitbucket.org/grimhacker/office365userenum/src/master/

NOTE: User enumeration is performed by submitting a single authentication attempt per user. If user enumeration is performed prior to password spraying please consider that all valid users have already submitted a single authentication attempt.

## Usage
Validate a domain is using O365:<br>
`python3 o365spray.py --validate --domain test.com`

Perform username enumeration:<br>
`python3 o365spray.py --enum --username usernames.txt`

Perform password spray:<br>
`python3 o365spray.py --spray --username usernames.txt --password passwords.txt --count 2 --lockout 5`


```
usage: o365spray.py [-h] [-u USERNAME] [-p PASSWORD] [--proxy PROXY]
                    [--count COUNT] [--lockout LOCKOUT] [--domain DOMAIN]
                    [--threads THREADS] [--debug] (-e | -s | -v)

Microsoft User Enumerator and Password Sprayer.

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        File containing list of usernames
  -p PASSWORD, --password PASSWORD
                        File containing list of passwords
  --proxy PROXY         Proxy to pass traffic through: <ip:port>
  --count COUNT         Number of password attempts to run before resetting
                        lockout timer
  --lockout LOCKOUT     Lockout policy reset time (in minutes)
  --domain DOMAIN       Domain name to validate against O365
  --threads THREADS     Number of threads to run. Default: 10
  --debug               Debug output
  -e, --enum            Perform username enumeration
  -s, --spray           Perform password spraying
  -v, --validate        Validate a domain is running O365
```
