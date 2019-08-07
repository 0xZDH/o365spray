# o365spray

This is a basic username enumeration and password spraying tool aimed at Microsoft O365. For educational purposes only.

Microsoft makes it possible to identify valid and invalid usernames when the domain is using O365. If an account on a non-O365 domain is attempted Microsoft will not flag this as an invalid username (404 HTTP response), but instead return responses making it seem as if the account is is valid and the password was incorrect or the account requires 2FA. This allows for false positives when spraying/enumerating so this tool includes the `--validate` flag in order to identify if a specific domain is using Microsoft O365 prior to performing spraying/enumeration.

NOTE: User enumeration is performed by submitting a single authentication attempt per user. If user enumeration is performed prior to password spraying please consider that all valid users have already submitted a single authentication attempt.

## Usage
Validate a domain is using O365:<br>
`python3 o365spray.py --validate --domain test.com`

Perform username enumeration:<br>
`python3 o365spray.py --enum --username usernames.txt`

Perform password spray:<br>
`python3 o365spray.py --spray --username usernames.txt --password passwords.txt --count 2 --lockout 5`


```
usage: o365spray.py [-h] [-u USERNAME] [-p PASSWORD] [--count COUNT]
                    [--lockout LOCKOUT] [--domain DOMAIN] [--proxy PROXY]
                    [--threads THREADS] [--output OUTPUT] [--debug]
                    (-e | -s | -v)

Microsoft O365 User Enumerator and Password Sprayer.

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        File containing list of usernames
  -p PASSWORD, --password PASSWORD
                        File containing list of passwords
  --count COUNT         Number of password attempts to run before resetting
                        lockout timer
  --lockout LOCKOUT     Lockout policy reset time (in minutes)
  --domain DOMAIN       Domain name to validate against O365
  --proxy PROXY         Proxy to pass traffic through: <ip:port>
  --threads THREADS     Number of threads to run. Default: 10
  --output OUTPUT       Output file name for enumeration and spraying
  --debug               Debug output
  -e, --enum            Perform username enumeration
  -s, --spray           Perform password spraying
  -v, --validate        Validate a domain is running O365
```

## Acknowledgments

**grimhacker** - *Research and discovery of user enumeration within Office 365 via ActiveSync.* See the [blog post](https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/) and the [office365userenum](https://bitbucket.org/grimhacker/office365userenum/src/master/) tool.
