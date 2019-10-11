# o365spray

This is a username enumeration and password spraying tool aimed at Microsoft O365. For educational purposes only.

Microsoft makes it possible to identify valid and invalid usernames when the domain is using O365. If an account on a non-O365 domain is attempted Microsoft will not flag this as an invalid username (404 HTTP response), but instead returns false positives making it seem as if the account is is valid and the password was incorrect.

NOTE: User enumeration is performed by submitting a single authentication attempt per user. If user enumeration is performed prior to password spraying please consider that all valid users have already submitted a single authentication attempt. If enumeration and spraying are run together, the tool will automatically reset the lockout timer prior to password spraying.

## Usage
Perform username enumeration:<br>
`python3 o365spray.py --enum -U usernames.txt --domain test.com`

Perform password spray:<br>
`python3 o365spray.py --spray -U usernames.txt -P passwords.txt --count 2 --lockout 5 --domain test.com`


```
usage: o365spray.py [-h] -d DOMAIN [-e] [-s] [-u USERNAME] [-p PASSWORD]
                    [-U USERFILE] [-P PASSFILE] [-c COUNT] [-l LOCKOUT]
                    [--secondary] [--timeout TIMEOUT] [--proxy PROXY]
                    [--output OUTPUT] [--paired] [--debug]

Microsoft O365 User Enumerator and Password Sprayer

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target O365 domain
  -e, --enum            Perform username enumeration
  -s, --spray           Perform password spraying
  -u USERNAME, --username USERNAME
                        Username(s) delimited using commas
  -p PASSWORD, --password PASSWORD
                        Password(s) delimited using commas
  -U USERFILE, --userfile USERFILE
                        File containing list of usernames
  -P PASSFILE, --passfile PASSFILE
                        File containing list of passwords
  -c COUNT, --count COUNT
                        Number of password attempts to run before resetting
                        lockout timer. Default: 1
  -l LOCKOUT, --lockout LOCKOUT
                        Lockout policy reset time (in minutes). Default: 5
                        minutes
  --secondary           Use `ActiveSync` for password spraying. Use
                        `OpenID-Config` for validation.
  --timeout TIMEOUT     Request timeout. Default: 25
  --proxy PROXY         Proxy to pass traffic through: <ip:port>
  --output OUTPUT       Output directory. Default: .
  --paired              Password spray pairing usernames and passwords (1:1).
  --debug               Debug output
```

## Acknowledgments

**grimhacker** - *Research and discovery of user enumeration within Office 365 via ActiveSync.* See the [blog post](https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/) and the [office365userenum](https://bitbucket.org/grimhacker/office365userenum/src/master/) tool.<br>
**byt3bl33d3r** - [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit/)<br>
**sensepost** - [Ruler](https://github.com/sensepost/ruler/)