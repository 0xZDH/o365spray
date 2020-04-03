# o365spray

This is a username enumeration and password spraying tool aimed at Microsoft O365. For educational purposes only.

This tool reimplements a collection of enumeration and spray techniques researched and identified by those mentioned in [Acknowledgments](#Acknowledgments).

Microsoft makes it possible to identify valid and invalid usernames when the domain is using O365. User enumeration and password spraying can both be done using Microsoft's Autodiscover, ActiveSync, or Azure AD APIs. Microsoft returns false positives for non-O365 domain accounts so this tool has an auto-validate feature to ensure the target domain is using O365.

> NOTE: ActiveSync user enumeration is performed by submitting a single authentication attempt per user. If ActiveSync enumeration is run with password spraying, the tool will automatically reset the lockout timer prior to the password spray. Autodiscover user enumeration works without any authentication attempts and does not require a lockout reset before password spraying.

## Usage

Perform username enumeration:<br>
`python3 o365spray.py --enum -U usernames.txt --domain test.com`

Perform password spray:<br>
`python3 o365spray.py --spray -U usernames.txt -P passwords.txt --count 2 --lockout 5 --domain test.com`


```
usage: o365spray.py [-h] -d DOMAIN [--validate] [--enum] [--spray]
                    [-u USERNAME] [-p PASSWORD] [-U USERFILE] [-P PASSFILE]
                    [-c COUNT] [-l LOCKOUT]
                    [--validate-type {openid-config,getuserrealm}]
                    [--enum-type {activesync,autodiscover}]
                    [--spray-type {activesync,autodiscover,msol}]
                    [--rate RATE] [--safe SAFE] [--paired] [--timeout TIMEOUT]
                    [--proxy PROXY] [--output OUTPUT] [--debug]

Microsoft O365 User Enumerator and Password Sprayer -- v1.1

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target O365 domain
  --validate            Perform domain validation only.
  --enum                Perform username enumeration.
  --spray               Perform password spraying.
  -u USERNAME, --username USERNAME
                        Username(s) delimited using commas.
  -p PASSWORD, --password PASSWORD
                        Password(s) delimited using commas.
  -U USERFILE, --userfile USERFILE
                        File containing list of usernames.
  -P PASSFILE, --passfile PASSFILE
                        File containing list of passwords.
  -c COUNT, --count COUNT
                        Number of password attempts to run before resetting
                        lockout timer. Default: 1
  -l LOCKOUT, --lockout LOCKOUT
                        Lockout policy reset time (in minutes). Default: 15
                        minutes
  --validate-type {openid-config,getuserrealm}
                        Specify which spray type to perform. Default:
                        getuserrealm
  --enum-type {activesync,autodiscover}
                        Specify which spray type to perform. Default:
                        Autodiscover
  --spray-type {activesync,autodiscover,msol}
                        Specify which spray type to perform. Default:
                        Autodiscover
  --rate RATE           Number of concurrent connections during enum and
                        spray. Default: 10
  --safe SAFE           Terminate scan if `n` locked accounts are observed.
                        Default: 10
  --paired              Password spray pairing usernames and passwords (1:1).
  --timeout TIMEOUT     Request timeout. Default: 25
  --proxy PROXY         Proxy to pass traffic through: [http(s)://ip:port]
  --output OUTPUT       Output directory. Default: Current directory
  --debug               Debug output
```

## Acknowledgments

#### ActiveSync Code/References
* [@grimhacker](https://bitbucket.org/grimhacker)
* Research and discovery of user enumeration via ActiveSync
* See [blog post](https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/) and [office365userenum](https://bitbucket.org/grimhacker/office365userenum/src/master/).

#### Autodiscover Code/References
* [@Raikia](https://github.com/Raikia)
* User enumeration via Autodiscover without authentication attempts
* [UhOh365](https://github.com/Raikia/UhOh365)

#### MSOL Code/References
* [@dafthack](https://github.com/dafthack)
* Password spray via MSOL
* [MSOLSpray](https://github.com/dafthack/MSOLSpray)
 * *This was rewritten in Python by byt3bl33d3r*: https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f

#### Other Code References
* [@byt3bl33d3r](https://github.com/byt3bl33d3r): [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit/)
* [@sensepost](https://github.com/sensepost): [Ruler](https://github.com/sensepost/ruler/)
