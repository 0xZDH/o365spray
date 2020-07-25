# o365spray

This is a username enumeration and password spraying tool aimed at Microsoft O365. For educational purposes only.

This tool reimplements a collection of enumeration and spray techniques researched and identified by those mentioned in [Acknowledgments](#Acknowledgments).

**Updates**:
```
- The office.com enumeration module has been implemented and set to default for Managed realms.
- The ActiveSync enumeration and password spraying modules have been reimplemented in an attempt to 
  handle the recent updates from Microsoft that are causing invalid results. The ActiveSync enumeration
  module still returns some false positives - this is why the office.com enumeration module has been moved
  to the default process.
- When a Federated realm is identified, the user is prompted to switch enumeration to OneDrive (otherwise
  disabled due to invalid results from different modules) and to switch spraying to ADFS (otherwise sprays
  against the user selected spray-type).
```

> WARNING: ActiveSync user enumeration is performed by submitting a single authentication attempt per user. If ActiveSync enumeration is run with password spraying, the tool will automatically reset the lockout timer prior to the password spray -- if enumeration is run alone, the user should be aware of the authentication attempts and reset the lockout timer manually.

OneDrive user enumeration relies on the target user(s) to have previously logged into OneDrive. If a valid user has not yet used OneDrive, their account will show as 'invalid'. This appears to be a viable solution for user enumeration against federated realms.


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
                    [--enum-type {office,activesync,onedrive}]
                    [--spray-type {activesync,autodiscover,msol,adfs}]
                    [--adfs ADFS] [--rate RATE] [--safe SAFE] [--paired]
                    [--timeout TIMEOUT] [--proxy PROXY] [--output OUTPUT] [--debug]

Microsoft O365 User Enumerator and Password Sprayer -- v1.3.6

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
                        Number of password attempts to run before resetting lockout
                        timer. Default: 1

  -l LOCKOUT, --lockout LOCKOUT
                        Lockout policy reset time (in minutes). Default: 15 minutes

  --validate-type {openid-config,getuserrealm}
                        Specify which validation module to use. Default: getuserrealm

  --enum-type {office,activesync,onedrive}
                        Specify which enum module to use. Default: Office

  --spray-type {activesync,autodiscover,msol,adfs}
                        Specify which spray module to use. Default: ActiveSync

  --adfs ADFS           URL of target ADFS login page for spraying.

  --rate RATE           Number of concurrent connections during enum and spray.
                        Default: 10

  --safe SAFE           Terminate scan if `n` locked accounts are observed.
                        Default: 10

  --paired              Password spray pairing usernames and passwords (1:1).
  --timeout TIMEOUT     Request timeout. Default: 25
  --proxy PROXY         Proxy to pass traffic through: [http(s)://ip:port]
  --output OUTPUT       Output directory. Default: Current directory
  --debug               Debug output
```

### Modules

#### Validation
* openid-config
* getuserrealm

#### Enumeration
* office
* activesync
* onedrive
* autodiscover -- *No longer working - Removed*

#### Spraying
* activesync
* autodiscover
* msol
* adfs

## Acknowledgments

#### Office.com Code/References
* [@gremwell](https://github.com/gremwell)
* User enumeration via Office.com without authentication
    * [o365enum](https://github.com/gremwell/o365enum)

#### ActiveSync Code/References
* [@grimhacker](https://bitbucket.org/grimhacker)
* Research and discovery of original user enumeration via ActiveSync.
    * [office365userenum](https://bitbucket.org/grimhacker/office365userenum/src/master/)
    * See the original [blog post](https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/).

#### Autodiscover Code/References
* [@Raikia](https://github.com/Raikia)
* User enumeration via Autodiscover without authentication
    * [UhOh365](https://github.com/Raikia/UhOh365)

#### MSOL Code/References
* [@dafthack](https://github.com/dafthack)
* Password spray via MSOL
    * [MSOLSpray](https://github.com/dafthack/MSOLSpray)
    * *This was rewritten in Python by [@byt3bl33d3r](https://github.com/byt3bl33d3r)*
        * https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f

#### OneDrive Code/References
* [@nyxgeek](https://github.com/nyxgeek)
* User enumeration via One Drive
    * [onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum)
    * See the [blog post](https://www.trustedsec.com/blog/achieving-passive-user-enumeration-with-onedrive/) discussing this technique.

#### ADFS Code/References
* [@Mr-Un1k0d3r](https://github.com/Mr-Un1k0d3r)
* Password spray via ADFS
    * https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py

#### Other Code References
* [@byt3bl33d3r](https://github.com/byt3bl33d3r) --- [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit/)
* [@sensepost](https://github.com/sensepost) --- [Ruler](https://github.com/sensepost/ruler/)
