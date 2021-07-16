# o365spray

> For educational, authorized and/or research purposes only.

o365spray a username enumeration and password spraying tool aimed at Microsoft Office 365 (O365). This tool reimplements a collection of enumeration and spray techniques researched and identified by those mentioned in [Acknowledgments](#Acknowledgments).

> WARNING: The ActiveSync and oAuth2 modules for user enumeration are performed by submitting a single authentication attempt per user. If either module is run in conjunction with password spraying in a single execution, o365spray will automatically reset the account lockout timer prior to performing the password spray -- if enumeration is run alone, the user should be aware of how many and when each authentication attempt was made and manually reset the lockout timer before performing any password spraying.

> If any bugs/errors are encountered, please open an Issue with the details (or a Pull Request with the proposed fix). See the [section below](#using-previous-versions) for more information about using previous versions.

## Usage

Validate a domain is using O365:<br>
`o365spray --validate --domain test.com`

Perform username enumeration against a given domain:<br>
`o365spray --enum -U usernames.txt --domain test.com`

Perform password spraying against a given domain:<br>
`o365spray --spray -U usernames.txt -P passwords.txt --count 2 --lockout 5 --domain test.com`

```
usage: o365spray [-h] [-d DOMAIN] [--validate] [--enum] [--spray]
                 [-u USERNAME] [-p PASSWORD] [-U USERFILE] [-P PASSFILE]
                 [--paired PAIRED] [-c COUNT] [-l LOCKOUT]
                 [--enum-module {office,activesync,onedrive,oauth2}]
                 [--spray-module {activesync,autodiscover,msol,adfs}]
                 [--adfs-url ADFS_URL] [--rate RATE] [--safe SAFE]
                 [--timeout TIMEOUT] [--proxy PROXY] [--output OUTPUT]
                 [-v] [--debug]

o365spray | Microsoft O365 User Enumerator and Password Sprayer -- v2.0.1

optional arguments:

  -h, --help            show this help message and exit

  -d DOMAIN, --domain DOMAIN
                        Target domain for validation, user enumeration, and/or
                        password spraying.

  --validate            Run domain validation only.

  --enum                Run username enumeration.

  --spray               Run password spraying.

  -u USERNAME, --username USERNAME
                        Username(s) delimited using commas.

  -p PASSWORD, --password PASSWORD
                        Password(s) delimited using commas.

  -U USERFILE, --userfile USERFILE
                        File containing list of usernames.

  -P PASSFILE, --passfile PASSFILE
                        File containing list of passwords.

  --paired PAIRED       File containing list of credentials in username:password
                        format.

  -c COUNT, --count COUNT
                        Number of password attempts to run per user before resetting
                        the lockout account timer. Default: 1

  -l LOCKOUT, --lockout LOCKOUT
                        Lockout policy's reset time (in minutes). Default: 15 minutes

  --enum-module {office,activesync,onedrive,oauth2}
                        Specify which enumeration module to run. Default: office

  --spray-module {activesync,autodiscover,msol,adfs}
                        Specify which password spraying module to run.
                        Default: activesync

  --adfs-url ADFS_URL   AuthURL of the target domain's ADFS login page for password
                        spraying.

  --sleep [-1, 0-120]   Throttle HTTP requests every `N` seconds. This can be
                        randomized by passing the value `-1` (between 1 sec and 2
                        mins). Default: 0

  --jitter [0-100]      Jitter extends --sleep period by percentage given (0-100).
                        Default: 0

  --rate RATE           Number of concurrent connections (attempts) during enumeration
                        and spraying. Default: 10

  --safe SAFE           Terminate password spraying run if `N` locked accounts are
                        observed. Default: 10

  --timeout TIMEOUT     HTTP request timeout in seconds. Default: 25

  --proxy PROXY         HTTP/S proxy to pass traffic through
                        (e.g. http://127.0.0.1:8080).

  --output OUTPUT       Output directory for results and test case files.
                        Default: current directory

  -v, --version         Print the tool version.

  --debug               Enable debug output.
```

## Modules

o365spray has been packaged to allow for use within automation scenarios. If domain validation, user enumeration, or password spraying is a part of your proposed attack/recon automation, see the below modules and import usage exmaples.

### Validation
* getuserrealm
* openid-config -- *Currently Disabled*

The validator can be imported and used via:
```python
from o365spray.core import Validator
v = Validator()
valid, adfs_url = v.validate('domain.com')
```

### Enumeration
* office
* activesync
* onedrive
  * This module relies on the target user(s) having previously logged into OneDrive. If a valid user has not yet used OneDrive, their account will show as 'invalid'.
* oauth2
* autodiscover -- *Currently Disabled*

The enumerator can be imported and used via:
```python
from o365spray.core import Enumerator
loop = asyncio.get_event_loop()
e = Enumerator(loop, writer=False)
loop.run_until_complete(
    e.run(
        userlist,
        password,
        domain,
        module,
    )
)
loop.run_until_complete()
loop.close()
list_of_valid_users = e.VALID_ACCOUNTS
```

### Spraying
* activesync
* autodiscover
* msol
* adfs

The sprayer can be imported and used via:
```python
from o365spray.core import Sprayer
loop = asyncio.get_event_loop()
s = Sprayer(loop, writer=False)
loop.run_until_complete(
    s.run(
        password,
        domain,
        module,
        userlist,
    )
)
loop.run_until_complete()
loop.close()
list_of_valid_creds = s.VALID_CREDENTIALS
```

## Omnispray

The o365spray framework has been ported to a new tool: [Omnispray](https://github.com/0xZDH/Omnispray). This tool is meant to modularize the original enumeration and spraying framework to allow for generic targeting, not just O365. Omnispray includes template modules for enumeration and spraying that can be modified and leveraged for any target.

## Acknowledgments

| Author | Tool/Research | Link |
| ---    | ---           | ---  |
| [gremwell](https://github.com/gremwell) | o365enum: User enumeration via [office.com](#) without authentication | [o365enum](https://github.com/gremwell/o365enum) |
| [grimhacker](https://bitbucket.org/grimhacker) | office365userenum: ActiveSync user enumeration research and discovery. | [office365userenum](https://bitbucket.org/grimhacker/office365userenum/src/master/) / [blog post](https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/) |
| [Raikia](https://github.com/Raikia) | UhOh365: User enumeration via Autodiscover without authentication. | [UhOh365](https://github.com/Raikia/UhOh365) |
| [dafthack](https://github.com/dafthack) | MSOLSpray: Password spraying via MSOL | [MSOLSpray](https://github.com/dafthack/MSOLSpray) |
| [byt3bl33d3r](https://github.com/byt3bl33d3r) | MSOLSpray: Python reimplementation | [Gist](https://gist.github.com/byt3bl33d3r/19a48fff8fdc34cc1dd1f1d2807e1b7f) |
| [nyxgeek](https://github.com/nyxgeek) | onedrive_user_enum: OneDrive user enumeration | [onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum) / [blog post](https://www.trustedsec.com/blog/achieving-passive-user-enumeration-with-onedrive/) |
| [Mr-Un1k0d3r](https://github.com/Mr-Un1k0d3r) | adfs-spray: ADFS password spraying | [adfs-spray](https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py) |
| [Nestori Syynimaa](https://github.com/NestoriSyynimaa) | AADInternals: oAuth2 user enumeration | [AADInternals](https://github.com/Gerenios/AADInternals) |
| [byt3bl33d3r](https://github.com/byt3bl33d3r) | SprayingToolkit: Code references | [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit/) |
| [sensepost](https://github.com/sensepost) | ruler: Code references | [Ruler](https://github.com/sensepost/ruler/) |

## Using Previous Versions

o365spray was recently rewritten (v2) and could have some hidden bugs remaining. If issues are encountered, try checking out the commit prior to the code rewrite (`v1.3.7`):

```
git checkout e235abdcebad61dbd2cde80974aca21ddb188704
```
