# CHANGELOG

## v2.0.1 (15/07/2021)
- Add oAuth2 user enumeration module based on [AADInternals](https://github.com/Gerenios/AADInternals)

## v2.0.0 (12/06/2021)
- Convert tool to package for PyPi deployment
- Add LICENSE
- Add CHANGELOG
- Code redesign for Python 3
- Code reformatting via `black`

## Previous Updates
- The office.com enumeration module has been implemented and set to default for Managed realms.
- The ActiveSync enumeration and password spraying modules have been reimplemented in an attempt to handle the recent updates from Microsoft that are causing invalid results. The ActiveSync enumeration module still returns some false positives - this is why the office.com enumeration module has been moved to the default process.
- When a Federated realm is identified, the user is prompted to switch enumeration to OneDrive (otherwise disabled due to invalid results from different modules) and to switch spraying to ADFS (otherwise sprays against the user selected spray-type).