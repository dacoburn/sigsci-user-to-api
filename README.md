# sigsci-user-to-api

## Description

Simple script that allows you to convert a user to an API user or back to a normal user.

## Usage

python  sigsci-user-to-api --config conf.json [--user USER@DOMAIN.COM | --userFile /path/to/file.txt] --api True

## Conf File Settings

**Commond Line Settings**

| CLI Flag | Description |
|----------|-------------|
| --config | Path to the config file, often called config.json |
| --user   | Specifies a singler user, can not be used with `--userFile` |
| --userFile | Specifies the path to the text file with one e-mail per line for users. Cannot be used with `--user` |
| --api    | Case sensitive setting that can be `True` or `False`. True means conver the user(s) to API mode, `False` means make them regular users |

**Config File Settings**

| Key Name | Description |
|----------|-------------|
| email    | This is the e-mail of your Signal Sciences user |
| password | This is the password of your Signal Sciences user. If this is not provided you will need to use the API Token |
| apitoken | If this is provided it will be used INSTEAD of your password. If set you can leave password empty |
| corp_name | This is the API name of your corp. You can find it in one of the dashboard URLS |


## Finding your Signal Sciences API Info

**CORP Name & Site Name**
You can find your Corp API Name and Site API Name in the dashboard URL. The `EXAMPLECORPNAME` would be the api name of your corp and and the `EXAMPLESITENAME` would be the api name of your site.

https://dashboard.signalsciences.net/corps/EXAMPLECORPNAME/sites/EXAMPLESITENAME/

So lets say my corp API name is `foocorp` and my Dashboard Site API Name is `barsite` then the URL woudl look like:

https://dashboard.signalsciences.net/corps/foocorp/sites/barsite/

**API Tokens**

Information on getting your API Token can be found at https://docs.signalsciences.net/using-signal-sciences/using-our-api/

