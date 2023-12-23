# tesla_api
Tesla API implementation in Python.

## Overview
* Implemets the 2024 interface including authentication and certificate handling
* It is a part of the [ElectronFluxBalancer](https://github.com/fabianhu/electron-flux-balancer) project
* Uses [Tesla Vehicle Commands](https://github.com/teslamotors/vehicle-command/) for signed commands.

## Installation
- include into your project as a library / submodule
- use ```bash
git submodule update --remote```
- For usage, please read the comments.
- maybe you have a look at the mess at [ElectronFluxBalancer](https://github.com/fabianhu/electron-flux-balancer) 
- you need to get and build tesla-control, see the readme in this subdirectory

## Registration Process
1. **Set up a third-party account at Tesla Developer**
   - Visit [Tesla Developer Portal](https://developer.tesla.com) to set up an account.

2. **Complete registration of your account**
    - Generate a public/private key pair for Tesla Vehicle Commands using the `secp256r1` curve:
        ```bash
        openssl ecparam -name prime256v1 -genkey -noout -out privatekey.pem
        ```
    - Extract the corresponding public key and save it in PEM format:
        ```bash
        openssl ec -in privatekey.pem -pubout -out publickey.pem
        ```
    - Host your public key in the `/.well-known` section of your website.
    - Store the public key at `https://your.domain/.well-known/appspecific/com.tesla.3p.public-key.pem`
    - Store both keys in the `TeslaKeys` directory

3. **Now within your python implementation**
    - Generate a partner authentication token:
        ```python
        partner_token = tesla_get_partner_auth_token(config.tesla_client_id, config.tesla_client_secret, AUDIENCE)
        ```
    - Make a POST call to `/api/1/partner_accounts` with your partner authentication token:
        ```python
        _r = tesla_register_partner_account(partner_token, config.tesla_redirect_domain) # is only needed once!
        print("account registration", _r)
        ```
    Now your partner registration should be completed.
    Check with: 
    ```python
    _r = tesla_partner_check_public_key(partner_token)
    ```

4. **Request authorization permissions from a customer**
    - Generate a third-party token on their behalf:
        ```python
        tesla_register_customer(myTesla) # register new customer (customer must log in and enter code here!)
        ```

5. **Customer must allow key on vehicle(s)**
    ```python
    tesla_register_customer_key()
    ```
   
## Use this library as a submodule
 Be aware, that in a submodule in default, any commit will not be to the main branch, if you do not check out main.
- Inside the library=submodule directory:
- to check out before commit: `git checkout main`
- to update: `git pull origin main`