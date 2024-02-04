# tesla_api
* Tesla 2024 API implementation in Python.
* This is a library.
* See the example implementation in [tesla_api_example](https://github.com/fabianhu/tesla_api_example)

## Overview
* Implements the 2024 interface including authentication and token handling
* It is a part of the [ElectronFluxBalancer](https://github.com/fabianhu/electron-flux-balancer) project
* Supports developer account registration
* Supports customer registration and key install on car
* Gets vehicle data as python structures
* Uses [Tesla Vehicle Commands](https://github.com/teslamotors/vehicle-command/) for signed commands.

## Installation
- include into your project as a library / git submodule in `lib/tesla_api/`
- use ```bash
git submodule update --remote``` to update
- For best usage, please read the comments in the main file `tesla_api_2024.py` at the beginning and at the end of the file.
- Example implementation in [tesla_api_example](https://github.com/fabianhu/tesla_api_example)
- Maybe you have a look at the implementation at [ElectronFluxBalancer](https://github.com/fabianhu/electron-flux-balancer)
- For sending commands, you need to get and build [tesla-control](https://github.com/teslamotors/vehicle-command/), see below and the readme in the subdirectory `tesla-control`

## Registration Process
1. **Set up a third-party account at Tesla Developer**
   - Visit [Tesla Developer Portal](https://developer.tesla.com) to set up an account.
   - Read the registration process [there](https://developer.tesla.com/docs/fleet-api)!

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
        import config
        _r = tesla_register_partner_account(partner_token, config.tesla_audience) # call once per audience you want to register for.
        print("account registration", _r)
        ```
    Now your partner registration should be completed.
    Check with: 
        ```python
        _r = tesla_partner_check_public_key(partner_token, audience)
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
    
## For sending commands, build the vehicle-command Go module
1. Install Go environment on your PC
2. Download [Tesla Vehicle Commands](https://github.com/teslamotors/vehicle-command/) source
3. Read the [build instructions there](https://github.com/teslamotors/vehicle-command/#installation-and-configuration)
4. In the downloaded directory go to
   ```bash
   cd vehicle-command/cmd/tesla-control/
   ```
5. Build for PC (testing)
   ```bash
   go build .
   ```
6. Cross-compile for Raspberry Pi 3 on the PC
   ```bash
   env GOOS=linux GOARCH=arm GOARM=7
   go build .
   ```
   This generates an elf file `tesla_control`, which can be directly executed on the Pi3.
7. put this file into the lib/tesla_api/vehicle_command/ directory of your project on the Pi.

   
## Use this library as a submodule
 Be aware, that in a git submodule in default, any commit will not be to the main branch, if you do not check out main.
- Inside the library=submodule directory:
- to check out before commit: `git checkout main`
- to update: `git pull origin main`
