"""
Tesla Fleet API - mandatory from 2024.
"""

import http.client
import json
import logging
import os
import requests
import datetime
import webbrowser
import secrets
from urllib.parse import urlencode

#own lib and modules
import config
from lib.logger import Logger
logger = Logger(logging.DEBUG, "tesla.log")


CLIENT_ID = config.tesla_client_id  # this is the developer account, not the customer !!
CLIENT_SECRET = config.tesla_client_secret # this is the developer account, not the customer !!
AUDIENCE = "fleet-api.prd.eu.vn.cloud.tesla.com" # Europe
#AUDIENCE = "fleet-api.prd.na.vn.cloud.tesla.com" # North America

class TeslaAPI:
    def __init__(self, _tesla_account_name: str = "tesla"):
        """
        :param _tesla_account_name: just an account name for storing the cached tokens for this account
        """
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at : datetime = datetime.datetime.now()
        self.token_file = _tesla_account_name+"_tokens.json"
        self.client_id = CLIENT_ID
        self.audience = AUDIENCE

        self.tokens_load()  # load the stored tokens and refresh, if necessary


    def tokens_load(self):
        """
        Load tokens from file.
        :return:
        """
        try:
            # Loading tokens from the file
            with open(self.token_file, "r") as file:
                loaded_tokens = json.load(file)

        except FileNotFoundError:
            print(f"Error: The file {self.token_file} was not found.")
            return
        except json.JSONDecodeError:
            print(f"Error: There was an issue decoding JSON in {self.token_file}.")
            return
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return

        # Accessing the loaded tokens
        self.access_token = loaded_tokens["access_token"]
        self.refresh_token = loaded_tokens["refresh_token"]
        self.token_expires_at = datetime.datetime.fromisoformat(loaded_tokens["expiry_time"])

        self.tokens_refresh() # re-aquires, if necessary


    def tokens_refresh(self):
        """
        Refresh tokens (using the refresh token)
        :return:
        """
        threshold_minutes = 5
        threshold_time = datetime.datetime.now() + datetime.timedelta(minutes=threshold_minutes)
        print(f"{self.token_expires_at}")
        if self.token_expires_at < threshold_time:
            token_url = "https://auth.tesla.com/oauth2/v3/token"
            payload = {
                'grant_type': 'refresh_token',
                'client_id': self.client_id,
                'refresh_token': self.refresh_token,
                'audience': self.audience
            }
            response = requests.post(token_url, data=payload)

            token_data = response.json()
            token_data["expiry_time"] = (datetime.datetime.now() + datetime.timedelta(seconds=token_data.get('expires_in'))).isoformat()
            self.token_expires_at = datetime.datetime.fromisoformat(token_data.get('expiry_time'))
            self.access_token = token_data.get('access_token')
            self.refresh_token = token_data.get('refresh_token')
            # Saving tokens to a file
            with open(self.token_file, "w") as file:
                json.dump(token_data, file, indent=4)
            #print("Token refreshed")
        else:
            # no need to refresh
            pass


    def exchange_code_for_tokens(self, client_id, client_secret, code):
        """
        During registration the customer receives a code, which has to be exchanged for the first pair of tokens.
        This is ONLY needed during registration once. The code is invalid after registration.
        :param client_id: the client ID (from Tesla developer page)
        :param client_secret: the client secret (from Tesla developer page)
        :param code: the code, which was returned to the recirect uri
        :return:
        """
        token_url = "https://auth.tesla.com/oauth2/v3/token"
        redirect_uri = config.tesla_redirect_uri
        payload = {
            'grant_type': 'authorization_code',  # works 200 and delivers 2 tokens!
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'audience': self.audience
        }
        response = requests.post(token_url, data=payload)
        token_data = response.json()
        expiry_time = datetime.datetime.now() + datetime.timedelta(seconds=token_data.get('expires_in'))
        token_data["expiry_time"] = expiry_time.isoformat()

        self.token_expires_at = expiry_time
        self.access_token = token_data.get('access_token')
        self.refresh_token = token_data.get('refresh_token')
        # Saving tokens to a file
        with open(self.token_file, "w") as file:
            json.dump(token_data, file, indent=4)


    def generic_request(self, target):
        self.tokens_refresh()
        return tesla_generic_request(self.audience, target, self.access_token)


    def get_vehicles_list(self):
        """
        List all vehicles
        :return: Dictionary of all vehicles with basic info
        """
        target = "/api/1/vehicles"
        return self.generic_request(target)


    def get_vehicle(self, _vin):
        """
        Get basic info for a specific vehicle
        :param _vin: the VIN of the vehicle (can also be the index from the prev. list.
        :return:
        """
        target = f'/api/1/vehicles/{_vin}'
        return self.generic_request(target)


    def get_vehicle_data(self, _vin, endpoints=''):
        """
        Get all vehicle data from specified endpoint list.
        :param _vin: the VIN of the vehicle (can also be the index from the prev. list.
        :param endpoints: String of endpoints, separated by semicolons;
        :return: dictionary of car data or none if car is asleep (status 408)
        """
        target = f'/api/1/vehicles/{_vin}/vehicle_data'
        if endpoints:
            endpoints = urlencode({'endpoints': endpoints})
            target += f'?{endpoints}'
        return self.generic_request(target)

    def cmd_wakeup(self, _vin):
        return self.tesla_command("wake",_vin)

    def cmd_charge_start(self, _vin):
        return self.tesla_command("charging-start", _vin)

    def cmd_charge_stop(self, _vin):
        return self.tesla_command("charging-stop", _vin)

    def cmd_charge_set_limit(self, _vin, _prc):
        return self.tesla_command(f"charging-set-limit {int(_prc)}", _vin)

    def cmd_charge_set_schedule(self, _vin, _mins):
        return self.tesla_command(f"charging-schedule {int(_mins)}", _vin)

    def cmd_charge_cancel_schedule(self, _vin):
        return self.tesla_command("charging-schedule-cancel", _vin)

    def cmd_charge_set_amps(self, _vin, _amps):
        return self.tesla_command(f"charging-set-amps {int(_amps)}", _vin)


    ''' 
    # fixme documentation is missing for a native implementation
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    
    def cmd_send_signed_command(self, _vin, _cryptostring):
        target = f"/api/1/vehicles/{_vin}/signed_command"
        payload = json.dumps({
            "routable_message": _cryptostring
        })
        return tesla_generic_command(self.audience, target, self.access_token, payload)
        
    
        public_key = json_data.get('public_key')
        public_key_bytes = bytes.fromhex(public_key)
    
        # Create an Elliptic Curve public key object
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)
    
        # Convert to PEM format
        pem_format = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
        # Print the PEM format
        print("PEM format:\n", pem_format.decode())
        
        '''


    def tesla_command(self, command_string, vin = config.tesla_vin):
        """
        Interface to the tesla-control CLI tool. Used here due to missing documentation for a native implementation.
        See instructions in tesla-control directory!
        Concept: we spit out the token and the key into files, invoke the CLI and off we go.

        '''
        :param vin: the VIN
        :param command_string: the command
        A selection of available COMMANDs , see tesla-control -h
        charge-port-close      Close charge port
        charge-port-open       Open charge port
        charging-schedule MINS Schedule charging to MINS minutes after midnight and enable daily scheduling
        charging-schedule-cancel Cancel scheduled charge start - will start charging when connected.
        charging-set-amps      Set charge current to AMPS
        charging-set-limit     Set charge limit to PERCENT
        charging-start         Start charging
        charging-stop          Stop charging
        product-info           Print JSON product info
        wake                   Wake up vehicle
        """
        logger.debug(f"Secure Command: {command_string}")

        # spit out the actual token
        tokenfile = ".temp_token"
        with open(".temp_token", 'w') as file:
            file.write(self.access_token)

        '''        import base64
        decoded_bytes = base64.b64decode(self.access_token)
        #decoded_string = decoded_bytes.decode('utf-8')
        print(decoded_bytes)'''

        # call the command externally
        import os
        cmd = f'./lib/tesla/tesla-control/tesla-control -key-file ./lib/tesla/TeslaKeys/privatekey.pem -token-file {tokenfile} -vin {vin} {command_string}'
        #cmd = f'./tesla-control/tesla-control -debug -key-file ./TeslaKeys/privatekey.pem -token-file {tokenfile} -vin {vin} {command_string}'

        logger.debug(f"Command:\n{cmd}")

        out = os.popen(cmd).read()
        logger.debug(f"Command output:\n{out}")
        if out.startswith("Error:"):
            logger.error(f"Tesla command '{command_string}' error -> {out}")
            return False
        elif out == '':
            # we assume everything went great, as no news is good news.
            return True
        else:
            logger.error(f"Tesla command '{command_string}' result -> {out}")
            return False



def tesla_generic_request(_audience, _target_url, _access_token, _payload =''):
    """
    get data from car
    :param _audience: the audience
    :param _target_url: target url according specification
    :param _access_token: a valid access token
    :param _payload: the question you ask
    :return: dictionary with requested data
    """
    if _access_token is None: return None
    conn = http.client.HTTPSConnection(_audience)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {_access_token}'
    }
    logger.debug(f"Tesla request, {_target_url}")

    conn.request("GET", _target_url, _payload, headers)
    res = conn.getresponse()

    if res.status == 301:
        # Check if 'Location' header is present in the list of tuples
        location_header = dict(res.getheaders()).get('Location') or dict(res.getheaders()).get('location')

        if location_header:
            # Handle redirect
            new_location = location_header
            logger.debug(f"Redirecting to: {new_location}")
            conn.close()
            return tesla_generic_request(_audience, new_location, _access_token, _payload)

    data = res.read()
    datastring = data.decode('utf-8')
    logger.debug(f"Result: {res.status}, {res.reason}, {datastring}")
    conn.close()

    if res.status == 200:
        json_data = json.loads(datastring)['response']
    else:
        json_data = None

    return json_data




def tesla_generic_command(_audience, _target_url, _access_token, _payload =''):
    """
    send a generic command
    :param _audience:
    :param _target_url:
    :param _access_token:
    :param _payload:
    :return:
    """
    if _access_token is None: return None
    print("Tesla Command:", _target_url)
    conn = http.client.HTTPSConnection(_audience)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {_access_token}'
    }
    conn.request("POST", _target_url, _payload, headers)
    res = conn.getresponse()
    data = res.read()
    data_string = data.decode("utf-8")

    if res.status == 200:
        json_data = json.loads(data_string)['response']
    else:
        json_data = None

    return json_data



def tesla_get_partner_auth_token(client_id, client_secret, audience_list):
    """
    Get a special access token for the partner role, which is used to register the customer.
    :param client_id:
    :param client_secret:
    :param audience_list: list in one string, separated by semicolon
    :return:
    """
    # Prepare the data for the POST request
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "openid vehicle_device_data vehicle_cmds vehicle_charging_cmds",
        #"scope": "vehicle_device_data vehicle_charging_cmds",
        "audience": f"https://{audience_list}",
    }
    # Make the POST request to obtain the authentication token
    url = "https://auth.tesla.com/oauth2/v3/token"
    response = requests.post(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    # Check if the request was successful
    if response.status_code == 200:
        token_data = response.json()
        return token_data.get("access_token")
    else:
        print("Error:", response.status_code, response.text)
        return None


def tesla_register_partner_account(_partner_token, _domain):
    """
    Do one call once, to verify your domain you entered during registration. API will not work, if not done.
    :param _partner_token: your partner token you got from tesla_get_partner_auth_token()
    :param _domain: The domain for this endpoint must match the root domain from the allowed_origins on developer.tesla.com. Include a tailing '/'!
    :return:
    """
    payload = json.dumps({
        "domain": _domain
    })
    target = "/api/1/partner_accounts"
    rv = tesla_generic_command(AUDIENCE,target,_partner_token,payload)
    print(rv)
    return rv


def tesla_register_customer(myTesla: TeslaAPI):
    """
    Call for every customer, this assigns your app to your customers account.
    This acquires the token(s) to communicate with the account and to access data from the car.
    :param myTesla: my Tesla instance, as we are doing the key exchange here
    :return:
    """
    REDIRECT_URI = config.tesla_redirect_uri
    random_state = secrets.token_hex(16)
    url = f"https://auth.tesla.com/oauth2/v3/authorize?&client_id={myTesla.client_id}&locale=de-DE&prompt=login&redirect_uri={REDIRECT_URI}&response_type=code&scope=vehicle_device_data%20offline_access%20vehicle_charging_cmds&state={random_state}"
    webbrowser.open(url)
    print(f"web-browser opened with URL:\n{url}\n complete registration and watch, if the following random number is not disturbed in the response.")
    print(random_state)
    print("Next step is to exchange the Code for tokens.")
    user_input_code = input("Please enter the code: ")
    myTesla.exchange_code_for_tokens(myTesla.client_id, CLIENT_SECRET, user_input_code)
    print("So, now we should have the access tokens saved. Your account is registered.")


def tesla_register_customer_key():
    """
    Register the public key of the partner to the car, so that the car can be controlled by the app.
    Installs the key to the car.
    :return:
    """
    url=f"https://tesla.com/_ak/{config.tesla_redirect_domain}"
    import qrcode
    import os

    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    qc=qr.print_ascii(invert=True)
    print(f"visit url:{url}")
    print(qc)

    # Create an image from the QR code instance
    img = qr.make_image(fill_color="black", back_color="white")

    # Save the image to /tmp directory
    file_path = '/tmp/registerkey.png'
    img.save(file_path)

    # Display the QR code using the default image viewer or web browser
    if os.name == 'nt':  # For Windows
        os.startfile(file_path)
    elif os.name == 'posix':  # For macOS and Linux
        os.system(f'xdg-open {file_path}')
    else:
        print("Operating system not supported for automatic image display.")


def tesla_get_region(_token):
    """
    Get the region of a user token
    :param _token:
    :return: Answer from server
    """
    target = '/api/1/users/region'
    return tesla_generic_request(AUDIENCE, target, _token)


def tesla_partner_check_public_key(_partner_token):
    """
    Check, if the partner token is successfully registered with tesla
    :param _partner_token:
    :return:
    """
    target = '/api/1/partner_accounts/public_key'
    return tesla_generic_request(AUDIENCE, target, _partner_token)


def tesla_register_process():

    # ATTENTION!!
    # read comments first

    if not __debug__:
        print("single-step this in debug, do not just run it!")
        return

    # registration process:
    # 1: Set up a third-party account at https://developer.tesla.com.

    # 2: Complete registration of your account

    # 2a: Generate a public/private key pair for Tesla Vehicle Commands.
    # Generate a private key using the secp256r1 curve
    #openssl ecparam -name prime256v1 -genkey -noout -out privatekey.pem

    # Extract the corresponding public key and save it in PEM format
    #openssl ec -in privatekey.pem -pubout -out publickey.pem

    # 2b: Host your public key in the /.well-known section of your website.
    #store the pubkey at: https://your.domain/.well-known/appspecific/com.tesla.3p.public-key.pem
    #and store into TeslaKeys directory

    # 2b: Generate a partner authentication token.
    partner_token = tesla_get_partner_auth_token(CLIENT_ID, CLIENT_SECRET, AUDIENCE)
    # 2c: Make a POST call to /api/1/partner_accounts with your partner authentication token.
    _r = tesla_register_partner_account(partner_token, config.tesla_redirect_domain) # is only needed once!
    print("account registration", _r)
    # 3: Request authorization permissions from a customer and generate a third-party token on their behalf.
    tesla_register_customer(myT) # register new customer (customer must log in and enter code here!)

    # 4: Customer must allow key on vehicle(s)
    tesla_register_customer_key()

    _r = tesla_partner_check_public_key(partner_token) # results in redirect and 404 for EU !!!
    print("registration", _r)


# test stuff, if run directly (PC!)
if __name__ == '__main__':

    os.chdir("../../")

    myT = TeslaAPI()
    #myT.tesla_command("wake")
    #myT.tesla_command("ping") # missing scope for security

    myT.tesla_command("charging-set-amps 5")
    #myT.tesla_command("charging-start")
    #myT.tesla_command("charging-stop")
    #myT.tesla_command("charging-schedule 30")
    #myT.tesla_command("charging-schedule-cancel")

    r = myT.get_vehicle_data(config.tesla_vin, 'charge_state;drive_state;location_data;vehicle_state')  # requests LIVE data only -> 408 if asleep!
    print(r)

    #r = tesla_get_region(myT.access_token) # 403 for user access token
    #print("region", r)
    r = myT.get_vehicles_list()
    print("vehicle list", r)
    r = myT.get_vehicle(config.tesla_vin) # VIN or ID from list
    if r['api_version'] != 69:
        print("Wrong API version")
    print("vehicle", r)

    if r['state'] == 'asleep':
        print("ZZZzz")
        #myT.cmd_wakeup(config.tesla_vin) # yesssss
    else:
        # r = tesla_get_vehicle_data(access_token, config.tesla_vin, 'charge_state;location_data') # requests LIVE data only -> 408 if asleep!
        # r = tesla_get_vehicle_data(access_token, config.tesla_vin, 'charge_state')  # requests LIVE data only -> 408 if asleep!
        # r = tesla_get_vehicle_data(access_token, config.tesla_vin, 'charge_state;climate_state;closures_state;drive_state;gui_settings;location_data;vehicle_config;vehicle_state;vehicle_data_combo') # requests LIVE data only -> 408 if asleep!
        r = myT.get_vehicle_data(config.tesla_vin, 'charge_state;drive_state;location_data;vehicle_state')  # requests LIVE data only -> 408 if asleep!
        print(r)


