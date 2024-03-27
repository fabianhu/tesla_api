"""
Tesla Fleet API - mandatory from 2024.

https://github.com/fabianhu/tesla_api

This library expects to be in the location lib/tesla_api/ in your project.
See it running in https://github.com/fabianhu/electron-flux-balancer

"""

import http.client
import json
import logging
import subprocess
import requests
import datetime
import webbrowser
import secrets
from urllib.parse import urlencode

#own lib and modules

from lib.logger import Logger # own logger
logger = Logger(logging.INFO, "tesla.log")

import config  # a file config.py in the base directory, which contains all the variables config.xxx as follows:
'''
# content of config.py:
tesla_vin = 'LRWYAAAAAAA135456'
tesla_client_id = "aaaaaaaaaaaa-bbbb-cccc-ddddddddddd"
tesla_client_secret = "ta-secret.aaaaaaaaaaaaaaaa"  # only needed during registration, so does not ever need to be on the Pi!
# put your key pair here:
#lib/tesla_api/TeslaKeys/privatekey.pem
#lib/tesla_api/TeslaKeys/publickey.pem
# and store the pubkey at: https://your.domain/.well-known/appspecific/com.tesla.3p.public-key.pem
tesla_redirect_domain = "your.domain"  # NO https:// !!!
tesla_redirect_uri = "https://your.domain/and/stuff/"  # start with https:// and include a tailing '/'!
tesla_audience = "fleet-api.prd.eu.vn.cloud.tesla.com" # Europe
#tesla_audience =  "fleet-api.prd.na.vn.cloud.tesla.com" # North America
tesla_scopes = "user_data vehicle_device_data vehicle_cmds vehicle_charging_cmds energy_device_data energy_cmds"  # match with your application access request
'''

CLIENT_ID = config.tesla_client_id  # this is the developer account, not the customer !!
CLIENT_SECRET = config.tesla_client_secret # this is the developer account, not the customer !!
AUDIENCE = config.tesla_audience

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
        self.audience = config.tesla_audience  # the audience for this customer

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
            logger.error(f"The file {self.token_file} was not found.")
            return
        except json.JSONDecodeError:
            logger.error(f"There was an issue decoding JSON in {self.token_file}.")
            return
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
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

        if self.token_expires_at < threshold_time:
            logger.debug(f"Token expires at {self.token_expires_at} - will refresh")
            token_url = "https://auth.tesla.com/oauth2/v3/token"
            payload = {
                'grant_type': 'refresh_token',
                'client_id': self.client_id,
                'refresh_token': self.refresh_token,
                'audience': self.audience
            }
            response = requests.post(token_url, data=payload)
            if response is None:
                logger.error(f"Token refresh response was returned empty.")
                return
            if response.status_code != 200:
                logger.error(f"Token refresh failed: {response.status_code}, {response.text}")
                return

            token_data = response.json()

            token_data["expiry_time"] = (datetime.datetime.now() + datetime.timedelta(seconds=token_data.get('expires_in'))).isoformat()
            self.token_expires_at = datetime.datetime.fromisoformat(token_data.get('expiry_time'))
            self.access_token = token_data.get('access_token')
            self.refresh_token = token_data.get('refresh_token')
            # Saving tokens to a file
            with open(self.token_file, "w") as file:
                json.dump(token_data, file, indent=4)
            #logger.debug("Token refreshed")
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
        payload = {
            'grant_type': 'authorization_code',  # works 200 and delivers 2 tokens!
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'redirect_uri': config.tesla_redirect_uri,
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
        # remark: this might start a charge immediately!
        return self.tesla_command("charging-schedule-cancel", _vin)

    def cmd_charge_set_amps(self, _vin, _amps):
        return self.tesla_command(f"charging-set-amps {int(_amps)}", _vin)


    def tesla_command(self, command_string, _vin):
        """
        Interface to the tesla-control CLI tool. Used here due to missing native implementation.
        Doc is available now - works as it is for the moment.
        https://github.com/teslamotors/vehicle-command/blob/main/pkg/protocol/protocol.md

        *** See build instructions in tesla-control directory!

        Concept: we spit out the token and the key into files, invoke the CLI and off we go.

        '''
        :param _vin: the VIN
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
        logger.debug(f"Send secure Command: {command_string}")

        # spit out the actual token
        tokenfile = ".temp_token"
        with open(".temp_token", 'w') as file:
            file.write(self.access_token)

        # call the command externally
        cmd = f'./lib/tesla_api/tesla-control/tesla-control -key-file ./lib/tesla_api/TeslaKeys/privatekey.pem -token-file {tokenfile} -vin {_vin} {command_string}'

        logger.debug(f"Command: {cmd}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True)

        if result.stderr:
            logger.error(f"Tesla command '{command_string}' result({result.returncode}):\n{result.stdout}{result.stderr}")
            return False
        if result.returncode != 0:
            logger.error(f"Tesla command '{command_string}' result({result.returncode}):\n{result.stdout}")
            return False
        logger.debug(f"Command output: {result.stdout}")
        return True


def tesla_generic_request(_audience, _target_url, _access_token, _payload=''):
    """
    Get data from car
    :param _audience: the audience
    :param _target_url: target url according specification
    :param _access_token: a valid access token
    :param _payload: the question you ask
    :return: dictionary with requested data
    """
    if _access_token is None:
        return None

    conn = None
    try:
        conn = http.client.HTTPSConnection(_audience)
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {_access_token}'
        }
        logger.debug(f"Tesla request, {_target_url}")

        conn.request("GET", _target_url, _payload, headers)
        res = conn.getresponse()

        if res.status == 301:
            location_header = dict(res.getheaders()).get('Location') or dict(res.getheaders()).get('location')

            if location_header:
                new_location = location_header
                logger.debug(f"Redirecting to: {new_location}")
                conn.close()
                return tesla_generic_request(_audience, new_location, _access_token, _payload)

        data = res.read()
        datastring = data.decode('utf-8')
        logger.debug(f"Result: {res.status}, {res.reason}, {datastring}")

        if res.status == 200:
            json_data = json.loads(datastring)['response']
        else:
            json_data = None

    except http.client.HTTPException as e:
        logger.error(f"HTTPException occurred: {e}")
        json_data = None
    except json.JSONDecodeError as e:
        logger.error(f"JSONDecodeError occurred: {e}")
        json_data = None
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        json_data = None
    finally:
        if conn:
            conn.close()

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
    if _access_token is None:
        logger.error("No Token specified!")
        return None
    logger.debug(f"Tesla Command url: {_target_url}")
    conn = http.client.HTTPSConnection(_audience)
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {_access_token}'
    }
    conn.request("POST", _target_url, _payload, headers)
    res = conn.getresponse()
    data = res.read()
    data_string = data.decode("utf-8")
    logger.debug("response status: " + str(res.status) + ", " + res.reason + ", "+ data_string)

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
        "scope": "openid offline_access " + config.tesla_scopes,  # the openid and offline_access is necessary for the partner token and for refreshing tokens without re-login of the user!
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
        logger.error(f"Partner auth token request error {response.status_code}, {response.text}")
        return None


def tesla_register_partner_account(_partner_token, _audience):
    """
    Call in an interactive session!
    Do one call once, to verify your domain you entered during registration. API will not work, if not done.

    :param _partner_token: your partner token you got from tesla_get_partner_auth_token()
    :param _audience: The audience (server) to register the partner token for
    :return:
    """
    payload = json.dumps({
        "domain": config.tesla_redirect_domain
    })
    target = "/api/1/partner_accounts"
    rv = tesla_generic_command(_audience,target,_partner_token,payload)
    print("return value register partner account: " + str(rv))
    return rv


def tesla_register_customer(myTesla: TeslaAPI):
    """
    Call in an interactive session!
    Call for every customer, this assigns your app to your customers account.
    This acquires the first token(s) to communicate with the account and to access data from the car.
    :param myTesla: my Tesla instance, as we are doing the key exchange here
    :return:
    """
    random_state = secrets.token_hex(16)
    urlscopes = "openid%20offline_access%20" + config.tesla_scopes.replace(' ','%20')
    url = f"https://auth.tesla.com/oauth2/v3/authorize?&client_id={myTesla.client_id}&locale=en-US&prompt=login&redirect_uri={config.tesla_redirect_uri}&response_type=code&scope={urlscopes}&state={random_state}"
    webbrowser.open(url)
    print(f"web-browser opened with URL:\n{url}\n complete registration and watch, if the following random number is not disturbed in the response.")
    print(random_state)
    print("Next step is to exchange the Code for tokens.\n You find the code in the URL, the tesla server redirects you to.\n The page likely shows a 400 Bad Request, this is normal")
    print("The code can be found between &code and &state in the url")
    user_input_code = input("Please enter the 'code' from the URL: ")
    myTesla.exchange_code_for_tokens(myTesla.client_id, CLIENT_SECRET, user_input_code)
    print("So, now we should have the access tokens saved. Your customer account is registered.")


def tesla_register_customer_key():
    """
    (only displays a QR code or link to be opened on the phone with the Tesla app installed)
    Register the public key of the partner to the car, so that the car can be controlled by the app.
    This requires that the customer has already been registered by tesla_register_customer()
    The QR/link is to be opened on the phone, where the Tesla app is installed.
    Installs the key to the car to enable end-to-end encrypted commands.
    :return:
    """
    url=f"https://tesla.com/_ak/{config.tesla_redirect_domain}"
    print(f"Please open the following URL on your phone with the Tesla app installed:\n{url}")

    try:
        import qrcode
    except ImportError:
        print("qr module not found, to install run: pip3 install qrcode")
        return

    # now we create a QR code for the URL
    import os
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    # qc=qr.print_ascii(invert=True)
    # Create an image from the QR code instance
    img = qr.make_image(fill_color="black", back_color="white")

    # Save the image to /tmp directory
    file_path = 'registerkey.png'
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
    return tesla_generic_request(config.tesla_audience, target, _token)


def tesla_partner_check_public_key(_partner_token, _audience):
    """
    Check, if the partner token is successfully registered with the audience
    :param _partner_token: the partner token
    :param _audience: the audience
    :return:
    """
    payload = json.dumps({
        "domain": config.tesla_redirect_domain
    })
    target = '/api/1/partner_accounts/public_key'
    return tesla_generic_request(_audience, target, _partner_token, payload)


# test stuff, if run directly (only on PC!)
if __name__ == '__main__':

    import os

    os.chdir("../../")  # hop to the correct directory, as if called as lib/tesla_api/...

    myT = TeslaAPI()

    # first run: go to the function tesla_register_process() and follow the comments.
    print("First run: go to https://github.com/fabianhu/tesla_api_example for an example project.")


    #r = tesla_get_region(myT.access_token) # 403 for user access token
    #print("region", r)

    r = myT.get_vehicles_list()
    print("vehicle list", r)

    vin = r[0]['vin']

    r = myT.get_vehicle(vin) # VIN or ID from list

    print(f"Your vehicle is on API version {r['api_version']}.")

    print("vehicle info", r)

    if r['state'] == 'asleep':
        print("ZZZzz")
        #myT.cmd_wakeup(config.tesla_vin)
    else:
        # r = tesla_get_vehicle_data(access_token, config.tesla_vin, 'charge_state;location_data') # requests LIVE data only -> 408 if asleep!
        # r = tesla_get_vehicle_data(access_token, config.tesla_vin, 'charge_state')  # requests LIVE data only -> 408 if asleep!
        # r = tesla_get_vehicle_data(access_token, config.tesla_vin, 'charge_state;climate_state;closures_state;drive_state;gui_settings;location_data;vehicle_config;vehicle_state;vehicle_data_combo') # requests LIVE data only -> 408 if asleep!
        r = myT.get_vehicle_data(vin, 'charge_state;drive_state;location_data;vehicle_state')  # requests LIVE data only -> 408 if asleep!
        print(r)

    ## here some command examples to test around
    #myT.tesla_command("wake")
    #myT.tesla_command("ping") # missing scope for security

    #myT.tesla_command("charging-set-amps 5")
    #myT.tesla_command("charging-start")
    #myT.tesla_command("charging-stop")
    #myT.tesla_command("charging-schedule 30")
    #myT.tesla_command("charging-schedule-cancel")


