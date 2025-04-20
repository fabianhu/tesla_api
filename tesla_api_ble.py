"""
Tesla Fleet API - mandatory from 2024.

https://github.com/fabianhu/tesla_api

This library expects to be in the location lib/tesla_api/ in your project.
See it running in https://github.com/fabianhu/electron-flux-balancer

https://edotor.net/?engine=dot#%0Adigraph%20%7B%0A%0Asubgraph%20cluster_connection%20%7B%0Aaway-%3E%20connected%20%5Blabel%3D%22search%20every%2020s%22%5D%0Aconnected%20-%3E%20disconnect%20%5Blabel%3D%22search%20every%2020s%22%5D%0A%7D%0A%0Asubgraph%20cluster_state%20%7B%0A%20%20%20%20idle%20-%3E%20charging%0A%20%20%20%20charging%20-%3E%20idle%0A%7D%0A%0Asubgraph%20cluster_whish%20%7B%0A%20%20%20%20overflow%20-%3E%20cheap%20%5Blabel%3D%22btn2%22%5D%0A%20%20%20%20cheap%20-%3E%20overflow%20%5Blabel%3D%22btn1%22%5D%0A%20%20%20%20cheap%20-%3E%20soon%20%5Blabel%3D%22btn3%22%5D%0A%20%20%20%20soon%20-%3E%20cheap%20%5Blabel%3D%22btn2%22%5D%0A%20%20%20%20overflow%20-%3E%20soon%20%5Blabel%3D%22btn3%22%5D%0A%20%20%20%20soon%20-%3E%20overflow%20%5Blabel%3D%22btn1%22%5D%0A%7D%0A%0A%7D%0A


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

# own lib and modules

from lib.logger import Logger  # own logger

logger = Logger(logging.DEBUG, "tesla_ble.log")

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


def assemble_domain_string(domain):
    if domain is None:
        return ""
    if not isinstance(domain, list):
        domain = [domain]
    return " ".join(f"-domain {value}" for value in domain)


class TeslaAPIBLE:
    def __init__(self, _tesla_account_name: str = "tesla"):
        """
        :param _tesla_account_name: just an account name for storing the cached tokens for this account
        """
        self.client_id = config.tesla_client_id
        self.vin = config.tesla_vin
        self.remote = config.tesla_remote

        self.commandcount = 0
        self.requestcount = 0

    # no tokens

    def cmd_add_key_request(self):
        # you have to generate the key first:
        # ./tesla-keygen -key-file ./relay_priv.pem create > ./ relay.pem
        # will generate two files - public and private
        # relay.pem
        # relay_priv.pem

        # copy over to Pi
        # scp relay*.pem user@192.168.1.77:~

        # prints: Sent add-key request to LR321321321321. Confirm by tapping NFC card on center console.
        # Note: there will be absolute NO INDICATION for the request in the vehicle, until the card is tapped - so just tap it!
        return self.tesla_ble_command("add-key-request ./relay.pem owner cloud_key")

    def cmd_wakeup(self):  # wake up the car
        return self.tesla_ble_command("wake", "vcsec")

    def get_state(self, which):  # One of climate, closures, charge-schedule, precondition-schedule, software-update, parental-controls, charge, drive, location, tire-pressure, media, media-detail
        return self.tesla_ble_command(f"state {which}", _expect_json=True)

    def get_vehicle_presence(self):  # returns "asleep" or "awake" or None
        # Fetch limited vehicle state information. Works over BLE when infotainment is asleep.
        # the PING command is not working, when the car is asleep
        res = self.tesla_ble_command("body-controller-state", "vcsec", _expect_json=True)
        if res is not None:
            if res["vehicleSleepStatus"] == "VEHICLE_SLEEP_STATUS_ASLEEP":
                return "asleep"
            elif res["vehicleSleepStatus"] == "VEHICLE_SLEEP_STATUS_AWAKE":
                return "awake"
            else:
                return None
        else:
            return None

    def cmd_charge_start(self):
        return self.tesla_ble_command("charging-start")
        # fails with: Failed to execute command: car could not execute command: is_charging

    def cmd_charge_stop(self):
        return self.tesla_ble_command("charging-stop")
        # fails with: Failed to execute command: car could not execute command: not_charging

    def cmd_charge_set_limit(self, _prc):
        return self.tesla_ble_command(f"charging-set-limit {int(_prc)}")

    def cmd_charge_set_schedule(self, _mins):
        return self.tesla_ble_command(f"charging-schedule {int(_mins)}")

    def cmd_charge_cancel_schedule(self):
        # remark: this will start a charge immediately!
        return self.tesla_ble_command("charging-schedule-cancel")
        # does not fail on repeated call

    def cmd_charge_set_amps(self, _amps):
        return self.tesla_ble_command(f"charging-set-amps {int(_amps)}")
        # does not fail on repeated call

    def cmd_climate_on(self):
        return self.tesla_ble_command(f"climate-on")

    def cmd_climate_off(self):
        return self.tesla_ble_command(f"climate-off")

    def tesla_ble_command(self, command_string, _domain=None, _expect_json=False):

        """
        Interface to the tesla-control CLI tool. Used here due to missing native implementation.
        Doc is available now - works as it is for the moment.
        https://github.com/teslamotors/vehicle-command/blob/main/pkg/protocol/protocol.md

        *** See build instructions in tesla-control directory!

        Concept: we spit out the token and the key into files, invoke the CLI and off we go.

        '''
        :param _expect_json: the command returns a JSON object (provided, tesla-control does return some JSON)
        :param command_string: the command
        :param _domain: the vehicle domain, can be one of "vcsec", "infotainment" or both as list ["vcsec","infotainment"]

        :return bool: true on success

        A selection of available command_string , see also tesla-control -h
        add-key-request          Request NFC-card approval for a enrolling PUBLIC_KEY with ROLE and FORM_FACTOR
        body-controller-state    Fetch limited vehicle state information. Works over BLE when infotainment is asleep.
        charge-port-close        Close charge port
        charge-port-open         Open charge port (also unlocks charging cable, when connected)
        charging-schedule        Schedule charging to MINS minutes after midnight and enable daily scheduling
        charging-schedule-cancel Cancel scheduled charge start
        charging-set-amps        Set charge current to AMPS
        charging-set-limit       Set charge limit to PERCENT
        charging-start           Start charging
        charging-stop            Stop charging
        flash-lights             Flash lights
        honk                     Honk horn
        list-keys                List public keys enrolled on vehicle (can also be used to detect sleeping vehicle with domain vcsec)
        lock                     Lock vehicle
        ping                     Ping vehicle - fails when vehicle sleeps
        product-info             Print JSON product info
        sentry-mode              Set sentry mode to STATE ('on' or 'off')
        session-info             Retrieve session info for PUBLIC_KEY from DOMAIN
        unlock                   Unlock vehicle
        wake                     Wake up vehicle - limit to domain vcsec!
        """

        logger.info(f"Send secure Command {self.commandcount}: {command_string}")

        # call the command externally
        # fixme store the key only temporarily in /tmp to avoid hard store in the file system

        if self.remote is None:
            # BLE on this machine
            cmd = f'./lib/tesla_api/tesla-control/tesla-control -ble {assemble_domain_string(_domain)} -session-cache ./.ble-cache.json -key-file ./lib/tesla_api/TeslaKeys/BLEprivatekey.pem -vin {self.vin} {command_string}'
        else:
            # remote execute the command on your other machine with better BLE reception
            cmd = f'ssh {self.remote} \'./tesla-control -ble {assemble_domain_string(_domain)} -session-cache ./.ble-cache.json -connect-timeout 10s -key-file ./relay_priv.pem -vin {self.vin} {command_string}\''

        logger.debug(f"Prepared command {self.commandcount}: {cmd}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True)

        if result.returncode != 0:  # we rely on the return code. The stderr is filled by -debug!
            if result.stderr:
                logger.error(f"Tesla command #{self.commandcount}: '{command_string}' result({result.returncode}): {result.stdout}\nERROR: {result.stderr}")
            else:
                logger.error(f"Tesla command #{self.commandcount}: '{command_string}' result({result.returncode}): {result.stdout}")
            # fail successfully
            if command_string == "charging-start" and result.stderr.endswith("is_charging"):
                logger.error(f"Tesla command #{self.commandcount}: '{command_string}' failed successfully - was already charging")
                return True
            if _expect_json:
                return None
            return False

        logger.debug(f"result({result.returncode}):{result.stdout}")

        if result.stderr:
            logger.debug(f"ERROR:{result.stderr}")  # OK output is always empty.

        if (_expect_json):
            try:
                jsondata = json.loads(result.stdout)
                if jsondata is not None:
                    logger.debug(f"JSON:{jsondata}")
                return jsondata  # return the JSON object or None on error
            except json.JSONDecodeError:
                logger.error(f"JSON Decode Error: {result.stdout}, {result.stderr}")
                return None
        else:
            return True


# test stuff, if run directly (only on PC!)
if __name__ == '__main__':
    import os

    os.chdir("../../")  # hop to the correct directory, as if called as lib/tesla_api/...

    myT = TeslaAPIBLE()
    myCar = {}

    r = myT.get_vehicle_presence()

    if r == "asleep":
        r = myT.cmd_wakeup()
        if r:
            print("Wake successful")
    elif r == "awake":
        print("Car is awake")
        # get some data
        r = myT.get_state("location")
        myCar["location"] = r
        r = myT.get_state("charge")
        myCar["charge"] = r
        r = myT.get_state("drive")
        myCar["drive"] = r

    print(myCar)

    # r = myT.cmd_charge_start()  # 'Failed to execute command: car could not execute command: complete'
    # r = myT.cmd_charge_stop() # Failed to execute command: car could not execute command: not_charging
    # r = myT.cmd_charge_set_limit(81)
    # r = myT.cmd_charge_set_amps(7) # success when awake

    # first run: go to the function tesla_register_process() and follow the comments.
    print("First run: go to https://github.com/fabianhu/tesla_api_example for an example project.")
