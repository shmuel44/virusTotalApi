from dataclasses import dataclass
from functools import cached_property
import sys
import logging
import os
import requests
from tabulate import tabulate
from typing import Final

from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv('API_KEY')
HASH:Final[str] = "84c82835a5d21bbcf75a61706d8ab549"

LEN_SHA_256: int = 64
LEN_SHA_1 = 40
LEN_MD5 = 32


def check_if_hash_exsit(hash_to_check:str) -> bool:
    with open('history.txt', 'r') as f:
        hashes =  f.readlines()
        for hash in hashes:
            if hash_to_check == hash.removesuffix('\n'):
                logging.error("find")
                return True
    return False

           
def save_hash(hash:str) -> None:
  
    with open("history.txt", 'a') as f:
        f.write(hash + '\n')


def isvalid_hash(hash: str) -> bool:
    """
    Check if the input hash is valid.

    Args:
        hash (str): The hash to validate.

    Returns:
        bool: True if the hash is valid, False otherwise.

    Raises:
        None
    """
    # check if the hash contains characters it is not letter (a-z) and numbers (0-9)
    #TODO bug until f letter
    if not hash.isalnum():
        logging.error("Invalid hash: Not a string (hash contain only letter and numbers).")
        return False

    len_hash = len(hash)

    if len_hash not in [LEN_SHA_256, LEN_SHA_1, LEN_MD5]:
        logging.error("Invalid hash: Incorrect length.")
        return False
    return True


def isvalid_fields(data: dict[str,dict[str , int |str]]) -> bool:
    """
    Check if the input dictionary has all the necessary fields.

    Args:
        data (dict): The dictionary to validate.

    Returns:
        bool: True if the dictionary has all the necessary fields, False otherwise.

    Raises:
        None
    """
    keys_to_check = ['md5', "sha1", "sha256", "last_analysis_results"]
    try:
        data_relevant = data['data']['attributes']
        data_relevant['last_analysis_stats']["malicious"]  # type: ignore   # check if last_analysis_stats and malicious exist inside the dictionary

        if missing_keys := [
            key for key in keys_to_check if key not in data_relevant  # type: ignore typynig er
       ]:
            raise KeyError(missing_keys)
    except KeyError as e:
        logging.error(f"Invalid field: {e}")
        return False
    return True


def get_virus_total_data(api_key: str, hash: str) -> dict | None:
    """
    Retrieve the virus total data for a given hash.

    Args:
        api_key (str): VirusTotal API key.
        hash (str): The hash of the file to retrieve data for.

    Returns:
        dict or None: VirusTotal data in dictionary format, or None if the request was not successful.

    Raises:
        requests.exceptions.RequestException: If there was an error while getting the information from VirusTotal.
    """
    headers = {"accept": "application/json", 'x-apikey': api_key}
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{hash}", headers=headers)
        response.raise_for_status()  # Raise an exception if the request was not successful OK[200]
        data = response.json()
        
        if not isinstance(data, dict):
            logging.error("VirusTotal response is not in the expected format, which is a dictionary(json).")
            return None
        if len(data) == 0:
            logging.error("VirusTotal Response is empty")
            return None

        return data
    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while getting IP information: {e}")
        return None


def parse_file_hashes(data: dict) -> dict[str, int]:
    """
    Extract the file hashes from the input dictionary.

    Args:
        data (dict): The dictionary that contains the file hashes.

    Returns:
        dict: A dictionary with keys 'MD5', 'SHA-1', and 'SHA-256' and the corresponding hash values as values.

    Raises:
        None
    """
    return {
        'MD5':    [data['md5']],
        'SHA-1':  [data['sha1']],
        'SHA-256': [data['sha256']],
    }


def parse_analysis_stats(data: dict) -> dict[list] or None:
    """
    Extract the last analysis statistics of a file from Virus Total data.

    Args:
    data (dict[any]): A dictionary containing the Virus Total data.

    Returns:
    dict[list[int]] or None: A dictionary containing the total scans and malicious scans
        information if successful, None otherwise.
    """
    # Get the last_analysis_stats from the virus total data
    stats = data['last_analysis_stats']
    try:
        # include type-unsupported
        sum_of_total_scans = sum(stats.values())
    except TypeError as e:
        logging.error(f"cannot sum of total scans because of error of type {e}")
        return None
    return {
        "Total Scans":    [sum_of_total_scans],
        "Malicious Scans":[stats["malicious"]]
    }


def parse_analysis_results(data: dict) -> dict:
    """
    Extract the analysis results from the input dictionary.

    Args:
        data (dict): The dictionary that contains the analysis results.

    Returns:
        dict: A dictionary with the names of the analysis scans as keys and the scan categories as values.

    Raises:
        None
    """
    last_analysis_results = data['last_analysis_results']

    # get only the name of the scan as a key and the  category as a value
    scan_result = {key: value['category'] for key, value in last_analysis_results.items()}
    return scan_result


def create_data_tables(file_hashes_info: dict, scan_status: dict[list[int]], scan_result: dict) -> tuple:
    """
    Create tables to display the file information, scan status, and scan result.

    Args:
        file_hashes_info (dict): The dictionary that contains the file hashes information.
        scan_status (dict): The dictionary that contains the scan status.
        scan_result (dict): The dictionary that contains the scan results.

    Returns:
        tuple: Three string values representing the file information table, scan status table, and scan result table in that order.

    Raises:
        None
    """
    file_info_table =   "**File information**\n" + tabulate(file_hashes_info, headers='keys', tablefmt="pipe")
    scan_status_table = "**Last Analysis Status**\n" + tabulate(scan_status, headers='keys', tablefmt="pipe")
    scan_result_table = "**Last Analysis Results**\n" + tabulate(scan_result.items(),
                                                                 headers=["Scan Origin", "Scan Result"],
                                                                 tablefmt="pipe")

    return file_info_table, scan_status_table, scan_result_table


def save_to_file(file_info_table: str, scan_status_table: str, scan_result_table: str) -> None:
    """
    Save the tables to a file in markdown format.

    Args:
        file_info_table (str): The string representation of the file information table.
        scan_status_table (str): The string representation of the scan status table.
        scan_result_table (str): The string representation of the scan result table.

    Returns:
        None

    Raises:
        None
    """
    with open('output.md', 'w') as f:
        f.write(file_info_table + '\n \n')
        f.write(scan_status_table + '\n \n')
        f.write(scan_result_table)


def main() -> None:  # sourcery skip: avoid-builtin-shadow
    """
    The required python packages are requests and tabulate.
    The main function retrieves and displays Virus Total data for a given hash.
    If there is an error, the error message will appear in helper functions.

    Steps:
        1) Get the file hash from the user input. If no input is provided, it uses the default hash.
        2) Validate the hash using the isvalid_hash function.
        3) Get the data from VirusTotal API using get_virus_total_data function.
        4) Validate the received data using the isvalid_fields function.
        5) Parse the relevant data using parse_file_hashes, parse_analysis_stats and parse_analysis_results functions.
        6) Create the markdown data tables using the create_data_tables function.
        7) Display the data tables.
        8) Save the data tables to a markdown file using the save_to_file function.
    """
    # Step 1: Get the file hash
    hash = sys.argv[1] if len(sys.argv) >= 2 else HASH
    
    if check_if_hash_exsit(hash):
        return
    save_hash(hash)
    # Step 2: Validate the hash
    if not isvalid_hash(hash):
        return

    # Step 3: Get data from VirusTotal API
    data = get_virus_total_data(API_KEY, hash)

    if data is None:
        return
    # Step 4: Validate the received data
    if not isvalid_fields(data):
        return

    # Get the reletive data from the big data
    data_relevant = data['data']['attributes']

    # Step 5: Parse relevant data
    file_hash_info = parse_file_hashes(data_relevant)
    scan_results = parse_analysis_results(data_relevant)
    scan_status = parse_analysis_stats(data_relevant)

    if scan_status is None:
        return

    # Step 6: Create markdown data tables
    tables = create_data_tables(file_hash_info, scan_status, scan_results)

    # Step 7: Display the data tables
    [print(table) for table in tables]
    # print(*tables)

    # Step 8: Save the data tables to a markdown file
    save_to_file(*tables)

    

if __name__ == '__main__':
    main()












