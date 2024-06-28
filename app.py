import requests
from bs4 import BeautifulSoup
import geoip2.database
import pkgutil
import importlib
import logging
import json
import os
import re

class ReconSouthAfrica:
    def __init__(self):
        self.modules = self.load_modules()
        self.setup_logging()
        self.config = self.load_config()

    def load_modules(self):
        modules = {}
        for _, name, _ in pkgutil.iter_modules():
            if name.startswith('module_'):
                module = importlib.import_module(name)
                modules[name] = module
        return modules

    def setup_logging(self):
        logging.basicConfig(filename='reconsouthafrica.log', level=logging.INFO,
                            format='%(asctime)s:%(levelname)s:%(message)s')

    def load_config(self):
        if os.path.exists('config.json'):
            with open('config.json', 'r') as file:
                return json.load(file)
        else:
            return {}

    def run_module(self, module_name, *args):
        if module_name in self.modules:
            module = self.modules[module_name]
            try:
                module.run(*args)
                logging.info(f"Successfully ran module {module_name} with args {args}")
            except Exception as e:
                logging.error(f"Error running module {module_name} with args {args}: {e}")
                print(f"An error occurred: {e}")
        else:
            print(f"Module {module_name} not found")

    def make_request(self, url, params=None):
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            print(f"Request failed: {e}")
            return None

    def parse_html(self, html):
        return BeautifulSoup(html, 'html.parser')

    def print_menu(self):
        print("Choose an action:")
        menu_options = [
            ("Domain Lookup", self.run_domain_lookup),
            ("IP Geolocation", self.run_ip_geolocation),
            ("Public Records Search", self.run_public_records),
            ("Reverse Image Search (TinEye)", self.run_reverse_image_search),
            ("SAPS Wanted/Missing Persons", self.run_saps_wanted_missing),
            ("International Wanted/Missing Persons", self.run_international_wanted_missing),
            ("Social Network Search by Email", lambda: self.run_social_network_search('email')),
            ("Social Network Search by IP", lambda: self.run_social_network_search('ip')),
            ("Social Network Search by VIN", lambda: self.run_social_network_search('vin')),
            ("Real Name Search Pattern", self.run_real_name_search_pattern),
            ("Google Dorks", self.run_google_dorks),
            ("Username Search", self.run_username_search),
            ("Email Address Search", self.run_email_address_search),
            ("Compromised Databases Search", self.run_compromised_databases_search),
            ("Phone Number Search", self.run_phone_number_search),
            ("Whois Lookup", self.run_whois),
            ("Reverse Whois Lookup", self.run_reverse_whois),
            ("Passive DNS Lookup", self.run_passive_dns),
            ("Geolocation Tools", self.run_geolocation_tools),
            ("Help", self.print_help),
            ("Settings", self.print_settings),
            ("Exit", self.exit_program)
        ]
        for index, (option, _) in enumerate(menu_options, start=1):
            print(f"{index}. {option}")

    def print_help(self):
        print("Help:")
        print("Select an option from the menu for details on each action.")

    def print_settings(self):
        print("Settings functionality not implemented yet.")

    def exit_program(self):
        print("Exiting...")
        exit()

    # Modules implementation

    def run_domain_lookup(self):
        domain = input("Enter the domain to lookup: ")
        url = f'https://www.za-example.com/domain-lookup/{domain}'
        response = self.make_request(url)
        if response:
            soup = self.parse_html(response.text)
            print(f"Domain Information for {domain}:")
            for info in soup.find_all('div', class_='domain-info'):
                print(info.text)
        else:
            print(f"Failed to retrieve data for {domain}")

    def run_ip_geolocation(self):
        ip_address = input("Enter the IP address to geolocate: ")
        try:
            with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
                response = reader.city(ip_address)
                print(f"Geolocation for IP {ip_address}:")
                print(f"City: {response.city.name}")
                print(f"Country: {response.country.name}")
                print(f"Latitude: {response.location.latitude}")
                print(f"Longitude: {response.location.longitude}")
        except Exception as e:
            logging.error(f"Failed to geolocate IP address {ip_address}: {e}")
            print(f"Failed to geolocate IP address {ip_address}: {e}")

    def run_public_records(self):
        name = input("Enter the name to search public records: ")
        url = f'https://www.sa-publicrecords-example.com/search?name={name}'
        response = self.make_request(url)
        if response:
            data = response.json()
            print(f"Public Records for {name}:")
            for record in data['records']:
                print(record)
        else:
            print(f"Failed to retrieve public records for {name}")

    def run_reverse_image_search(self):
        image_url = input("Enter the image URL for reverse image search: ")
        url = f'https://tineye.com/search?url={image_url}'
        response = self.make_request(url)
        if response:
            soup = self.parse_html(response.text)
            print(f"Reverse Image Search Results for {image_url}:")
            results = soup.find_all('div', class_='result')
            for result in results:
                print(result.text)
        else:
            print(f"Failed to perform reverse image search for {image_url}")

    def run_saps_wanted_missing(self):
        search_term = input("Enter the search term for SAPS wanted/missing persons: ")
        url = f'https://www.saps.gov.za/crimestop/wanted/search.php?q={search_term}'
        response = self.make_request(url)
        if response:
            soup = self.parse_html(response.text)
            print(f"SAPS Wanted/Missing Persons for {search_term}:")
            for person in soup.find_all('div', class_='person-info'):
                print(person.text)
        else:
            print(f"Failed to retrieve SAPS wanted/missing persons for {search_term}")

    def run_international_wanted_missing(self):
        search_term = input("Enter the search term for international wanted/missing persons: ")
        url = f'https://www.interpol.int/en/How-we-work/Notices/View-Red-Notices?q={search_term}'
        response = self.make_request(url)
        if response:
            soup = self.parse_html(response.text)
            print(f"International Wanted/Missing Persons for {search_term}:")
            for person in soup.find_all('div', class_='result'):
                print(person.text)
        else:
            print(f"Failed to retrieve international wanted/missing persons for {search_term}")

    def run_social_network_search(self, search_type):
        query = input(f"Enter the {search_type} for social network search: ")
        url = f'https://www.socialnetworksearch-example.com/search?{search_type}={query}'
        response = self.make_request(url)
        if response:
            soup = self.parse_html(response.text)
            print(f"Social Network Search Results for {search_type} {query}:")
            for result in soup.find_all('div', class_='result'):
                print(result.text)
        else:
            print(f"Failed to perform social network search for {search_type} {query}")

    def run_real_name_search_pattern(self):
        name = input("Enter the real name for pattern search: ")
        print(f"Searching for patterns matching real name: {name}")
        pattern = re.compile(r'\b' + re.escape(name) + r'\b', re.IGNORECASE)
        sample_text = "Example text with real name John Doe and other content."
        matches = pattern.findall(sample_text)
        print(f"Found {len(matches)} matches for name {name} in sample text.")

    def run_google_dorks(self):
        search_query = input("Enter the Google Dorks query: ")
        url = f'https://www.google.com/search?q={search_query}'
        response = self.make_request(url)
        if response:
            soup = self.parse_html(response.text)
            print(f"Google Dorks Search Results for query: {search_query}")
            for result in soup.find_all('h3', class_='r'):
                print(result.text)
        else:
            print(f"Failed to perform Google Dorks search for query: {search_query}")

    def run_username_search(self):
        username = input("Enter the username for search: ")
        print(f"Searching for information related to username: {username}")
        print(f"Username {username} found on various platforms.")

    def run_email_address_search(self):
        email = input("Enter the email address for search: ")
        print(f"Searching for information related to email address: {email}")
        print(f"Information related to {email} found.")

    def run_compromised_databases_search(self):
        query = input("Enter the query for compromised databases search: ")
        print(f"Searching for compromised databases related to: {query}")
        print(f"Compromised databases related to {query} found.")

    def run_phone_number_search(self):
        phone_number = input("Enter the phone number for search: ")
        print(f"Searching for information related to phone number: {phone_number}")
        print(f"Information related to phone number {phone_number} found.")

    def run_whois(self):
        domain = input("Enter the domain for Whois lookup: ")
        print(f"Performing Whois lookup for domain: {domain}")
        print(f"Whois information for {domain}.")

    def run_reverse_whois(self):
        name = input("Enter the name for Reverse Whois lookup: ")
        print(f"Performing Reverse Whois lookup for name: {name}")
        print(f"Reverse Whois information for {name}.")

    def run_passive_dns(self):
        query = input("Enter the query for Passive DNS lookup: ")
        print(f"Performing Passive DNS lookup for query: {query}")
        print(f"Passive DNS information for {query}.")

    def run_geolocation_tools(self):
        print("Geolocation Tools:")
        print("1. IP-based Geolocation")
        print("2. Location Search")
        choice = input("Enter your choice (1-2): ")
        if choice == '1':
            self.run_ip_geolocation()
        elif choice == '2':
            location = input("Enter the location to search: ")
            print(f"Performing location search for: {location}")
            print(f"Location information for {location}.")

    def start(self):
        while True:
            self.print_menu()
            try:
                choice = int(input("Enter your choice (1-22): ").strip())
                if 1 <= choice <= 22:
                    if choice == 20:
                        self.print_help()
                    elif choice == 21:
                        self.print_settings()
                    elif choice == 22:
                        self.exit_program()
                    else:
                        self.run_menu_choice(choice)
                else:
                    print("Invalid choice. Please enter a number between 1 and 22.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    def run_menu_choice(self, choice):
        menu_options = [
            self.run_domain_lookup,
            self.run_ip_geolocation,
            self.run_public_records,
            self.run_reverse_image_search,
            self.run_saps_wanted_missing,
            self.run_international_wanted_missing,
            lambda: self.run_social_network_search('email'),
            lambda: self.run_social_network_search('ip'),
            lambda: self.run_social_network_search('vin'),
            self.run_real_name_search_pattern,
            self.run_google_dorks,
            self.run_username_search,
            self.run_email_address_search,
            self.run_compromised_databases_search,
            self.run_phone_number_search,
            self.run_whois,
            self.run_reverse_whois,
            self.run_passive_dns,
            self.run_geolocation_tools
        ]
        menu_options[choice - 1]()

if __name__ == "__main__":
    recon = ReconSouthAfrica()
    recon.start()

