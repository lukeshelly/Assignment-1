"""
Name: Luke Shelly
Program: ShellyLA01.py

Purpose:
This program combines the menu-based port scanning work from Lab 03
with reusable menu, port-scanning, and log-file-scanning classes.

Design and thinking steps:
1. Create a reusable menu class that displays choices and checks input.
2. Create a port-scanning class that reads IP addresses and ports from
   files or asks the user to enter multiple values.
3. Let the user set a socket timeout and scan the selected IP/port pairs.
4. Save scan results to a new file with the date and time in its name.
5. Create a log-scanning class that searches for several words.
6. Display matching log lines with their original line numbers.
7. Support searches where ALL words or ANY words must be present.
8. Save search results to a new timestamped file.
9. Use a main menu that repeats until the user chooses Quit.

Testing plan:
- Test each menu with valid, invalid, and text input.
- Test loading IPNums.txt and PortNums.txt.
- Test manually entering multiple IP addresses and ports.
- Test valid and invalid timeout values.
- Test scanning only an authorized test system.
- Test log searches with ALL words and ANY words.
- Test a missing log file, no matches, and saving results.
"""

import ipaddress
import socket
from datetime import datetime


def make_output_filename(prefix):
    """Return a filename with the current date and time."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return prefix + "_" + timestamp + ".txt"


def read_values_from_file(filename):
    """
    Read values separated by spaces, commas, or new lines.
    This supports common formats used in simple class data files.
    """
    with open(filename, "r", encoding="utf-8", errors="replace") as file:
        contents = file.read()

    contents = contents.replace(",", " ").replace(";", " ")
    return contents.split()


class ShellyL_MenuClass:
    """
    Design:
    This class displays a menu and returns a valid numbered choice.

    Thinking steps:
    1. Store the title and list of menu choices.
    2. Display each choice with a number.
    3. Ask for the user's selection.
    4. Repeat until the user enters a valid choice.

    Testing:
    Test valid choices, out-of-range numbers, and non-number input.
    """

    def __init__(self, title, options):
        self.title = title
        self.options = options

    def display(self):
        print("\n" + "=" * 42)
        print(self.title)
        print("=" * 42)

        for number, option in enumerate(self.options, start=1):
            print(str(number) + ". " + option)

        while True:
            answer = input("Enter your choice: ").strip()

            try:
                choice = int(answer)
                if 1 <= choice <= len(self.options):
                    return choice
                print("Please choose a number shown in the menu.")
            except ValueError:
                print("Invalid input. Please enter a number.")


class ShellyL_PortScannerClass:
    """
    Design:
    This class loads IP addresses and port numbers, runs TCP connection
    checks, displays results, and saves them to a timestamped file.

    Thinking steps:
    1. Load IP addresses from IPNums.txt or accept manual input.
    2. Load ports from PortNums.txt or accept manual input.
    3. Validate addresses, ports, and timeout values.
    4. Check each selected IP address and port using a TCP socket.
    5. Display results and save them without overwriting older files.

    Testing:
    Test file loading, manual input, invalid values, timeout settings,
    a permitted test host, and timestamped output.
    """

    def __init__(self):
        self.ip_addresses = []
        self.ports = []
        self.timeout = 1.0
        self.results = []

    def read_ports_file(self):
        try:
            values = read_values_from_file("PortNums.txt")
        except OSError:
            print("Could not open PortNums.txt. Check that it is in this folder.")
            return

        valid_ports = []
        for value in values:
            try:
                port = int(value)
                if 1 <= port <= 65535:
                    valid_ports.append(port)
                else:
                    print("Skipping port outside 1-65535:", value)
            except ValueError:
                print("Skipping invalid port entry:", value)

        self.ports = sorted(set(valid_ports))
        print("Loaded", len(self.ports), "valid port number(s).")
        if not self.ports:
            print("No valid ports were found in PortNums.txt.")

    def enter_ports(self):
        text = input("Enter one or more ports separated by commas or spaces: ")
        valid_ports = []

        for value in text.replace(",", " ").split():
            try:
                port = int(value)
                if 1 <= port <= 65535:
                    valid_ports.append(port)
                else:
                    print("Port must be between 1 and 65535:", value)
            except ValueError:
                print("Not a valid port number:", value)

        if valid_ports:
            self.ports = sorted(set(valid_ports))
            print("Selected ports:", self.ports)
        else:
            print("No valid ports were entered.")

    def read_ips_file(self):
        try:
            values = read_values_from_file("IPNums.txt")
        except OSError:
            print("Could not open IPNums.txt. Check that it is in this folder.")
            return

        valid_ips = []
        for value in values:
            try:
                ipaddress.ip_address(value)
                valid_ips.append(value)
            except ValueError:
                print("Skipping invalid IP address:", value)

        self.ip_addresses = list(dict.fromkeys(valid_ips))
        print("Loaded", len(self.ip_addresses), "valid IP address(es).")
        if not self.ip_addresses:
            print("No valid IP addresses were found in IPNums.txt.")

    def enter_ips(self):
        text = input(
            "Enter one or more IP addresses separated by commas or spaces: "
        )
        valid_ips = []

        for value in text.replace(",", " ").split():
            try:
                ipaddress.ip_address(value)
                valid_ips.append(value)
            except ValueError:
                print("Invalid IP address:", value)

        if valid_ips:
            self.ip_addresses = list(dict.fromkeys(valid_ips))
            print("Selected IP addresses:", self.ip_addresses)
        else:
            print("No valid IP addresses were entered.")

    def set_timeout(self):
        answer = input("Enter timeout in seconds (for example, 1 or 1.5): ")
        try:
            value = float(answer)
            if 0 < value <= 60:
                self.timeout = value
                print("Timeout set to", self.timeout, "seconds.")
            else:
                print("Timeout must be greater than 0 and no more than 60.")
        except ValueError:
            print("Please enter a valid number.")

    def scan_ports(self):
        if not self.ip_addresses:
            print("Load or enter IP addresses before scanning.")
            return
        if not self.ports:
            print("Load or enter ports before scanning.")
            return

        print("\nOnly scan computers and networks you have permission to test.")
        confirm = input("Continue with this scan? (y/n): ").strip().lower()
        if confirm != "y":
            print("Scan cancelled.")
            return

        self.results = []
        for address in self.ip_addresses:
            for port in self.ports:
                try:
                    ip_version = ipaddress.ip_address(address).version
                    family = socket.AF_INET if ip_version == 4 else socket.AF_INET6

                    with socket.socket(family, socket.SOCK_STREAM) as connection:
                        connection.settimeout(self.timeout)
                        status = connection.connect_ex((address, port))

                    if status == 0:
                        status_text = "OPEN"
                    else:
                        status_text = "CLOSED, FILTERED, OR UNREACHABLE"

                    result = address + "," + str(port) + "," + status_text
                except (OSError, ValueError) as error:
                    result = address + "," + str(port) + ",ERROR: " + str(error)

                self.results.append(result)
                print(result.replace(",", " | "))

        output_name = make_output_filename("PortScanResults")
        try:
            with open(output_name, "w", encoding="utf-8") as file:
                file.write("IP Address,Port,Result\n")
                for result in self.results:
                    file.write(result + "\n")
            print("Results saved to", output_name)
        except OSError:
            print("Could not save the scan results.")

    def menu(self):
        menu = ShellyL_MenuClass(
            "PORT SCANNING",
            [
                "Read standard ports from PortNums.txt",
                "Enter port numbers manually",
                "Read IP addresses from IPNums.txt",
                "Enter IP addresses manually",
                "Change socket timeout",
                "Run port scan and save results",
                "Go to Network Tools Menu",
            ],
        )

        while True:
            choice = menu.display()
            if choice == 1:
                self.read_ports_file()
            elif choice == 2:
                self.enter_ports()
            elif choice == 3:
                self.read_ips_file()
            elif choice == 4:
                self.enter_ips()
            elif choice == 5:
                self.set_timeout()
            elif choice == 6:
                self.scan_ports()
            elif choice == 7:
                return


class ShellyL_FileLogScanningClass:
    """
    Design:
    This class searches a chosen log file for several words and saves
    matching lines with their original line numbers.

    Thinking steps:
    1. Ask for the log filename.
    2. Ask for a separator and multiple search words.
    3. Let the user choose ALL words or ANY words.
    4. Search each nonblank log line while keeping original line numbers.
    5. Display and save matching lines to a timestamped file.

    Testing:
    Test ALL and ANY searches, no matches, invalid choices, a missing
    file, blank lines, line numbering, and saving results.
    """

    def __init__(self):
        self.filename = ""
        self.words = []
        self.results = []

    def search_log(self):
        self.filename = input("Enter the log filename: ").strip()
        if not self.filename:
            print("Filename cannot be blank.")
            return

        try:
            with open(
                self.filename, "r", encoding="utf-8", errors="replace"
            ) as file:
                lines = file.readlines()
        except OSError:
            print("Could not open that log file.")
            return

        separator = input(
            "Enter the separator between words (for example, comma): "
        )
        if separator == "":
            print("The separator cannot be blank.")
            return

        word_text = input("Enter the search words using that separator: ")
        self.words = [
            word.strip().lower()
            for word in word_text.split(separator)
            if word.strip()
        ]
        if not self.words:
            print("Enter at least one search word.")
            return

        search_menu = ShellyL_MenuClass(
            "CHOOSE SEARCH TYPE",
            ["Find lines containing ALL words", "Find lines containing ANY words"],
        )
        search_choice = search_menu.display()

        self.results = []
        for line_number, line in enumerate(lines, start=1):
            # Ignore blank lines, but do not change the original line numbers.
            if not line.strip():
                continue

            lower_line = line.lower()
            if search_choice == 1:
                match = all(word in lower_line for word in self.words)
            else:
                match = any(word in lower_line for word in self.words)

            if match:
                self.results.append(str(line_number) + ": " + line.rstrip())

        if self.results:
            print("\n===== SEARCH RESULTS =====")
            for result in self.results:
                print(result)
        else:
            print("No matching lines were found.")

        output_name = make_output_filename("LogSearchResults")
        try:
            with open(output_name, "w", encoding="utf-8") as file:
                for result in self.results:
                    file.write(result + "\n")
            print("Results saved to", output_name)
        except OSError:
            print("Could not save the search results.")

    def menu(self):
        menu = ShellyL_MenuClass(
            "LOG FILE SCANNING",
            ["Search a log file", "Go to Forensics Tools Menu"],
        )

        while True:
            choice = menu.display()
            if choice == 1:
                self.search_log()
            elif choice == 2:
                return


def main():
    """
    Design:
    Connect the three classes using the main menu and two submenus.

    Thinking steps:
    1. Create the menu and tool objects.
    2. Show Network Tools, Forensics Tools, and Quit.
    3. Open the selected submenu.
    4. Return to the main menu when requested.
    5. Quit only from the main menu.

    Testing:
    Test both tool paths, returning from every submenu, and quitting.
    """
    port_scanner = ShellyL_PortScannerClass()
    log_scanner = ShellyL_FileLogScanningClass()

    main_menu = ShellyL_MenuClass(
        "MAIN MENU", ["Network Tools", "Forensics Tools", "Quit"]
    )
    network_menu = ShellyL_MenuClass(
        "NETWORK TOOLS", ["Port Scanning", "Go to Main Menu"]
    )
    forensics_menu = ShellyL_MenuClass(
        "FORENSICS TOOLS", ["LogFileScanning", "Go to Main Menu"]
    )

    while True:
        choice = main_menu.display()

        if choice == 1:
            while True:
                network_choice = network_menu.display()
                if network_choice == 1:
                    port_scanner.menu()
                else:
                    break

        elif choice == 2:
            while True:
                forensics_choice = forensics_menu.display()
                if forensics_choice == 1:
                    log_scanner.menu()
                else:
                    break

        elif choice == 3:
            print("Thank you for using the program.")
            break


if __name__ == "__main__":
    main()
