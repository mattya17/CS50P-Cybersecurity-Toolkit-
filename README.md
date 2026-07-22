Cybersecurity Toolkit

Description:
Cybersecurity Toolkit is a command-line program, written in Python, that brings together 3 small utilities inspired by the world of cyber security into a single tool:
1) Password Toolkit: to check and generate secure passwords;
2) Cipher Toolkit: implements the Caesar cipher to encrypt and/or decrypt text;
3) Log Analyzer: analyzes an access log file to identify IP addresses with a suspicious number of failed login attempts.

The idea for the project stems from my passion for cybersecurity and my recent self-taught studies on some basic concepts of "defensive" information security, which pushed me to build a project that would truly put me to the test.
It should be noted that the project contains no offensive tools whatsoever; instead, it introduces three problems that cybersecurity professionals frequently encounter: how strong a credential is, how classical cryptography works, and how to recognize suspicious behavior by analyzing logs.

How to run it:
After installing the dependencies with pip install -r requirements.txt, simply run python project.py.
The program shows a main menu from which you can choose which of the three tools to use; each tool has its own submenu with the relevant options.
The program keeps running, always returning to the main menu, until the user selects the "Exit" option.

File structure:
The project consists of three files, all located in the root folder:
1) project.py contains the entire logic of the program.
   It is organized into three sections, plus the main() function that manages the main menu.
   Each module exposes a run_toolkit() function that handles user interaction (input, print) and delegates the actual logic to "pure" functions, meaning functions that receive data as input and return a result without interacting directly with the console.
   This separation was an intentional design choice: it makes the logic functions easy to test with pytest, without having to simulate keyboard input in the tests.

2) test_project.py contains the automated tests for eight functions of the project, checking both "normal" cases and some edge cases, such as a password that is too short, a log file with malformed rows, or a suspicion    threshold that can never be reached.

3) requirements.txt lists the project's only external dependency, pytest, needed to run the test suite.

Details of the three modules:
The Password Toolkit offers two features: check_password_strength() assigns a score from 0 to 5 to a password based on its length, the presence of uppercase letters, digits and symbols, also applying a penalty if the password matches a common password or contains trivial sequences (such as "123" or "abc"), checked by the support function has_common_pattern(). The generate_secure_password() instead generates a secure random password, always guaranteeing at least one character from each required category and a minimum of 8 character.

The Cipher Toolkit implements a classic Caesar cipher through caesar_encrypt() and caesar_decrypt(), keeping spaces and punctuation unchanged and respecting uppercase/lowercase letters.

The Log Analyzer reads a CSV file with columns timestamp, ip and status through parse_log_file(), automatically discarding invalid rows (for example, ones with a malformed timestamp).
count_failed_logins() counts the failed attempts for each IP, while flag_suspicious_ips() identifies the ones that exceed a configurable threshold, returning them sorted from most to least suspicious.

Design choices:
An important choice was to clearly separate user interaction
(input/print) from the business logic: this made it possible to write clean tests that call the functions directly with controlled data, without having to handle simulated keyboard input.
Another choice was to avoid relying on any external library besides pytest, using only Python's standard library (csv, re, random, string, collections, datetime): this makes the project easy to run anywhere, with no dependency on external APIs or access keys.

Possible future developments:
Natural extensions of the project include: loading a larger list of common passwords from an external file, and exporting the Log Analyzer results to a CSV or JSON report.
