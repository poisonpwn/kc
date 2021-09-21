from random import randint, choices, shuffle
from pathlib import Path
from linecache import getline
from string import ascii_letters, ascii_lowercase, digits
from typing import Union, Optional
import click


class PassGen:
    def __init__(self):
        # TODO: implement dispatch to password generators
        pass

    # static method can't be used normally
    # here because this function is monkey patched
    def xkcd(
        no_of_words: int = 5,
        delim: str = "-",
        include_size: bool = True,
        service_name: Optional[str] = None,
        should_capitalize_words: bool = False,
        word_len_range: Union[range, int] = range(4, 10),
    ) -> str:
        """generates an xkcd style passphrase, like in
        https://xkcd.com/936/

        Args:
            no_of_words (int, optional): the number of words the password should contain. Defaults to 5.

            delim (str, optional): the delimeter to seperate each word with. Defaults to "-".

            include_size (bool, optional): whether to append the total size of the password to it
              including delimeters, except the delimeter seperating the size itself. Defaults to True.

            service_name (Optional[str], optional): if not None, service name will be used as the
              first word of the password. Defaults to None.

            should_capitalize_words (bool, optional): if True, every word in password will be capitalized. Defaults to False.

            word_len_range (Union[range, int], optional): [description]. Defaults to range(4, 10).
        """

        if no_of_words < 0:
            raise ValueError("no of words in password has to be a positive number!")

        word_list = []
        if service_name is not None:
            word_list.append(service_name)

        if isinstance(word_len_range, int):
            word_pass_predicate = word_len_range.__eq__
        elif isinstance(word_len_range, range):
            word_pass_predicate = word_len_range.__contains__
        else:
            raise TypeError(
                "Invalid Type for word_len_range"
                f"expected range or int, got {type(word_len_range)}"
            )

        word_len_sum = 0
        while len(word_list) < no_of_words:
            word = getline(
                str(PassGen.xkcd.WORDLIST_FILE),
                randint(*PassGen.xkcd.LINE_RANGE),
            ).strip()
            if word_pass_predicate(word_len := len(word)):
                word_len_sum += word_len
                word_list.append(word)

        if should_capitalize_words:
            word_list = [word.capitalize() for word in word_list]

        if include_size:
            word_list.append(
                # add `no_of_words - 1` to take delimeters into account
                # when calculating the len of password to append later
                str(word_len_sum + no_of_words - 1)
                # * NOTE: the last delimeter before the length number is not counted in length
            )
        return delim.join(word_list)

    xkcd.WORDLIST_DIR = Path(__file__).parents[2].absolute()
    xkcd.WORDLIST_FILE = xkcd.WORDLIST_DIR / "wordlist.txt"
    xkcd.LINE_RANGE = (4, 7700)  # only words between these line numbers are chosen
    xkcd = staticmethod(xkcd)

    @staticmethod
    def random_chars(
        size: int = 20,
        digit_count: int = 3,
        include_uppercase: bool = True,
        special_char_count: int = 3,
    ) -> str:
        """generate a password consisting of a random string of characters with
        using the specified parameters

        Args:
            size (int, optional): the length of the password. Defaults to 20.

            digit_count (int, optional): no of digits to include in the password. Defaults to 3.

            include_uppercase (bool, optional): whether to include the uppercase alphabet. Defaults to True.

            special_char_count (int, optional): no of special charectars to include in the password. Defaults to 3.
        """
        if size < 1:
            raise ValueError("size of password has to be a positive number!")

        if (digit_count + special_char_count) > size:
            click.echo(
                "no of numbers and special charectars can't be more than length of password itself!",
                err=True,
            )

        letter_options = ascii_letters if include_uppercase else ascii_lowercase

        # vvvvv only has letters and nothing else
        passwd_char_list = choices(
            letter_options,
            # no of letters is total size minus the no of digits and special chars
            k=size - (digit_count + special_char_count),
        )
        # add some random numbers
        passwd_char_list += choices(digits, k=digit_count)

        # add some random special chars
        passwd_char_list += choices(r"&$%#@!*=+-\,.;:/?", k=special_char_count)

        passwd_char_list = shuffle(passwd_char_list)
        return "".join(passwd_char_list)


if __name__ == "__main__":
    print(PassGen.xkcd())
    print(PassGen.random_chars())
