from functools import update_wrapper
from inspect import signature
from .exceptions import PostInitNotFoundErr


class PsuedoFunc(type):
    """turns the class constructor act like a regular function and make it
    return a value instead of an instance of the class

    when the 'constructor' of the class is called i.e ClassName(args)
    those args are passed to the __post_init__ function of the class
    and the return value of that function is what is actually returned
    instad of the instance

    the __init__ of class also recieves the same arguments, and can still be used
    but the instance methods of the class cannot be used from the outside as an
    instance of the class is not returned by the constructor

    the class's __init__ signature will be replaced with that of the __post_init__ function
    to aid documetation
    """

    def __new__(meta_cls, name, bases, dct):
        cls_post_init = dct.get("__post_init__")

        if cls_post_init is None:
            raise PostInitNotFoundErr(f"can't find __post_init__ in {name}")

        if isinstance(cls_post_init, (staticmethod, classmethod)):
            cls_post_init = cls_post_init.__func__  # the actual function inside

        dct_init = dct.get("__init__")
        if dct_init is None:
            dct_init = lambda *args, **kwargs: None
        cls_init = update_wrapper(dct_init, cls_post_init)

        post_init_sig = signature(cls_post_init)
        post_init_sig = post_init_sig.replace(
            parameters=tuple(post_init_sig.parameters.values())
        )

        # replace the function signature of the __init__ with that of __post_init__
        cls_init.__signature__ = post_init_sig

        # replace init with the newly formed one
        dct["__init__"] = cls_init
        return super().__new__(meta_cls, name, bases, dct)

    def __call__(cls, *args, **kwargs):
        # make sure the __init__ runs with same args
        instance = super().__call__(cls, *args, **kwargs)
        # call the post init with the same arguments so as to imitate a real function
        return instance.__post_init__(*args, **kwargs)
