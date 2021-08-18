class PostInit(type):
    """
    enables the use of a class as a psuedofunction of sorts

    it overrides the __call__ of `type` class to actuall call an internel function
    of the class itself

    i.e when the actual class constructor is called

    value = Something() # class which has metaclass PostInit

    a class instance is NOT created, instance it returns the output of the __post_init__
    of the Something class
    """

    def __call__(cls, *args, **kwargs):
        try:
            return type.__call__(cls, *args, **kwargs).__post_init__()
        except AttributeError:
            print(
                f"class {cls.__name__} needs to have "
                "__post_init__ attribute defined."
            )
            raise
