""" This module contains the custom excepts to return on errors. """


class Error(Exception):
    """Base class for other exceptions"""
    pass


class KeyExpirationError(Error):
    """Raised when a gpg key has expired"""
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class KeyImportError(Error):
    """Raised when an error occurs while importing a key"""
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class GpgDecryptError(Error):
    """Raised when and error occurs during file decryption"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)
