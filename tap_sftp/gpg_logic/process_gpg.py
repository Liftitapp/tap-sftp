"""" This module contains the logic to process encrypted files in GnuPg. """
# Utilities
import gnupg
import datetime
from typing import Tuple
import logging
# Local
from .errors import KeyImportError, GpgDecryptError, KeyExpirationError


class GnuPgManager:

    def __init__(self):
        pass

    gpg = gnupg.GPG(gnupghome='/gpg/.gnupg')
    logger = logging.getLogger()

    SPECIAL_KEYS_ATTS = {
        'expires',  # Expiration date
        'uids',  # Certificate associated with specific emails of the form name <email>

    }

    @classmethod
    def get_config(cls, config: dict) -> Tuple[dict, bool]:
        """ This method check if config data contains gpg configurations.
        Args:
            config: A dict with all configuration for the current organization tap.
        Returns:
            - An empty dict and a False bool when the configuration parameters do not meet
              the minimum requirements for the process of decrypting a file.
            - An dict with the gpg necessary data to decrypt a file and True bool.
        """
        if config and config.get('gpg_config') is not None:
            gpg_data = config.get('gpg_config')
            if gpg_data.get("enable", False) is True:
                return config.get('gpg_config', {}), True
            return {}, False
        return {}, False

    @classmethod
    def import_key(cls, data: str, passphrase: str = None, type_key: str = "private"):
        """
        Import an armor key on gpg i.e. asc file data,
        return a Tuple with form <Execution result: boolean>, <Updated or not>, <result>

        If return is True, True, Result the keys is imported without problem
        if an error occurs in the import of the key, it returns an exception of type KeyImportError
        with a descriptive message of the error.
        """

        public = "BEGIN PGP PUBLIC KEY BLOCK"
        private = "BEGIN PGP PRIVATE KEY BLOCK"

        init_key_info = private if type_key == "private" else public

        if init_key_info in data:
            try:
                if not passphrase:
                    import_result = cls.gpg.import_keys(data)
                    response, status, result = True, import_result.results[0]['ok'] == '1', import_result.results[0]
                    result_text = result.get('text')
                    if status is False and result_text not in 'Not actually changed\n':
                        raise KeyImportError(message=str(result))
                    return response, status, result
                else:
                    import_result = cls.gpg.import_keys(data, passphrase=passphrase)
                    response, status, result = True, import_result.results[0]['ok'] == '1', import_result.results[0]
                    result_text = result.get('text')
                    if status is False and result_text not in 'Not actually changed\n':
                        cls.logger.error(f"result: {result}")
                        raise KeyImportError(message=str(result))
                    return response, status, result
            except Exception as e:
                cls.logger.error(f"Error import {type_key} key: {e}")
                raise KeyImportError(message=str(e))
        else:
            raise KeyImportError(message="No se encontro una llave valida para importar")

    @classmethod
    def decrypt_data(cls, data: str, passphrase: str):
        """
        Decrypt a data with a passphrase with gpg
        return str decrypt data.

        If decrypted data process is success return str with data in utf-8 encoding.
        if an error occurs decrypting the data, it returns a raise of type GpgDecryptError
        with a descriptive message of the error.


        Keyword arguments:
        data       -- Data to decrypt
        passphrase -- Passphrase from a gpg_logic certificate
        """

        decrypted_data = cls.gpg.decrypt(data, passphrase=passphrase)

        try:
            if decrypted_data.ok:
                return decrypted_data.data.decode("utf-8")
            else:
                decrypt_error = decrypted_data.stderr
                raise GpgDecryptError(message=str(decrypt_error))
        except Exception as e:
            cls.logger.error(f"Error trying to decrypt a file: {e}")
            raise GpgDecryptError(message=str(e))

    @classmethod
    def __format_att(cls, name: str, value: any):
        """
        Transform certain atts in a value
        expires to a datetime
        uids to a list of a name and email array

        Keyword arguments:
        name   -- att name
        value  -- att value
        """
        if name == 'expires':
            if value:
                return datetime.datetime.fromtimestamp(int(value))
            return None
        elif name == 'uids':
            formatted_data = []
            for uid in value:
                first_char_pos = uid.find('<')
                data = {
                    'name': uid[0:first_char_pos],
                    'email': uid[first_char_pos + 1:-1]
                }
                formatted_data.append(data)
            return formatted_data
        else:
            return value

    @classmethod
    def __get_key_data(cls, uid_to_search, atts_to_extract=None, format_atts=False):
        """
        Get a key associated with a uid
        return a Tuple with form <Execution result: boolean>, <result>

        If return is False, None, None is an internal error
        If return is True, Result is a correct execution and in result has the key data or certain att data

        Keyword arguments:
        uid_to_search   -- uid to search i.e an email
        atts_to_extract -- attr to extract from found key i.e. keyid, expires, uids
        format_atts     -- Transform att value to an specific type or structure i.e. expires to a date see format_atts
        """
        keys = cls.gpg.list_keys()

        for key in keys:
            uids = key['uids']
            for uid in uids:
                if uid_to_search in uid:
                    if atts_to_extract:
                        attrs_to_add = []
                        for att in atts_to_extract:
                            att_data = {'name': att, 'value': key[att]}
                            if format_atts:
                                att_data['format_value'] = cls.__format_att(att, key[att])
                            attrs_to_add.append(att_data)
                        return True, attrs_to_add
                    else:
                        return True, key
        return False, None

    @classmethod
    def verify_expiration_key(cls, uuid: str):
        exist_key, key_data = cls.__get_key_data(
            uid_to_search=uuid,
            atts_to_extract=cls.SPECIAL_KEYS_ATTS,
            format_atts=True
        )

        if exist_key and isinstance(key_data, list):
            exp_info = next((d for d in key_data if d.get('name') == 'expires'), None)
            if exp_info:
                exp_time = exp_info.get("format_value")
                current_time = datetime.datetime.now()

                if exp_time > current_time:
                    return 'ok'
                raise KeyExpirationError(
                    message=f'El certificado expiro en: {datetime.datetime.strftime(exp_time, "%Y-%m-%d %H:%M:%S")}'
                )
            return 'ok'

        elif exist_key and isinstance(key_data, dict):
            return 'ok'
        else:
            raise KeyExpirationError(message='No se pudo comprobar la valides del certificado')
