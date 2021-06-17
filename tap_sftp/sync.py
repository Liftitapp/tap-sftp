import json
import singer
from singer import metadata, utils, Transformer
from tap_sftp import client
from tap_sftp import stats
from singer_encodings import csv
# Import gpg module
from .gpg_logic import GnuPgManager
from io import StringIO
import tempfile
import sys

LOGGER = singer.get_logger()

def sync_stream(config, state, stream):
    table_name = stream.tap_stream_id
    modified_since = utils.strptime_to_utc(singer.get_bookmark(state, table_name, 'modified_since') or
                                           config['start_date'])

    LOGGER.info('Syncing table "%s".', table_name)
    LOGGER.info('Getting files modified since %s.', modified_since)

    conn = client.connection(config)
    table_spec = [c for c in json.loads(config["tables"]) if c["table_name"]==table_name]
    if len(table_spec) == 0:
        LOGGER.info("No table configuration found for '%s', skipping stream", table_name)
        return 0
    if len(table_spec) > 1:
        LOGGER.info("Multiple table configurations found for '%s', skipping stream", table_name)
        return 0
    table_spec = table_spec[0]

    files = conn.get_files(table_spec["search_prefix"],
                           table_spec["search_pattern"],
                           modified_since)

    LOGGER.info('Found %s files to be synced.', len(files))

    records_streamed = 0
    if not files:
        return records_streamed

    for f in files:
        # Send config parameter to sync_file, this parameter contains all config data for the current tap
        records_streamed += sync_file(conn, f, stream, table_spec, config)
        state = singer.write_bookmark(state, table_name, 'modified_since', f['last_modified'].isoformat())
        singer.write_state(state)

    LOGGER.info('Wrote %s records for table "%s".', records_streamed, table_name)

    return records_streamed

def sync_file(conn, f, stream, table_spec, config=None):
    LOGGER.info('Syncing file "%s".', f["filepath"])

    file_handle = conn.get_file_handle(f)

    # Check if current configuration contains data to decrypt gpg files
    config_data, enabled_gpg = GnuPgManager.get_config(config=config)

    # When in current config is enable decrypt files
    if enabled_gpg:

        passphrase = config_data.get('passphrase')
        private_key = config_data.get('private_key')
        key_uuid = config_data.get('uuid')

        # Import private key to decrypt files
        GnuPgManager.import_key(data=private_key, passphrase=passphrase, type_key='private')

        # check if the key has not expired
        GnuPgManager.verify_expiration_key(uuid=key_uuid)

        # Decrypt file data
        file_encrypt_data = ""
        # Each line of encrypted data
        for line in file_handle:
            file_encrypt_data += line.decode('utf-8' + '\n')

        # LOGGER.info(file_encrypt_data)
        encoding = table_spec.get('encoding') if table_spec.get('encoding') is not None else 'utf-8'
        decrypt_data = GnuPgManager.decrypt_data(data=file_encrypt_data, passphrase=passphrase, encoding=encoding)

        LOGGER.info(decrypt_data)
        if decrypt_data:
            LOGGER.info('Contruyendo el archivo temporal')
            data = StringIO(decrypt_data)

            tmp_file = tempfile.TemporaryFile(mode='w+')
            for line in data:
                tmp_file.write(line)
            tmp_file.seek(0)
            file_handle = open(tmp_file.name, 'rb')

        else:
            LOGGER.info('Hubo un error al desencriptar el archivo')

    # Add file_name to opts and flag infer_compression to support gzipped files
    opts = {'key_properties': table_spec['key_properties'],
            'delimiter': table_spec['delimiter'],
            'encoding': table_spec.get('encoding'),
            'file_name': f['filepath']}

    readers = csv.get_row_iterators(file_handle, options=opts, infer_compression=True)

    records_synced = 0

    for reader in readers:
        with Transformer() as transformer:
            for row in reader:
                custom_columns = {
                    '_sdc_source_file': f["filepath"],

                    # index zero, +1 for header row
                    '_sdc_source_lineno': records_synced + 2
                }
                rec = {**row, **custom_columns}

                to_write = transformer.transform(rec, stream.schema.to_dict(), metadata.to_map(stream.metadata))

                singer.write_record(stream.tap_stream_id, to_write)
                records_synced += 1

    stats.add_file_data(table_spec, f['filepath'], f['last_modified'], records_synced)

    return records_synced
