#!/usr/bin/env python3
import subprocess import logging import os import json import logging.handlers
import requests import inotify.constants import multiprocessing import inotify.adapters import hashlib 


def config(basedir):
    config = {
        'paths': set(),
        'extensions': set()
    }

    with open(os.path.expanduser(basedir + '/config.json')) as data:
        user_config = json.load(data)

        if 'api_key' in user_config and type(user_config['api_key']) is str:
            config['api_key'] = user_config['api_key']
        else:
            raise Exception('API key not found')

        if 'paths' in user_config and type(user_config['paths']) is list:
            for path in user_config['paths']:
                path = os.path.expanduser(path.encode())
                if not os.path.isabs(path):
                    logging.warn('"%s" not an absolute ' % path)
                elif not os.path.isdir(path):
                    logging.warn('"%s" not a directory' % path)
                else:
                    config['paths'].add(path)

        if not config['paths']:
            logging.info('default path')
            config['paths'] = {os.path.expanduser('~/Downloads').encode()}

        if 'extensions' in user_config and type(user_config['extensions']) is list:
            for ext in user_config['extensions']:
                if ext[0] == '.':
                    ext = ext[1:]

                if ext == '':
                    continue

                config['extensions'].add(ext.lower())

        if not config['extensions']:
            logging.info('Using default extensions')
            config['extensions'] = {
                'exe', 'msi', 'dll', 'scr', 'cpl', 'apk', 'jar', 'swf', 'vbs',
                'wsf', 'zip', 'rar', 'iso', 'pdf', 'doc', 'xls', 'ppt', 'docm',
                'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm'
            }

    return config

def set_dir(basedir):
    if not(os.path.exists(basedir) and os.path.isdir(basedir)):
        os.mkdir(basedir)

def set_log(basedir):
    log_path = os.path.expanduser(basedir + '/scan.log')
    logger = logging.getLogger()

    handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=131072, backupCount=3)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    


def notify(title, message, icon='', expires=15):
    subprocess.call(['notify-send', title, message, '-t', str(expires * 1000), '-i', icon])
    

def scan_file(path, api_key):
    hash = hashlib.sha256()

    try:
        with open(path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data:
                    break

                hash.update(data)

        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params={
            'apikey': api_key,
            'resource': hash.hexdigest()
        })

        if response.status_code != 200:
            notify('check failed',
                   'Failed to check %s' % path,
                   'dialog-information')
            return

        jsonresponse = response.json()

        if 'positives' in jsonresponse and 'total' in jsonresponse:
            positives = jsonresponse['positives']
            total = jsonresponse['total']

            for av, res in jsonresponse['scans'].items():
                if res['detected']:
                    virusname = res['result']
                    break

            if positives > 0:
                notify('Ransomware/malware detected',
                       'File: %s\n'
                       'Malware family: %s (%s)\n'
                       'Detection Ratio: %i/%i (%.2f%%)'
                       % (path, virusname, av, positives, total, 100 * positives/total),
                       'dialog-warning',
                       1200)

    except requests.exceptions.RequestException as e:
        logging.warn('Unable to check file "%s": %s' % (path, str(e)))
    except IOError as e:
        logging.warn('Unable to read file "%s": %s' % (path, str(e)))

def monitor_dirs(paths, scan_exts, api_key):
    watcher = inotify.adapters.InotifyTrees(paths=paths,
        mask=inotify.constants.IN_CLOSE_WRITE | inotify.constants.IN_MOVED_TO)

    try:
        for event in watcher.event_gen():
            if event is not None and event[0].mask in [
                inotify.constants.IN_CLOSE_WRITE,
                inotify.constants.IN_MOVED_TO
            ]:
                filename = event[3].decode('utf-8')
                ext = os.path.splitext(filename)[1][1:].lower()

                if ext in scan_exts:
                    path = os.path.join(event[2].decode('utf-8'), filename)
                    checker = multiprocessing.Process(target=scan_file, args=(path, api_key))
                    checker.start()
    finally:
        for path in paths:
            watcher.remove_watch(path)

def main():
    basedir = os.path.expanduser('~/.scandir')

    set_dir(basedir)
    set_log(basedir)

    config_ = config(basedir)
    monitor_dirs(list(config_['paths']), config_['extensions'], config_['api_key'])

if __name__ == '__main__':
    main()
