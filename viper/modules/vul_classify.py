import os
import requests

from viper.common.abstracts import Module
from viper.core.config import __config__
from viper.core.session import __sessions__

cfg = __config__
cfg.parse_http_client(cfg.vul_classify)


class VulClassify(Module):
    cmd = 'vulclassify'
    description = 'This module does vul classification'

    def __init__(self):
        super(VulClassify, self).__init__()

    def run(self):
        if not __sessions__.is_set():
            # No open session.
            print('No open session. This command expects a file to be open.')
            return

        file_path = __sessions__.current.file.path

        url = cfg.vul_classify.https_proxy + '/classify?path=' + file_path
        res = requests.post(url)

        # print(res.status_code)
        if res.status_code == 200:
            value = res.json()

            print('the probability of each type:')
            for proba in value.items():
                print(proba[0], ':', proba[1])

        elif res.status_code == 400:
            print('current file is invaild.')
        
        elif res.status_code == 422:
            print('current file cannot be interpreted as a valid binary program.')
        
        else:
            print(res.text)
        