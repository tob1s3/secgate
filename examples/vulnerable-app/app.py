"""Специально уязвимое приложение — пример для демонстрации secgate. НЕ запускать в проде."""

import hashlib
import pickle
import subprocess

import yaml


def ping(host: str) -> str:
    # Командная инъекция: host попадает в shell без экранирования.
    return subprocess.check_output(f"ping -c 1 {host}", shell=True).decode()


def load_config(text: str) -> dict:
    # Небезопасная загрузка YAML: может создать произвольные объекты.
    return yaml.load(text, Loader=yaml.Loader)


def restore_session(blob: bytes):
    # Десериализация недоверенных данных.
    return pickle.loads(blob)


def password_hash(password: str) -> str:
    # Слабый хэш для пароля.
    return hashlib.md5(password.encode()).hexdigest()
