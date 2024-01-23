from dataclasses import dataclass


class BOM:
    format: str
    version: str
    serial_number: str


class Component:
    type: str
    name: str
    version: str


class Vulnerability:
    id: str
