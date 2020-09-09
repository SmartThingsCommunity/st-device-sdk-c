# QR generation tools for Individual and Commercial

[![License](https://img.shields.io/badge/licence-Apache%202.0-brightgreen.svg?style=flat)](LICENSE)

## Summary

This repository provides a tool to generate QR codes for ST devices.

## Prerequisites

Install qrcode python package
```sh
pip install qrcode --user
```
or for Ubuntu
```sh
sudo apt-get install python3-qrcode
```

## Usage

```sh
stdk-qrgen.py [-h] [--folder FOLDER]

--folder FOLDER  Folder containing onboarding_config.json and device_info.json (if not supplied uses current folder)
```
