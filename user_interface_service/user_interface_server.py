"""Monefy-web-app - analyze and visualize data from Monefy App
 that will be parsed from csv formatted backup created in Monefy mobile application"""
from common.app_setup import ApplicationLauncher
from common.logger_config import LOGGING_CONFIG_CUSTOM

user_interface_service = ApplicationLauncher(
    "Monefy-Web-App", log_config=LOGGING_CONFIG_CUSTOM
)
