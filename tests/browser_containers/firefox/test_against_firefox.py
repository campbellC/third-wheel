from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import sys

from time import sleep

proxy_server = "127.0.0.1:8080" # mitm proxy server

firefox_profile = webdriver.FirefoxProfile("/root/.mozilla/firefox/my_profile.default")

firefox_options = webdriver.firefox.options.Options()
firefox_options.headless = True
print("Launching firefox")
browser = webdriver.Firefox(firefox_profile, options=firefox_options)

browser.get('https://www.example.com/')
markup = browser.find_element_by_tag_name("body").text
browser.close()



example_markup = "This domain is for use in illustrative examples in documents."


correct_markup = example_markup in markup
if correct_markup:
    print("Markup was as expected")
else:
    print("Markup and example markup were different")
    print("Expected to contain:")
    print(example_markup)
    print("Received:")
    print(markup)

    sys.exit(1)
