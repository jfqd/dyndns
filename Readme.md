# DynDNS

Web-App for PowerDNS with MySQL Backend.

You should have an existing PowerDNS MySQL-Database to use this app. Maybe additional table fields are required for your database. Take a look into the source to see what is needed.

## Installation

git clone https://github.com/jfqd/dyndns.git
cd dyndns
bundle
mkdir log

## Hosting

We use Phusion Passenger, but you can use thin, puma, unicorn or any other rack server as well. For testing just use:

rackup

Copyright (c) 2014 Stefan Husch, qutic development.