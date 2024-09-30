#!/bin/bash

python src/main.py generate --number_of_elements_per_date 20 --create_tickets true
python src/main.py generate --number_of_elements_per_date 200 --create_alertstats true
